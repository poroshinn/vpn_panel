"""Точка входа FastAPI (FR-3.15.2, FR-3.16.1).

Порядок старта: логгер → БД → миграции → маршруты.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, PlainTextResponse

from app.accounting.finalization import FinalizationService
from app.accounting.service import POLL_INTERVAL_DEFAULT, AccountingService
from app.api.routes.accounting import router as accounting_router
from app.api.routes.auth import router as auth_router
from app.api.routes.backups import router as backups_router
from app.api.routes.events import router as events_router
from app.api.routes.protocols import router as protocols_router
from app.api.routes.servers import router as servers_router
from app.api.routes.sharing import router as sharing_router
from app.api.routes.tokens import router as tokens_router
from app.api.routes.users import router as users_router
from app.auth.tokens import TokenService
from app.backups.restore import RestoreService
from app.backups.telegram import BackupScheduler
from app.core.config import get_settings
from app.core.logging import setup_logging
from app.core.rate_limit import api_rate_ok
from app.db.database import Database
from app.db.migrator import apply_migrations
from app.protocols.installer import ProtocolInstaller
from app.protocols.peers import PeerService
from app.servers.service import ServerService
from app.sharing.service import ShareService
from app.sharing.web import share_router
from app.ssh.pool import SSHPool
from app.ssh.probes import NodeProber
from app.users.service import UserService
from app.web.pages import router as pages_router
from app.web.sse import EventHub

logger = logging.getLogger(__name__)


async def _db_healthy(db: Database) -> bool:
    try:
        await db.fetch_one("SELECT 1")
        return True
    except Exception:  # noqa: BLE001
        return False


@asynccontextmanager
async def lifespan(app: FastAPI):
    setup_logging()
    settings = get_settings()
    Path(settings.db_file).parent.mkdir(parents=True, exist_ok=True)
    app.state.event_hub = EventHub()

    db = Database()
    await db.connect()
    version = await apply_migrations(db)
    logger.info("Panel started, schema version %s", version)

    app.state.db = db
    app.state.ssh_pool = SSHPool()
    app.state.server_service = ServerService(app.state.ssh_pool)
    app.state.node_prober = NodeProber(app.state.ssh_pool)
    app.state.protocol_installer = ProtocolInstaller(app.state.ssh_pool, app.state.server_service)
    app.state.peer_service = PeerService(app.state.ssh_pool, app.state.server_service)
    app.state.user_service = UserService(
        app.state.ssh_pool, app.state.peer_service, app.state.server_service
    )
    app.state.share_service = ShareService(app.state.peer_service)
    app.state.finalization_service = FinalizationService(
        app.state.ssh_pool, app.state.server_service
    )
    poll_interval = int(
        getattr(settings, "accounting_poll_interval", POLL_INTERVAL_DEFAULT)
    )
    app.state.accounting_service = AccountingService(
        db, app.state.ssh_pool, app.state.server_service, app.state.peer_service,
        poll_interval=poll_interval,
    )
    app.state.restore_service = RestoreService(db, Path(settings.backup_dir))
    token_service = TokenService()

    class _TokenHook:
        """Адаптер TokenService под TokenRevocationHook (UserService)."""

        async def revoke_user_tokens(self, user_id: int) -> int:
            return await token_service.revoke_user_tokens(db, user_id)

    app.state.user_service.set_token_hook(_TokenHook())
    app.state.accounting_service.start()
    app.state.backup_scheduler = BackupScheduler(db)
    app.state.backup_scheduler.start()
    yield
    await app.state.backup_scheduler.stop()
    await app.state.accounting_service.stop()
    await app.state.ssh_pool.close_all()
    await db.close()


def create_app() -> FastAPI:
    app = FastAPI(title="Amnezia Web Panel", version="0.1.0", lifespan=lifespan)

    @app.middleware("http")
    async def rate_limit_middleware(request: Request, call_next):
        """Rate-limit /api/* (FR-2.3): скользящее окно на IP."""
        path = request.url.path
        if path.startswith("/api/"):
            ip = request.client.host if request.client else "unknown"
            if not api_rate_ok(ip, path):
                return JSONResponse(
                    status_code=429,
                    content={
                        "error_code": "rate_limited",
                        "message": "Too many requests, retry later",
                        "details": {},
                    },
                )
        return await call_next(request)

    # /api/auth/* — без сессии (ТЗ §2.3); HTML-страницы — корневые пути;
    # /share/* — публичные (FR-3.8.2), без сессии панели
    app.include_router(auth_router)
    app.include_router(servers_router)
    app.include_router(protocols_router)
    app.include_router(accounting_router)
    app.include_router(users_router)
    app.include_router(tokens_router)
    app.include_router(backups_router)
    app.include_router(sharing_router)
    app.include_router(events_router)
    app.include_router(pages_router)
    app.include_router(share_router)

    # Единый JSON-формат ошибок на все HTTPException (FR-3.12.5, правило 9)
    from fastapi.exceptions import RequestValidationError
    from fastapi.responses import RedirectResponse

    @app.exception_handler(HTTPException)
    async def http_exc_handler(request: Request, exc: HTTPException):
        if request.url.path.startswith("/api"):
            return JSONResponse(
                status_code=exc.status_code,
                content={
                    "error_code": str(exc.detail),
                    "message": str(exc.detail),
                    "details": {},
                },
            )
        return PlainTextResponse(str(exc.detail), status_code=exc.status_code)

    @app.exception_handler(RequestValidationError)
    async def validation_exc_handler(request: Request, exc: RequestValidationError):
        if request.url.path.startswith("/api"):
            return JSONResponse(
                status_code=422,
                content={
                    "error_code": "validation_error",
                    "message": "Request validation failed",
                    "details": {"errors": exc.errors()},
                },
            )
        return JSONResponse(status_code=422, content={"detail": exc.errors()})

    # /api — алиас на /api/v1 (FR-3.12.3): без потери тела — 307 preserve method

    @app.api_route("/api/{rest:path}", methods=["GET", "POST", "PATCH", "PUT", "DELETE"],
                   include_in_schema=False)
    async def api_alias(rest: str) -> RedirectResponse:
        return RedirectResponse(url=f"/api/v1/{rest}", status_code=307)

    @app.get("/health", tags=["system"])
    async def health() -> dict:
        """Health-check (FR-3.16.1): живость + состояние БД."""
        db: Database = app.state.db
        ok = await _db_healthy(db)
        return {"status": "ok" if ok else "degraded", "database": "up" if ok else "down"}

    return app


app = create_app()
