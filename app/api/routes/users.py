"""REST API пользователей (FR-3.6.1–3.6.5): /api/v1/users.

Роли (матрица §2.2): CRUD/enable/disable/привязка/отвязка — admin;
просмотр списка/карточки и экспорт подключений — admin + support (FR-3.6.5).
Ошибки — единый JSON (правило 9 AGENTS.md); секреты не раскрываются.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field

from app.auth.dependencies import client_ip, require_role
from app.auth.sessions import SessionData
from app.core.audit import log_event
from app.db.database import Database
from app.users.service import UserError, UserService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/users", tags=["Users"])


def get_users(request: Request) -> UserService:
    return request.app.state.user_service


def _error(exc: UserError, status_code: int) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={"error_code": exc.error_code, "message": exc.message, "details": {}},
    )


class UserCreate(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    role: str = Field(pattern="^(admin|support|user|none)$")
    password: str | None = None
    telegram_id: int | None = None
    traffic_limit: int | None = Field(default=None, ge=0)
    expiration: str | None = None


class UserUpdate(BaseModel):
    role: str | None = Field(default=None, pattern="^(admin|support|user|none)$")
    password: str | None = None
    telegram_id: int | None = None
    traffic_limit: int | None = Field(default=None, ge=0)
    expiration: str | None = None


class EnabledUpdate(BaseModel):
    enabled: bool


class AssignRequest(BaseModel):
    connection_id: int


class UnlinkRequest(BaseModel):
    stop: bool = True
    allow_unverified: bool = False


_ERROR_STATUS = {
    "user_not_found": 404,
    "connection_not_found": 404,
    "username_taken": 409,
    "invalid_role": 400,
    "invalid_username": 400,
    "password_required": 400,
    "weak_password": 400,
    "last_admin": 409,
    "finalization_unavailable": 503,
}


# ------------------------------------------------------------------ list/get


@router.get("")
async def list_users(
    request: Request,
    _: SessionData = Depends(require_role("admin", "support")),
    users: UserService = Depends(get_users),
) -> Any:
    """Список пользователей (admin/support, FR-3.6.1)."""
    db: Database = request.app.state.db
    return await users.list_users(db)


@router.get("/{user_id}")
async def get_user(
    user_id: int,
    request: Request,
    _: SessionData = Depends(require_role("admin", "support")),
    users: UserService = Depends(get_users),
) -> Any:
    """Карточка пользователя (admin/support)."""
    db: Database = request.app.state.db
    try:
        return await users.get_user(db, user_id)
    except UserError as exc:
        return _error(exc, 404)


@router.get("/{user_id}/connections")
async def user_connections(
    user_id: int,
    request: Request,
    _: SessionData = Depends(require_role("admin", "support")),
    users: UserService = Depends(get_users),
) -> Any:
    """Подключения пользователя (admin/support)."""
    db: Database = request.app.state.db
    try:
        await users.get_user(db, user_id)
    except UserError as exc:
        return _error(exc, 404)
    return await users.user_connections(db, user_id)


# ---------------------------------------------------------------------- CRUD


@router.post("", status_code=201)
async def create_user(
    body: UserCreate,
    request: Request,
    session: SessionData = Depends(require_role("admin")),
    users: UserService = Depends(get_users),
) -> Any:
    """Создать пользователя (admin, FR-3.6.1)."""
    db: Database = request.app.state.db
    try:
        return await users.create_user(
            db,
            username=body.username,
            role=body.role,
            password=body.password,
            telegram_id=body.telegram_id,
            traffic_limit=body.traffic_limit,
            expiration=body.expiration,
            actor=session.username,
            ip=client_ip(request),
        )
    except UserError as exc:
        return _error(exc, _ERROR_STATUS.get(exc.error_code, 400))


@router.patch("/{user_id}")
async def update_user(
    user_id: int,
    body: UserUpdate,
    request: Request,
    session: SessionData = Depends(require_role("admin")),
    users: UserService = Depends(get_users),
) -> Any:
    """Изменить пользователя (admin): роль/пароль/telegram/квоту/expiration.

    Понижение роли отзывает Bearer-токены (FR-3.6.4); сессии режутся
    сверкой с БД мгновенно.
    """
    db: Database = request.app.state.db
    try:
        return await users.update_user(
            db,
            user_id,
            role=body.role,
            password=body.password,
            telegram_id=body.telegram_id,
            traffic_limit=body.traffic_limit,
            expiration=body.expiration,
            actor=session.username,
            ip=client_ip(request),
        )
    except UserError as exc:
        return _error(exc, _ERROR_STATUS.get(exc.error_code, 400))


@router.post("/{user_id}/enabled")
async def set_enabled(
    user_id: int,
    body: EnabledUpdate,
    request: Request,
    session: SessionData = Depends(require_role("admin")),
    users: UserService = Depends(get_users),
) -> Any:
    """Включение/отключение одной кнопкой (admin, FR-3.6.1/3.6.4)."""
    db: Database = request.app.state.db
    try:
        return await users.set_enabled(
            db, user_id, enabled=body.enabled,
            actor=session.username, ip=client_ip(request),
        )
    except UserError as exc:
        return _error(exc, _ERROR_STATUS.get(exc.error_code, 400))


@router.delete("/{user_id}")
async def delete_user(
    user_id: int,
    request: Request,
    session: SessionData = Depends(require_role("admin")),
    users: UserService = Depends(get_users),
) -> Any:
    """Удалить пользователя (admin)."""
    db: Database = request.app.state.db
    try:
        return await users.delete_user(
            db, user_id, actor=session.username, ip=client_ip(request)
        )
    except UserError as exc:
        return _error(exc, _ERROR_STATUS.get(exc.error_code, 400))


# ------------------------------------------------- привязка/отвязка (3.6.2/3.6.3)


@router.post("/{user_id}/connections", status_code=201)
async def assign_connection(
    user_id: int,
    body: AssignRequest,
    request: Request,
    session: SessionData = Depends(require_role("admin")),
    users: UserService = Depends(get_users),
) -> Any:
    """Привязать подключение к пользователю (admin, FR-3.6.2)."""
    db: Database = request.app.state.db
    try:
        return await users.assign_connection(
            db, connection_id=body.connection_id, user_id=user_id,
            actor=session.username, ip=client_ip(request),
        )
    except UserError as exc:
        return _error(exc, _ERROR_STATUS.get(exc.error_code, 400))


@router.post("/connections/{connection_id}/unlink")
async def unlink_connection(
    connection_id: int,
    body: UnlinkRequest,
    request: Request,
    session: SessionData = Depends(require_role("admin")),
    users: UserService = Depends(get_users),
) -> Any:
    """Отвязка владельца (admin, FR-3.6.3).

    Активный peer — останавливается на ноде (``stop``), затем финализация;
    нечитаемый счётчик — 409 c ``can_force``, ретрай с ``allow_unverified``.
    """
    db: Database = request.app.state.db
    finalization = request.app.state.finalization_service
    try:
        return await users.unlink_owner(
            db,
            connection_id=connection_id,
            stop=body.stop,
            allow_unverified=body.allow_unverified,
            finalize=finalization.finalize_peer,
            actor=session.username,
            ip=client_ip(request),
        )
    except UserError as exc:
        return _error(exc, _ERROR_STATUS.get(exc.error_code, 400))
    except Exception as exc:  # FinalizationError — fail-closed (правило 5)
        code = getattr(exc, "error_code", "finalization_failed")
        details: dict[str, Any] = {}
        if getattr(exc, "can_force", False):
            details["can_force"] = True
        return JSONResponse(
            status_code=409,
            content={
                "error_code": code,
                "message": getattr(exc, "message", str(exc)),
                "details": details,
            },
        )


# ---------------------------------------------------------------- экспорт (3.6.5)


@router.get("/{user_id}/export")
async def export_user_configs(
    user_id: int,
    request: Request,
    session: SessionData = Depends(require_role("admin", "support")),
    users: UserService = Depends(get_users),
) -> Any:
    """Экспорт списка подключений пользователя (admin/support, FR-3.6.5).

    Ответ — JSON-документ со списком подключений (без секретов нод);
    конфиги выгружаются построчно из raw-конфигов нод при наличии.
    """
    db: Database = request.app.state.db
    peers = request.app.state.peer_service
    servers = request.app.state.server_service
    import json as _json

    try:
        user = await users.get_user(db, user_id)
    except UserError as exc:
        return _error(exc, 404)

    conns = await users.user_connections(db, user_id)
    export_items: list[dict[str, Any]] = []
    for conn in conns:
        item: dict[str, Any] = dict(conn)
        try:
            raw = await peers.raw_config(db, conn["server_id"], conn["id"])
            server_row = await servers._get_row(db, conn["server_id"])  # noqa: SLF001
            info = {}
            try:
                info = _json.loads(server_row.get("protocols") or "{}").get(
                    conn["protocol"], {}
                )
            except _json.JSONDecodeError:
                info = {}
            item["conf"] = raw
            item["host"] = server_row["host"]
            item["port"] = int(info.get("port", 0))
        except Exception as exc:  # noqa: BLE001 — нода недоступна: экспорт продолжается
            item["config_error"] = "node_unavailable"
            logger.info(
                "export user %s connection %s: config unavailable (%s)",
                user_id, conn["id"], getattr(exc, "error_code", exc),
            )
        export_items.append(item)

    await log_event(
        db, session.username, "user.export",
        object=f"user:{user['username']}", ip=client_ip(request),
        details={"connections": len(export_items)},
    )
    payload = {
        "user": {k: user[k] for k in ("id", "username", "role", "enabled")},
        "connections": export_items,
    }
    filename = f"user-{user['username']}-connections.json"
    return Response(
        content=_json.dumps(payload, ensure_ascii=False, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
