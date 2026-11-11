"""Системные эндпоинты (FR-3.16.1, ТЗ §8.8).

- ``GET /health`` — без аутентификации; allowlist-контроль по IP
  (``HEALTH_ALLOWLIST``, по умолчанию только loopback); БД остановлена ⇒ 503.
- ``GET /api/v1/system/status`` — uptime, версия схемы, размер БД,
  статистика фоновых задач (admin).
"""

from __future__ import annotations

import logging
import os
import time
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from app.auth.dependencies import client_ip, require_role
from app.auth.sessions import SessionData
from app.db.database import Database
from app.db.migrator import get_schema_version

logger = logging.getLogger(__name__)

router = APIRouter(tags=["System"])

# Allowlist /health (ТЗ §8.8): CIDR-строки через запятую, env HEALTH_ALLOWLIST.
# Пусто/не задано → только loopback (127.0.0.0/8, ::1).
DEFAULT_ALLOWLIST = ("127.0.0.0/8", "::1")


def _allowlist() -> list[str]:
    raw = os.environ.get("HEALTH_ALLOWLIST", "").strip()
    if not raw:
        return list(DEFAULT_ALLOWLIST)
    return [item.strip() for item in raw.split(",") if item.strip()]


def _ip_allowed(ip: str, allowlist: list[str]) -> bool:
    """Проверка IP против allowlist (ipaddress, поддержка IPv4/IPv6 CIDR).

    Точное строковое совпадение тоже допускается (test-клиенты).
    """
    import ipaddress

    if ip in allowlist:
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for item in allowlist:
        try:
            if "/" in item:
                if addr in ipaddress.ip_network(item, strict=False):
                    return True
            elif addr == ipaddress.ip_address(item):
                return True
        except ValueError:
            continue
    return False


# Момент старта процесса (uptime для /api/v1/system/status)
_STARTED_AT = time.time()


def _db_status(db: Database) -> tuple[bool, str]:
    """Живость БД: (ok, состояние)."""
    try:
        _ = db.conn  # noqa: B018 — проверка-доступ
    except RuntimeError:
        return False, "down"
    return True, "up"


@router.get("/health", include_in_schema=False)
async def health(request: Request) -> JSONResponse:
    """Health-check (§8.8): без аутентификации, allowlist по IP.

    БД остановлена ⇒ 503 ``{"status": "down", "database": "down"}``.
    """
    ip = client_ip(request)
    if not _ip_allowed(ip, _allowlist()):
        return JSONResponse(
            status_code=404,
            content={"status": "not_found"},
        )
    db: Database | None = getattr(request.app.state, "db", None)
    if db is None:
        return JSONResponse(
            status_code=503,
            content={"status": "down", "database": "down"},
        )
    ok, state = _db_status(db)
    if not ok:
        return JSONResponse(
            status_code=503,
            content={"status": "down", "database": state},
        )
    try:
        await db.fetch_one("SELECT 1")
    except Exception:  # noqa: BLE001
        return JSONResponse(
            status_code=503,
            content={"status": "down", "database": "down"},
        )
    return JSONResponse(content={"status": "ok", "database": "up"})


@router.get("/api/v1/system/status")
async def system_status(
    request: Request,
    _: SessionData = Depends(require_role("admin")),
) -> Any:
    """Системный статус (admin, FR-3.16.1): uptime, схема, размер БД, фоновые задачи."""
    db: Database = request.app.state.db
    settings_db_size = 0
    wal_size = 0
    if db.path.exists():
        stat = db.path.stat()
        settings_db_size = stat.st_size
        wal = db.path.with_name(db.path.name + "-wal")
        if wal.exists():
            wal_size = wal.stat().st_size

    schema_version = await get_schema_version(db)

    accounting = getattr(request.app.state, "accounting_service", None)
    backups = getattr(request.app.state, "backup_scheduler", None)
    background = {
        "accounting": {
            "running": bool(accounting and accounting._task and not accounting._task.done()),
            "poll_interval": getattr(accounting, "poll_interval", None),
        },
        "backup_scheduler": {
            "running": bool(backups and backups._task and not backups._task.done()),
            "last_result": getattr(backups, "last_result", None),
        },
    }

    return {
        "uptime_seconds": int(time.time() - _STARTED_AT),
        "started_at": datetime.fromtimestamp(_STARTED_AT, tz=UTC).isoformat(
            timespec="seconds"
        ),
        "now_utc": datetime.now(UTC).isoformat(timespec="seconds"),
        "schema_version": schema_version,
        "database": {
            "path": str(db.path),
            "size_bytes": settings_db_size,
            "wal_size_bytes": wal_size,
        },
        "background_tasks": background,
        "version": request.app.version,
    }
