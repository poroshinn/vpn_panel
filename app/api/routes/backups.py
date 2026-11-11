"""REST API бэкапов (FR-3.10.10, FR-3.11.1, FR-3.11.3, FR-3.11.7).

Роли (матрица §2.2): все операции бэкапа/восстановления — admin.
Ошибки — единый JSON (правило 9 AGENTS.md); аудит — backup.* события.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, Request, UploadFile
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel

from app.auth.dependencies import client_ip, require_role
from app.auth.sessions import SessionData
from app.backups import telegram as tg
from app.backups.restore import RestoreError, RestoreService
from app.backups.snapshot import make_snapshot
from app.core.audit import log_event
from app.core.config import get_settings
from app.db.database import Database

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/backups", tags=["Backups"])


def _restore_service(request: Request) -> RestoreService:
    if not hasattr(request.app.state, "restore_service"):
        request.app.state.restore_service = RestoreService(
            request.app.state.db, Path(get_settings().backup_dir)
        )
    return request.app.state.restore_service


def _error(exc: RestoreError, status_code: int) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={"error_code": exc.error_code, "message": exc.message,
                 "details": exc.details},
    )


_ERROR_STATUS = {
    "invalid_file": 400,
    "invalid_schema": 400,
    "invalid_request": 400,
    "integrity_failed": 400,
    "schema_newer": 409,
    "protected_records": 409,
    "restore_failed": 500,
}


# ------------------------------------------------------------------- снапшот


@router.post("/snapshot")
async def create_snapshot(
    request: Request,
    session: SessionData = Depends(require_role("admin")),
) -> Any:
    """Ручной снапшот БД (admin, FR-3.11.1а) — скачиваемый, без ротации."""
    db: Database = request.app.state.db
    ip = client_ip(request)
    snapshot = await make_snapshot(
        db, Path(get_settings().backup_dir) / "manual", prefix="manual", rotate=False
    )
    await db.execute(
        "INSERT INTO recovery_snapshots (kind, path, sha256, created_at) "
        "VALUES ('manual', ?, ?, datetime('now'))",
        (str(snapshot.path), snapshot.sha256),
    )
    await log_event(
        db, session.username, "backup.snapshot_created", ip=ip,
        details={"sha256": snapshot.sha256, "size": snapshot.size},
    )
    return {
        "name": snapshot.path.name,
        "sha256": snapshot.sha256,
        "size": snapshot.size,
    }


@router.get("/snapshots")
async def list_snapshots(
    request: Request,
    _: SessionData = Depends(require_role("admin")),
) -> Any:
    """Список локальных снимков (admin): ручные, автобэкап, пред-restore."""
    settings = get_settings()
    root = Path(settings.backup_dir)
    groups: dict[str, list[dict[str, Any]]] = {}
    for group in ("manual", "local", "pre-restore", "pre-migrate"):
        d = root / group
        items: list[dict[str, Any]] = []
        if d.is_dir():
            for f in sorted(d.glob("*.db.gz"), reverse=True):
                items.append({"name": f.name, "group": group, "size": f.stat().st_size})
        groups[group] = items
    return groups


@router.get("/snapshots/{group}/{name}")
async def download_snapshot(
    group: str,
    name: str,
    request: Request,
    _: SessionData = Depends(require_role("admin")),
) -> Response:
    """Скачивание локального снимка (admin, FR-3.11.1)."""
    if group not in ("manual", "local", "pre-restore", "pre-migrate"):
        return JSONResponse(
            status_code=404,
            content={"error_code": "not_found", "message": "Unknown snapshot group",
                     "details": {}},
        )
    safe = Path(name)
    if safe.name != name or ".." in safe.parts:
        return JSONResponse(
            status_code=404,
            content={"error_code": "not_found", "message": "Invalid name", "details": {}},
        )
    path = Path(get_settings().backup_dir) / group / safe
    if not path.is_file():
        return JSONResponse(
            status_code=404,
            content={"error_code": "not_found", "message": "Snapshot not found",
                     "details": {}},
        )
    return Response(
        content=path.read_bytes(),
        media_type="application/gzip",
        headers={"Content-Disposition": f'attachment; filename="{safe.name}"'},
    )


# ------------------------------------------------------------------ restore


@router.post("/restore/preview")
async def restore_preview(
    request: Request,
    file: UploadFile,
    _: SessionData = Depends(require_role("admin")),
) -> Any:
    """Превью файла бэкапа (admin): версия, число записей, предупреждения."""
    service = _restore_service(request)
    data = await file.read()
    try:
        preview, warnings = await service.preview(data)
    except RestoreError as exc:
        return _error(exc, _ERROR_STATUS.get(exc.error_code, 400))
    return {
        "schema_version": preview.schema_version,
        "tables": preview.tables,
        "warnings": warnings,
    }


@router.post("/restore")
async def restore(
    request: Request,
    file: UploadFile,
    session: SessionData = Depends(require_role("admin")),
    confirm_text: str | None = None,
    keep_protected: bool = True,
) -> Any:
    """Восстановление из файла бэкапа (admin, FR-3.11.1/3.11.3).

    ``keep_protected=true`` (по умолчанию) — merge-безопасный профиль;
    полное восстановление: ``keep_protected=false`` + ``confirm_text=restore``.
    Попытка отмотать защищённые записи без подтверждения — 409.
    """
    db: Database = request.app.state.db
    ip = client_ip(request)
    service = _restore_service(request)
    data = await file.read()
    await log_event(
        db, session.username, "backup.restore_started", ip=ip,
        details={"keep_protected": keep_protected, "confirm": bool(confirm_text)},
    )
    try:
        result = await service.apply(
            data, confirm_text=confirm_text, keep_protected=keep_protected
        )
    except RestoreError as exc:
        await log_event(
            db, session.username, "backup.restore_failed", ip=ip,
            details={"error_code": exc.error_code},
        )
        return _error(exc, _ERROR_STATUS.get(exc.error_code, 400))
    return result


# ------------------------------------------------------- Telegram-автобэкап


@router.get("/telegram/config")
async def telegram_config(
    request: Request,
    _: SessionData = Depends(require_role("admin")),
) -> Any:
    """Настройки автобэкапа (admin); токен не раскрывается (правило 3)."""
    db: Database = request.app.state.db
    config = await tg.get_config(db)
    last_error = await tg._get_setting(db, "backup_last_error")
    return {
        "enabled": config.enabled,
        "send_time_utc": config.send_time.strftime("%H:%M"),
        "telegram_configured": bool(config.bot_token and config.chat_id),
        "last_error": last_error,
    }


class TelegramConfigUpdate(BaseModel):
    """Обновление настроек автобэкапа (admin)."""

    enabled: bool | None = None
    send_time_utc: str | None = None
    bot_token: str | None = None
    chat_id: str | None = None


@router.put("/telegram/config")
async def update_telegram_config(
    payload: TelegramConfigUpdate,
    request: Request,
    session: SessionData = Depends(require_role("admin")),
) -> Any:
    """Сохранение настроек автобэкапа (admin, FR-3.10.10).

    Токен передаётся только на запись; ответ никогда не содержит секрета.
    """
    db: Database = request.app.state.db
    ip = client_ip(request)
    await tg.save_config(
        db,
        enabled=payload.enabled,
        send_time=payload.send_time_utc,
        bot_token=payload.bot_token if payload.bot_token is not None else ...,
        chat_id=payload.chat_id if payload.chat_id is not None else ...,
    )
    await log_event(
        db, session.username, "backup.telegram_config_updated", ip=ip,
        details={
            "enabled": payload.enabled,
            "send_time_utc": payload.send_time_utc,
            "telegram_configured": bool(
                (payload.bot_token is not None) or bool((await tg.get_config(db)).bot_token)
            ),
        },
    )
    config = await tg.get_config(db)
    return {
        "enabled": config.enabled,
        "send_time_utc": config.send_time.strftime("%H:%M"),
        "telegram_configured": bool(config.bot_token and config.chat_id),
    }


@router.post("/telegram/run")
async def run_backup_now(
    request: Request,
    session: SessionData = Depends(require_role("admin")),
) -> Any:
    """Ручной прогон автобэкапа (admin): снапшот + отправка при настроенном боте."""
    db: Database = request.app.state.db
    ip = client_ip(request)
    result = await tg.run_daily_backup(db, actor=session.username)
    await log_event(
        db, session.username, "backup.manual_run", ip=ip,
        details={"delivered": result.delivered, "error": result.error},
    )
    return {
        "delivered": result.delivered,
        "error": result.error,
        "snapshot": result.snapshot.path.name if result.snapshot else None,
    }
