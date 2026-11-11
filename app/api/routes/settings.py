"""REST API настроек панели (FR-3.10.1, FR-3.10.3, FR-3.10.13).

Роли (матрица §2.2): чтение — admin/support; изменение — admin.
Токены/чаты Telegram никогда не возвращаются (правило 3 AGENTS.md).
Ошибки — единый JSON (правило 9).
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from app.alerts.service import (
    ALERT_KEYS,
    get_alert_config,
    save_alert_config,
    send_alert_message,
)
from app.auth.dependencies import client_ip, require_role
from app.auth.sessions import SessionData
from app.backups.telegram import TelegramSendError
from app.core.audit import log_event
from app.core.disk_guard import last_state
from app.db.database import Database

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/settings", tags=["Settings"])


@router.get("/appearance")
async def get_appearance(
    request: Request,
    _: SessionData = Depends(require_role("admin", "support")),
) -> Any:
    """Настройки внешнего вида (FR-3.10.1): заголовок/подзаголовок/логотип."""
    db: Database = request.app.state.db
    rows = await db.fetch_all(
        "SELECT key, value FROM settings WHERE key IN "
        "('panel_title', 'panel_subtitle', 'panel_logo')"
    )
    data = {r["key"]: r["value"] for r in rows}
    return {
        "title": data.get("panel_title", ""),
        "subtitle": data.get("panel_subtitle", ""),
        "logo": data.get("panel_logo", ""),
    }


class AppearanceUpdate(BaseModel):
    """Обновление внешнего вида (FR-3.10.1)."""

    title: str | None = Field(default=None, max_length=100)
    subtitle: str | None = Field(default=None, max_length=200)
    logo: str | None = Field(default=None, max_length=500)


@router.put("/appearance")
async def update_appearance(
    payload: AppearanceUpdate,
    request: Request,
    session: SessionData = Depends(require_role("admin")),
) -> Any:
    """Сохранение заголовка/подзаголовка/логотипа (admin)."""
    db: Database = request.app.state.db
    ip = client_ip(request)
    mapping = {
        "title": "panel_title",
        "subtitle": "panel_subtitle",
        "logo": "panel_logo",
    }
    updates = {key: getattr(payload, field) for field, key in mapping.items()
               if getattr(payload, field) is not None}
    for key, value in updates.items():
        await db.execute(
            "INSERT INTO settings (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )
    await log_event(
        db, session.username, "settings.appearance_updated", ip=ip,
        details={"keys": sorted(updates)},
    )
    return {"updated": sorted(updates)}


@router.get("/captcha")
async def get_captcha_settings(
    request: Request,
    _: SessionData = Depends(require_role("admin", "support")),
) -> Any:
    """Настройка CAPTCHA (FR-3.10.3)."""
    db: Database = request.app.state.db
    row = await db.fetch_one("SELECT value FROM settings WHERE key = 'captcha_enabled'")
    return {"enabled": row is not None and row["value"] == "1"}


@router.put("/captcha")
async def update_captcha_settings(
    request: Request,
    payload: dict[str, bool],
    session: SessionData = Depends(require_role("admin")),
) -> Any:
    """Вкл/выкл CAPTCHA (admin, FR-3.10.3)."""
    db: Database = request.app.state.db
    ip = client_ip(request)
    enabled = bool(payload.get("enabled", False))
    await db.execute(
        "INSERT INTO settings (key, value) VALUES ('captcha_enabled', ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        ("1" if enabled else "0",),
    )
    await log_event(
        db, session.username, "settings.captcha_updated", ip=ip,
        details={"enabled": enabled},
    )
    return {"enabled": enabled}


@router.get("/alerts")
async def get_alerts_settings(
    request: Request,
    _: SessionData = Depends(require_role("admin", "support")),
) -> Any:
    """Настройки алертов (admin/support, FR-3.10.13): тумблеры без секретов."""
    db: Database = request.app.state.db
    config = await get_alert_config(db)
    return {
        "toggles": config.toggles,
        "telegram_configured": config.configured,
        "server_down_minutes": config.server_down_minutes,
        "ssl_cert_path": config.ssl_cert_path,
    }


class AlertsUpdate(BaseModel):
    """Обновление настроек алертов (admin, FR-3.10.13)."""

    toggles: dict[str, bool] | None = None
    bot_token: str | None = None
    chat_id: str | None = None
    ssl_cert_path: str | None = None
    server_down_minutes: int | None = Field(default=None, ge=1, le=1440)


@router.put("/alerts")
async def update_alerts_settings(
    payload: AlertsUpdate,
    request: Request,
    session: SessionData = Depends(require_role("admin")),
) -> Any:
    """Сохранение настроек алертов (admin). Токен только на запись."""
    db: Database = request.app.state.db
    ip = client_ip(request)
    try:
        await save_alert_config(
            db,
            toggles=payload.toggles,
            bot_token=payload.bot_token if payload.bot_token is not None else ...,
            chat_id=payload.chat_id if payload.chat_id is not None else ...,
            ssl_cert_path=(
                payload.ssl_cert_path if payload.ssl_cert_path is not None else ...
            ),
            server_down_minutes=payload.server_down_minutes,
        )
    except ValueError as exc:
        return JSONResponse(
            status_code=400,
            content={"error_code": "invalid_request", "message": str(exc), "details": {}},
        )
    await log_event(
        db, session.username, "settings.alerts_updated", ip=ip,
        details={"toggles": payload.toggles,
                 "server_down_minutes": payload.server_down_minutes},
    )
    config = await get_alert_config(db)
    return {
        "toggles": config.toggles,
        "telegram_configured": config.configured,
    }


@router.post("/alerts/test")
async def test_alerts(
    request: Request,
    session: SessionData = Depends(require_role("admin")),
) -> Any:
    """Пробная отправка алерта в Telegram (admin)."""
    db: Database = request.app.state.db
    ip = client_ip(request)
    config = await get_alert_config(db)
    if not config.configured:
        return JSONResponse(
            status_code=400,
            content={
                "error_code": "telegram_not_configured",
                "message": "Bot token and chat id are not configured",
                "details": {},
            },
        )
    try:
        await send_alert_message(
            config.bot_token or "", config.chat_id or "",
            "✅ Amnezia Web Panel test alert",
        )
    except TelegramSendError as exc:
        return JSONResponse(
            status_code=502,
            content={"error_code": "telegram_send_failed",
                     "message": str(exc), "details": {}},
        )
    await log_event(db, session.username, "settings.alerts_test", ip=ip)
    return {"sent": True}


@router.get("/disk")
async def disk_status(
    request: Request,
    _: SessionData = Depends(require_role("admin", "support")),
) -> Any:
    """Дисковый статус (FR-3.15.7): free_mb, критичность, read-only."""
    state = last_state()
    if state is None:
        from app.core.disk_guard import check_disk

        state = await check_disk()
    return {
        "free_mb": state.free_mb,
        "critical": state.critical,
        "read_only": state.read_only,
    }


_ = ALERT_KEYS  # реэкспорт для тестов
