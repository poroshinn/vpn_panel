"""REST API шеринга (FR-3.8.1, FR-3.8.4): /api/v1/users/{id}/share.

Роли (матрица §2.2): setup/rotate/revoke — только admin; статус — admin/support.
Токен возвращается в открытом виде **один раз** на setup/rotate (never-echo
в остальных ответах); пароль принимается по HTTPS и сразу хэшируется.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from app.auth.dependencies import client_ip, require_role
from app.auth.sessions import SessionData
from app.db.database import Database
from app.sharing.service import ShareError, ShareService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/users", tags=["Sharing"])


def get_share(request: Request) -> ShareService:
    return request.app.state.share_service


_ERROR_STATUS = {
    "user_not_found": 404,
    "user_disabled": 409,
    "share_not_enabled": 409,
    "weak_password": 400,
    "share_unavailable": 503,
}


def _error(exc: ShareError, status_code: int) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={"error_code": exc.error_code, "message": exc.message, "details": {}},
    )


class ShareSetup(BaseModel):
    password: str | None = Field(default=None, min_length=8, max_length=256)


@router.get("/{user_id}/share")
async def share_status(
    user_id: int,
    request: Request,
    _: SessionData = Depends(require_role("admin", "support")),
    share: ShareService = Depends(get_share),
) -> Any:
    """Статус шеринга пользователя (admin/support) — без секрета токена."""
    db: Database = request.app.state.db
    try:
        return await share.share_status(db, user_id)
    except ShareError as exc:
        return _error(exc, _ERROR_STATUS.get(exc.error_code, 400))


@router.post("/{user_id}/share/setup", status_code=201)
async def share_setup(
    user_id: int,
    body: ShareSetup,
    request: Request,
    session: SessionData = Depends(require_role("admin")),
    share: ShareService = Depends(get_share),
) -> Any:
    """Включить шеринг (admin, FR-3.8.1): токен стабилен, plaintext — один раз."""
    db: Database = request.app.state.db
    try:
        result = await share.setup_share(
            db, user_id, password=body.password,
            actor=session.username, ip=client_ip(request),
        )
    except ShareError as exc:
        return _error(exc, _ERROR_STATUS.get(exc.error_code, 400))
    return result


@router.post("/{user_id}/share/rotate", status_code=201)
async def share_rotate(
    user_id: int,
    request: Request,
    session: SessionData = Depends(require_role("admin")),
    share: ShareService = Depends(get_share),
) -> Any:
    """Перегенерация токена (admin, FR-3.8.4): старая ссылка недействительна."""
    db: Database = request.app.state.db
    try:
        result = await share.rotate_token(
            db, user_id, actor=session.username, ip=client_ip(request)
        )
    except ShareError as exc:
        return _error(exc, _ERROR_STATUS.get(exc.error_code, 400))
    return result


@router.post("/{user_id}/share/revoke")
async def share_revoke(
    user_id: int,
    request: Request,
    session: SessionData = Depends(require_role("admin")),
    share: ShareService = Depends(get_share),
) -> Any:
    """Полная ревокация шеринга (admin, FR-3.8.4)."""
    db: Database = request.app.state.db
    try:
        return await share.revoke_share(
            db, user_id, actor=session.username, ip=client_ip(request)
        )
    except ShareError as exc:
        return _error(exc, _ERROR_STATUS.get(exc.error_code, 400))
