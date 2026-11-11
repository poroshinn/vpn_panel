"""REST API Bearer-токенов (FR-3.12.4): /api/v1/tokens.

Каждый пользователь (admin/support) управляет только своими токенами.
Полное значение токена возвращается однократно при создании/ротации.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from app.auth.dependencies import client_ip, get_token_service, require_role
from app.auth.sessions import SessionData
from app.auth.tokens import TokenError
from app.core.audit import log_event
from app.db.database import Database

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/tokens", tags=["API Tokens"])

_STATUS = {
    "insufficient_role": 403,
    "token_not_found": 404,
    "token_revoked": 409,
    "token_expired": 409,
    "too_many_tokens": 429,
    "invalid_token": 401,
}


def _error(exc: TokenError) -> JSONResponse:
    return JSONResponse(
        status_code=_STATUS.get(exc.error_code, 400),
        content={
            "error_code": exc.error_code,
            "message": exc.message,
            "details": {},
        },
    )


class TokenCreate(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    ttl_seconds: int | None = Field(default=None, ge=60, le=365 * 24 * 3600)


@router.get("")
async def list_tokens(
    request: Request,
    session: SessionData = Depends(require_role("admin", "support")),
) -> list[dict]:
    """Список своих токенов (без секретов)."""
    db: Database = request.app.state.db
    return await get_token_service().list_tokens(db, session.user_id)


@router.post("", status_code=201)
async def create_token(
    payload: TokenCreate,
    request: Request,
    session: SessionData = Depends(require_role("admin", "support")),
    ip: str = Depends(client_ip),
) -> dict:
    """Создать токен (raw возвращается один раз — FR-3.12.4)."""
    db: Database = request.app.state.db
    try:
        raw, record = await get_token_service().create(
            db,
            owner_id=session.user_id,
            owner_role=session.role,
            name=payload.name,
            ttl_seconds=payload.ttl_seconds,
        )
    except TokenError as exc:
        return _error(exc)
    await log_event(
        db, session.username, "api_token.created",
        object=f"api_token:{record.get('id')}", ip=ip, result="ok",
        details={"name": payload.name},
    )
    return {**record, "token": raw}


@router.post("/{token_id}/rotate")
async def rotate_token(
    token_id: int,
    request: Request,
    session: SessionData = Depends(require_role("admin", "support")),
    ip: str = Depends(client_ip),
) -> dict:
    """Ротация: новый raw + отзыв старого (FR-3.12.4)."""
    db: Database = request.app.state.db
    try:
        raw, record = await get_token_service().rotate(
            db, owner_id=session.user_id, owner_role=session.role, token_id=token_id
        )
    except TokenError as exc:
        return _error(exc)
    await log_event(
        db, session.username, "api_token.rotated",
        object=f"api_token:{token_id}", ip=ip, result="ok", details={},
    )
    return {**record, "token": raw}


@router.delete("/{token_id}")
async def revoke_token(
    token_id: int,
    request: Request,
    session: SessionData = Depends(require_role("admin", "support")),
    ip: str = Depends(client_ip),
) -> dict:
    """Мгновенный отзыв своего токена."""
    db: Database = request.app.state.db
    try:
        revoked = await get_token_service().revoke(
            db, owner_id=session.user_id, token_id=token_id
        )
    except TokenError as exc:
        return _error(exc)
    await log_event(
        db, session.username, "api_token.revoked",
        object=f"api_token:{token_id}", ip=ip, result="ok", details={},
    )
    return {"revoked": revoked}
