"""Auth-эндпоинты (FR-3.12.3 Authentication): login/logout/me, CAPTCHA, смена пароля.

Ошибки — единый JSON; секреты в ответах не раскрываются (правило 3/9 AGENTS.md).
``/api/auth/*`` исключены из требования сессии (ТЗ §2.3).
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from app.api import errors
from app.auth.captcha import CaptchaExpired, captcha_store
from app.auth.dependencies import client_ip, get_current_session
from app.auth.sessions import COOKIE_NAME, SessionData
from app.auth.service import (
    AuthError,
    AuthService,
    InvalidCredentials,
    IpBlocked,
    LoginDelayed,
)
from app.core.audit import log_event
from app.core.config import get_settings
from app.db.database import Database

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/auth", tags=["Authentication"])

# Единственный сервис на процесс (регистрируется в app.state в main.py)
_service = AuthService()


def get_auth_service() -> AuthService:
    return _service


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)
    captcha_id: str | None = None
    captcha_answer: str | None = None


class ChangePasswordRequest(BaseModel):
    old_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=8, max_length=256)


class CaptchaOut(BaseModel):
    captcha_id: str
    question: str


def _error_response(exc: AuthError, status_code: int, headers: dict[str, str] | None = None) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={"error_code": exc.error_code, "message": exc.message, "details": {}},
        headers=headers,
    )


@router.get("/captcha", response_model=CaptchaOut)
async def get_captcha() -> CaptchaOut:
    """Выдать новый CAPTCHA-challenge (включается настройкой панели)."""
    challenge = await captcha_store.create()
    return CaptchaOut(captcha_id=challenge.challenge_id, question=challenge.question)


@router.post("/login")
async def login(payload: LoginRequest, request: Request, response: Response) -> dict:
    settings = get_settings()
    db: Database = request.app.state.db
    service: AuthService = _service
    ip = client_ip(request)

    try:
        # CAPTCHA (когда включена) — дополнительный слой поверх brute-force
        if settings.captcha_enabled:
            if not payload.captcha_id or payload.captcha_answer is None:
                raise AuthError(errors.CAPTCHA_FAILED, "captcha required")
            try:
                ok = await captcha_store.consume(payload.captcha_id, payload.captcha_answer)
            except CaptchaExpired as exc:
                raise AuthError(errors.CAPTCHA_EXPIRED, "captcha expired") from exc
            if not ok:
                raise AuthError(errors.CAPTCHA_FAILED, "wrong captcha answer")

        await service.ensure_first_admin(db)
        session = await service.authenticate(db, payload.username, payload.password, ip)
    except LoginDelayed as exc:
        await log_event(db, payload.username, "auth.login", ip=ip, result="delayed")
        return _error_response(exc, 429, headers={"Retry-After": str(int(exc.retry_after) + 1)})
    except IpBlocked as exc:
        await log_event(db, payload.username, "auth.login", ip=ip, result="ip_blocked")
        return _error_response(exc, 429)
    except InvalidCredentials as exc:
        await log_event(db, payload.username, "auth.login", ip=ip, result="denied")
        return _error_response(exc, 401)
    except AuthError as exc:
        await log_event(db, payload.username, "auth.login", ip=ip, result="denied")
        return _error_response(exc, 400)

    touched = session.touched()
    response.set_cookie(
        COOKIE_NAME,
        touched.to_token(),
        max_age=settings.session_abs_ttl_seconds,
        httponly=True,
        samesite="lax",
        secure=request.url.scheme == "https",
        path="/",
    )
    await log_event(db, session.username, "auth.login", ip=ip, result="ok")
    return {
        "username": session.username,
        "role": session.role,
        "must_change_password": session.must_change_password,
    }


@router.post("/logout")
async def logout(request: Request, response: Response, session: SessionData = Depends(get_current_session)) -> dict:
    db: Database = request.app.state.db
    from app.auth.dependencies import revoke_session

    revoke_session(session)  # серверная инвалидация stateless-сессии
    response.delete_cookie(COOKIE_NAME, path="/")
    await log_event(db, session.username, "auth.logout", ip=client_ip(request))
    return {"status": "ok"}


@router.get("/me")
async def me(session: SessionData = Depends(get_current_session)) -> dict:
    """Текущая сессия: кто вошёл, требуется ли смена пароля."""
    return {
        "username": session.username,
        "role": session.role,
        "must_change_password": session.must_change_password,
    }


@router.post("/change-password")
async def change_password(
    payload: ChangePasswordRequest,
    request: Request,
    session: SessionData = Depends(get_current_session),
) -> dict:
    db: Database = request.app.state.db
    service: AuthService = _service
    try:
        await service.change_password(db, session.user_id, payload.old_password, payload.new_password)
    except InvalidCredentials as exc:
        return _error_response(exc, 401)
    except AuthError as exc:
        return _error_response(exc, 400)
    # Обновляем сессию: флаг обязательной смены снят
    fresh = SessionData(
        user_id=session.user_id,
        username=session.username,
        role=session.role,
        must_change_password=False,
        issued_at=session.issued_at,
    )
    response_cookie = JSONResponse(content={"status": "ok"})
    response_cookie.set_cookie(
        COOKIE_NAME,
        fresh.to_token(),
        max_age=get_settings().session_abs_ttl_seconds,
        httponly=True,
        samesite="lax",
        secure=request.url.scheme == "https",
        path="/",
    )
    await log_event(db, session.username, "auth.password_changed", ip=client_ip(request))
    return response_cookie
