"""Единая точка авторизации (ТЗ §2.2 — матрица полномочий, источник истины).

- ``get_current_session`` — разбирает cookie, сверяет пользователя с БД
  (инвалидация при ``enabled=false``/понижении роли/``role=none``).
- ``require_role(*roles)`` — зависимость FastAPI; 401 без сессии, 403 без роли.
- API-ошибки — единый JSON (правило 9 AGENTS.md).
"""

from __future__ import annotations

from typing import Any

from fastapi import Depends, HTTPException, Request
from fastapi.responses import JSONResponse

from app.auth.sessions import COOKIE_NAME, SessionData, SessionError
from app.db.database import Database

ROLE_RANK = {"none": 0, "user": 1, "support": 2, "admin": 3}


def api_error(status_code: int, error_code: str, message: str, details: dict[str, Any] | None = None) -> JSONResponse:
    """Единый формат ошибки API (правило 9 AGENTS.md)."""
    return JSONResponse(
        status_code=status_code,
        content={"error_code": error_code, "message": message, "details": details or {}},
    )


# Процессно-локальный blacklist отозванных logout'ом сессий (1 воркер).
# Ключ — (user_id, issued_at); записи чистятся по мере истечения absolute TTL.
_revoked_sessions: set[tuple[int, float]] = set()


def revoke_session(session: SessionData) -> None:
    """Отозвать сессию (logout) — процессно-локально, до конца absolute TTL."""
    _revoked_sessions.add(session.revoked_key())


def _is_revoked(session: SessionData) -> bool:
    return session.revoked_key() in _revoked_sessions


def _gc_revoked() -> None:
    """Очистка blacklist'а от сессий, умерших по absolute TTL сами."""
    import time

    settings = get_settings()
    now = time.time()
    alive = {
        key
        for key in _revoked_sessions
        if now - key[1] <= settings.session_abs_ttl_seconds
    }
    _revoked_sessions.intersection_update(alive)


async def get_current_session(request: Request) -> SessionData:
    """Текущая сессия из cookie; сверка с БД на каждом запросе.

    :raises HTTPException: 401 — нет/битая сессия; 403 — сессия невалидна
        (пользователь отключён, роль none).
    """
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        raise HTTPException(status_code=401, detail="not_authenticated")
    try:
        session = SessionData.from_token(token)
    except SessionError as exc:
        raise HTTPException(status_code=401, detail="invalid_session") from exc
    if _is_revoked(session):
        raise HTTPException(status_code=401, detail="session_revoked")
    if len(_revoked_sessions) > 1024:
        _gc_revoked()

    db: Database = request.app.state.db
    user = await db.fetch_one("SELECT id, username, role, enabled FROM users WHERE id = ?", (session.user_id,))
    if user is None or not user["enabled"]:
        # Инвалидация: пользователь удалён или отключён
        raise HTTPException(status_code=403, detail="account_disabled")
    if user["role"] != session.role:
        # Инвалидация: роль изменилась (понижение/повышение) — пересоздаём сессию
        raise HTTPException(status_code=401, detail="role_changed")
    if user["role"] == "none":
        raise HTTPException(status_code=403, detail="account_disabled")

    request.state.session = session
    return session


async def require_session(session: SessionData = Depends(get_current_session)) -> SessionData:
    """Любая валидная сессия (роли admin/support/user; ``none`` исключён выше)."""
    return session


def require_role(*allowed: str):
    """Зависимость-фабрика: доступ только указанным ролям (ТЗ §2.2).

    Пример: ``Depends(require_role("admin"))`` — только admin;
    ``Depends(require_role("admin", "support"))`` — просмотр/аудит.
    """

    async def _checker(session: SessionData = Depends(get_current_session)) -> SessionData:
        if session.role not in allowed:
            raise HTTPException(status_code=403, detail="insufficient_role")
        return session

    return _checker


def client_ip(request: Request) -> str:
    """IP клиента (без X-Forwarded-For до появления SSL-прокси — FR-3.10.2, этап 2)."""
    if request.client and request.client.host:
        return request.client.host
    return "unknown"
