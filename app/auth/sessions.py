"""Подписанные cookie-сессии (ТЗ §2.3).

HMAC-SHA256 подпись payloads ключом ``SECRET_KEY`` (стандартная библиотека,
без новых зависимостей). Сроки: absolute (7 дней) и idle (24 ч) — из настроек.
Инвалидация при ``enabled=false``/понижении роли/``role=none`` выполняется на
каждом запросе сверкой с БД (см. ``app/auth/dependencies.py``).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field

from app.core.config import get_settings

COOKIE_NAME = "awp_session"


class SessionError(Exception):
    """Сессия отсутствует, повреждена или истекла."""


def _sign(key: str, payload: bytes) -> str:
    return hmac.new(key.encode("utf-8"), payload, hashlib.sha256).hexdigest()


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text.encode("ascii"))


@dataclass(slots=True)
class SessionData:
    """Данные сессии, хранящиеся в cookie (подписано, но не зашифровано)."""

    user_id: int
    username: str
    role: str
    must_change_password: bool = False
    issued_at: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)

    def to_token(self) -> str:
        settings = get_settings()
        payload = json.dumps(
            {
                "uid": self.user_id,
                "u": self.username,
                "r": self.role,
                "mcp": self.must_change_password,
                "iat": round(self.issued_at, 3),
                "ls": round(self.last_seen, 3),
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        sig = _sign(settings.secret_key, payload)
        return f"{_b64e(payload)}.{sig}"

    @classmethod
    def from_token(cls, token: str) -> SessionData:
        settings = get_settings()
        try:
            payload_b64, sig = token.split(".", 1)
            payload = _b64d(payload_b64)
        except ValueError as exc:
            raise SessionError("malformed session token") from exc
        if not hmac.compare_digest(_sign(settings.secret_key, payload), sig):
            raise SessionError("session signature mismatch")
        try:
            raw = json.loads(payload)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise SessionError("malformed session payload") from exc

        now = time.time()
        if now - raw["iat"] > settings.session_abs_ttl_seconds:
            raise SessionError("session expired (absolute)")
        if now - raw["ls"] > settings.session_idle_ttl_seconds:
            raise SessionError("session expired (idle)")
        return cls(
            user_id=raw["uid"],
            username=raw["u"],
            role=raw["r"],
            must_change_password=raw["mcp"],
            issued_at=raw["iat"],
            last_seen=raw["ls"],
        )

    def revoked_key(self) -> tuple[int, float]:
        """Ключ для blacklist logout'ов (user_id + issued_at)."""
        return (self.user_id, self.issued_at)

    def touched(self) -> SessionData:
        """Копия с обновлённым ``last_seen`` (для продления idle-таймаута)."""
        return SessionData(
            user_id=self.user_id,
            username=self.username,
            role=self.role,
            must_change_password=self.must_change_password,
            issued_at=self.issued_at,
            last_seen=time.time(),
        )

    def is_alive_at(self, now: float) -> bool:
        settings = get_settings()
        return (
            now - self.issued_at <= settings.session_abs_ttl_seconds
            and now - self.last_seen <= settings.session_idle_ttl_seconds
        )
