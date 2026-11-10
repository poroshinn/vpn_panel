"""Сервис аутентификации (ТЗ §2.2–2.3): вход, первый admin, brute-force.

- Первый пользователь создаётся при первом входе как ``admin/admin`` с
  обязательной сменой пароля (``must_change_password``).
- Brute-force: прогрессивная задержка на пару логин+IP (5 неудач → 30 с,
  экспонента), блокировка IP по лимиту.
- Инвалидация сессий при disable/понижении роли реализована сверкой с БД на
  каждом запросе (dependencies) — состояние пользователя всегда источник истины.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from datetime import datetime, timezone

from app.auth.sessions import SessionData
from app.core.security import hash_password, verify_password
from app.db.database import Database

logger = logging.getLogger(__name__)

# Brute-force параметры (ТЗ §2.3; настраиваемые — из settings БД на этапе 2)
BRUTEFORCE_THRESHOLD = 5  # неудач до начала задержки
BRUTEFORCE_BASE_DELAY = 30.0  # секунд, экспонента: 30, 60, 120...
IP_BLOCK_THRESHOLD = 20  # суммарных неудач с одного IP → блокировка
IP_BLOCK_SECONDS = 900.0

VALID_ROLES = ("admin", "support", "user", "none")


class AuthError(Exception):
    """Базовая ошибка аутентификации."""

    def __init__(self, error_code: str, message: str) -> None:
        super().__init__(message)
        self.error_code = error_code
        self.message = message


class LoginDelayed(AuthError):
    """Прогрессивная задержка ещё не истекла."""

    def __init__(self, retry_after: float) -> None:
        super().__init__("login_delayed", f"retry after {retry_after:.0f}s")
        self.retry_after = retry_after


class IpBlocked(AuthError):
    """IP заблокирован по лимиту неудач."""

    def __init__(self) -> None:
        super().__init__("ip_blocked", "too many failed attempts from this address")


class InvalidCredentials(AuthError):
    """Неверный логин или пароль."""


class CaptchaRequired(AuthError):
    """CAPTCHA не пройдена (когда включена)."""


@dataclass(slots=True)
class _FailState:
    count: int = 0
    blocked_until: float = 0.0
    last_fail_at: float = 0.0


class AuthService:
    """Вход/учётные записи; процессно-локальный brute-force стор (1 воркер)."""

    def __init__(self) -> None:
        self._login_fails: dict[tuple[str, str], _FailState] = {}  # (login, ip)
        self._ip_fails: dict[str, _FailState] = {}
        self._lock = asyncio.Lock()

    # ------------------------------------------------------- brute-force

    async def _check_throttling(self, login: str, ip: str) -> None:
        async with self._lock:
            now = time.monotonic()

            ip_state = self._ip_fails.get(ip)
            if ip_state and ip_state.blocked_until > now:
                raise IpBlocked()

            state = self._login_fails.get((login, ip))
            if state and state.blocked_until > now:
                raise LoginDelayed(retry_after=state.blocked_until - now)

    async def _register_failure(self, login: str, ip: str) -> None:
        async with self._lock:
            now = time.monotonic()

            state = self._login_fails.setdefault((login, ip), _FailState())
            state.count += 1
            state.last_fail_at = now
            if state.count >= BRUTEFORCE_THRESHOLD:
                exponent = state.count - BRUTEFORCE_THRESHOLD
                state.blocked_until = now + BRUTEFORCE_BASE_DELAY * (2**exponent)

            ip_state = self._ip_fails.setdefault(ip, _FailState())
            ip_state.count += 1
            ip_state.last_fail_at = now
            if ip_state.count >= IP_BLOCK_THRESHOLD:
                ip_state.blocked_until = now + IP_BLOCK_SECONDS

            self._gc(now)

    async def _register_success(self, login: str, ip: str) -> None:
        async with self._lock:
            self._login_fails.pop((login, ip), None)

    def _gc(self, now: float) -> None:
        """Очистка устаревших записей (стратегия памяти, не логика безопасности)."""
        stale_pairs = [
            key
            for key, state in self._login_fails.items()
            if state.blocked_until and state.blocked_until < now - 3600
        ]
        for key in stale_pairs:
            del self._login_fails[key]
        stale_ips = [
            ip
            for ip, state in self._ip_fails.items()
            if state.blocked_until and state.blocked_until < now - 3600
        ]
        for ip in stale_ips:
            del self._ip_fails[ip]

    def _clear(self) -> None:
        """Сброс стора (используется тестами для изоляции)."""
        self._login_fails.clear()
        self._ip_fails.clear()

    # ------------------------------------------------------- users / вход

    async def ensure_first_admin(self, db: Database) -> None:
        """Создать ``admin/admin``, если пользователей нет (смена пароля обязательна)."""
        row = await db.fetch_one("SELECT COUNT(*) AS n FROM users")
        if row and row["n"] == 0:
            await db.execute(
                "INSERT INTO users (username, password_hash, role, enabled, "
                "disable_reasons, created_at) VALUES (?, ?, 'admin', 1, '[]', ?)",
                ("admin", hash_password("admin"), datetime.now(timezone.utc).isoformat(timespec="seconds")),
            )
            logger.info("created initial admin user (password change required)")

    async def authenticate(self, db: Database, login: str, password: str, ip: str) -> SessionData:
        """Полный вход: throttling → проверка → сессия. Ошибки — :class:`AuthError`."""
        await self._check_throttling(login, ip)

        user = await db.fetch_one("SELECT * FROM users WHERE username = ?", (login,))
        if user is None or not verify_password(user["password_hash"] or "", password):
            await self._register_failure(login, ip)
            # Единообразный ответ — не раскрываем существование логина
            raise InvalidCredentials("invalid_username_or_password", "Invalid username or password")

        if not user["enabled"]:
            await self._register_failure(login, ip)
            raise InvalidCredentials("account_disabled", "Account is disabled")

        if user["role"] not in VALID_ROLES or user["role"] == "none":
            raise AuthError("role_none", "Account has no panel access")

        await self._register_success(login, ip)
        return SessionData(
            user_id=user["id"],
            username=user["username"],
            role=user["role"],
            must_change_password=user["password_hash"] == hash_password("") or _is_initial_hash(user["password_hash"]),
        )

    # ------------------------------------------------------- смена пароля

    async def change_password(self, db: Database, user_id: int, old: str, new: str) -> None:
        """Смена пароля с проверкой старого; снимает флаг обязательной смены."""
        user = await db.fetch_one("SELECT * FROM users WHERE id = ?", (user_id,))
        if user is None or not verify_password(user["password_hash"] or "", old):
            raise InvalidCredentials("invalid_password", "Current password is incorrect")
        if len(new) < 8:
            raise AuthError("weak_password", "Password must be at least 8 characters")
        await db.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (hash_password(new), user_id),
        )


def _is_initial_hash(password_hash: str) -> bool:
    """Хэш дефолтного пароля «admin» → требуется смена при первом входе."""
    return verify_password(password_hash, "admin")
