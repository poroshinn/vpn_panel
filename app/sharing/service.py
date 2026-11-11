"""Сервис публичного шеринга конфигураций (FR-3.8.1–3.8.4).

- Share-токен пользователя: стабилен (админ отдаёт ссылку многократно),
  хранится как есть в ``users.share_token`` (это не секрет панели, но
  действует как «пароль входа» на share-страницу — перебор отсекается
  rate-limit'ом, длина ≥ 32 символов crypto-random);
- Share-пароль: только argon2-хэш в ``users.share_password_hash`` (правило 3
  AGENTS.md — never-echo);
- Перегенерация токена мгновенно инвалидирует старую ссылку (FR-3.8.4);
- Ревокация полностью закрывает share-доступ;
- Все операции — audit-события ``share.*``.

Share-сессии (после успешного ввода пароля) — подписанные cookie-токены
HMAC-SHA256 с ревизией (revision = краткий хэш share_password_hash + token),
чтобы смена пароля/токена немедленно разлогинивала share-сессии.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import time
from typing import Any

from app.core.audit import log_event
from app.core.config import get_settings
from app.core.security import generate_token, hash_password, verify_password
from app.db.database import Database
from app.protocols.peers import PeerService

logger = logging.getLogger(__name__)

SHARE_COOKIE = "awp_share"


class ShareError(Exception):
    """Доменная ошибка шеринга (без секретов)."""

    def __init__(self, error_code: str, message: str) -> None:
        super().__init__(message)
        self.error_code = error_code
        self.message = message


def _now() -> float:
    return time.time()


def _revision(share_token: str, password_hash: str | None) -> str:
    """Ревизия share-сессии: меняется при любом изменении параметров доступа."""
    payload = f"{share_token}|{password_hash or ''}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def sign_share_session(value: str, *, secret: str) -> str:
    """Подпись share-сессии HMAC-SHA256: ``payload.signature``."""
    sig = hmac.new(secret.encode("utf-8"), value.encode("utf-8"), hashlib.sha256)
    return f"{value}.{sig.hexdigest()}"


def verify_share_session(signed: str, *, secret: str) -> str | None:
    """Проверка подписи share-сессии; невалидна → None."""
    if not signed or "." not in signed:
        return None
    payload, _, sig = signed.rpartition(".")
    expected = hmac.new(
        secret.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(sig, expected):
        return None
    return payload


class ShareService:
    """Управление share-токенами и паролями. Один инстанс на процесс."""

    def __init__(self, peers: PeerService) -> None:
        self._peers = peers
        # rate-limit попыток пароля: key=token → (window_start, attempts)
        self._attempts: dict[str, tuple[float, int]] = {}
        self._attempts_guard: Any = None  # последовательный event-loop

    # ------------------------------------------------------------ rate-limit

    _RATE_WINDOW = 60.0
    _RATE_MAX = 10

    def _rate_ok(self, token: str) -> bool:
        """Простой in-process rate-limit на попытки пароля по токену."""
        now = _now()
        entry = self._attempts.get(token)
        if entry is None or now - entry[0] > self._RATE_WINDOW:
            self._attempts[token] = (now, 1)
            return True
        if entry[1] >= self._RATE_MAX:
            return False
        self._attempts[token] = (entry[0], entry[1] + 1)
        return True

    # ---------------------------------------------------------------- read

    async def share_status(self, db: Database, user_id: int) -> dict[str, Any]:
        """Статус шеринга пользователя (без секрета токена: только факт)."""
        row = await db.fetch_one(
            "SELECT share_token, share_enabled, share_password_hash"
            " FROM users WHERE id = ?",
            (user_id,),
        )
        if row is None:
            raise ShareError("user_not_found", "user not found")
        return {
            "user_id": user_id,
            "share_enabled": bool(row["share_enabled"]),
            "has_password": bool(row["share_password_hash"]),
            "has_token": bool(row["share_token"]),
        }

    # ---------------------------------------------------------------- setup

    async def setup_share(
        self,
        db: Database,
        user_id: int,
        *,
        password: str | None = None,
        actor: str | None = None,
        ip: str | None = None,
    ) -> dict[str, Any]:
        """Включить шеринг (FR-3.8.1): создать/переиспользовать токен.

        Токен стабилен: повторный setup не меняет существующую ссылку.
        Пароль при передаче — сразу хэшем. Возврат содержит plaintext-токен
        **один раз** (админ успевает скопировать ссылку).
        """
        row = await db.fetch_one(
            "SELECT id, username, share_token, share_password_hash, enabled, role"
            " FROM users WHERE id = ?",
            (user_id,),
        )
        if row is None:
            raise ShareError("user_not_found", "user not found")
        if row["role"] == "none" or not row["enabled"]:
            raise ShareError("user_disabled", "user disabled or role none")

        token = row["share_token"] or generate_token("sh")
        sets = ["share_token = ?", "share_enabled = 1"]
        params: list[Any] = [token]
        if password is not None:
            if len(password) < 8:
                raise ShareError("weak_password", "password must be at least 8 characters")
            sets.append("share_password_hash = ?")
            params.append(hash_password(password))
        params.append(user_id)
        await db.execute(
            f"UPDATE users SET {', '.join(sets)} WHERE id = ?",  # noqa: S608
            params,
        )

        await log_event(
            db, actor or "system", "share.setup",
            object=f"user:{row['username']}", ip=ip,
            details={"password_set": password is not None},
        )
        return {"share_token": token, "share_enabled": True}

    # --------------------------------------------------------------- rotate

    async def rotate_token(
        self,
        db: Database,
        user_id: int,
        *,
        actor: str | None = None,
        ip: str | None = None,
    ) -> dict[str, Any]:
        """Перегенерация токена (FR-3.8.4): старая ссылка недействительна сразу."""
        row = await db.fetch_one(
            "SELECT id, username, share_enabled FROM users WHERE id = ?", (user_id,)
        )
        if row is None:
            raise ShareError("user_not_found", "user not found")
        if not row["share_enabled"]:
            raise ShareError("share_not_enabled", "sharing is not enabled")

        token = generate_token("sh")
        await db.execute(
            "UPDATE users SET share_token = ? WHERE id = ?", (token, user_id)
        )
        await log_event(
            db, actor or "system", "share.token_rotated",
            object=f"user:{row['username']}", ip=ip,
        )
        return {"share_token": token, "share_enabled": True}

    async def revoke_share(
        self,
        db: Database,
        user_id: int,
        *,
        actor: str | None = None,
        ip: str | None = None,
    ) -> dict[str, Any]:
        """Полная ревокация шеринга (FR-3.8.4): токен+пароль стираются."""
        row = await db.fetch_one(
            "SELECT id, username FROM users WHERE id = ?", (user_id,)
        )
        if row is None:
            raise ShareError("user_not_found", "user not found")
        await db.execute(
            "UPDATE users SET share_enabled = 0, share_token = NULL,"
            " share_password_hash = NULL WHERE id = ?",
            (user_id,),
        )
        self._attempts.pop(f"user:{user_id}", None)
        await log_event(
            db, actor or "system", "share.revoked",
            object=f"user:{row['username']}", ip=ip,
        )
        return {"share_enabled": False}

    # --------------------------------------------------------------- access

    async def resolve_token(self, db: Database, token: str) -> dict[str, Any] | None:
        """Валидный включённый share → строка владельца, иначе None."""
        if not token or len(token) < 16 or not token.startswith("sh_"):
            return None
        row = await db.fetch_one(
            "SELECT id, username, share_token, share_enabled, share_password_hash,"
            " enabled, role FROM users WHERE share_token = ?",
            (token,),
        )
        if row is None or not row["share_enabled"]:
            return None
        if row["role"] == "none" or not row["enabled"]:
            return None
        return dict(row)

    async def verify_share_password(
        self, db: Database, user_id: int, *, password: str
    ) -> bool:
        """Проверка share-пароля по хэшу (rate-limited на уровне вызова)."""
        row = await db.fetch_one(
            "SELECT share_password_hash FROM users WHERE id = ?", (user_id,)
        )
        if row is None or not row["share_password_hash"]:
            return False
        return verify_password(row["share_password_hash"], password)

    def session_value(self, token: str, password_hash: str | None) -> str:
        """Значение подписываемой share-сессии: ``uid:rev``."""
        return f"{token}:{_revision(token, password_hash)}"

    # ------------------------------------------------------------ содержимое

    async def shared_connections(
        self, db: Database, user_id: int
    ) -> list[dict[str, Any]]:
        """Подключения владельца для share-страницы (без секретов/счётчиков)."""
        rows = await db.fetch_all(
            "SELECT id, server_id, protocol, client_id, name, created_at"
            " FROM user_connections WHERE user_id = ? ORDER BY id",
            (user_id,),
        )
        return [dict(r) for r in rows]

    def secret_for_signing(self) -> str:
        """Секрет HMAC для share-сессий (мастер-ключ панели, hex)."""
        settings = get_settings()
        if settings.panel_master_key:
            return settings.panel_master_key
        from app.core.security import _load_master_key  # noqa: SLF001

        return _load_master_key().hex()
