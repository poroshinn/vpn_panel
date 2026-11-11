"""Bearer API-токены (FR-3.12.4, ТЗ §2.3).

- префикс ``awp_``; в БД — только SHA-256-хэш, полное значение возвращается
  однократно при создании/ротации (правило 3 AGENTS.md);
- токен наследует роль владельца динамически (проверка живой роли на каждом
  запросе); TTL опционален (``expires_at`` nullable — бессрочный);
- мгновенный отзыв и ротация (новый + отзыв старого);
- hook ``revoke_user_tokens`` — автопрекращение при отключении/удалении/
  понижении владельца (интеграция с UserService из MVP-08).
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any

from app.auth.sessions import SessionData
from app.db.database import Database

TOKEN_PREFIX = "awp_"  # noqa: S105 — публичный префикс, не секрет
TOKEN_RANDOM_BYTES = 32
MAX_ACTIVE_TOKENS = 20

_DEFAULT_COLUMNS = (
    "id, name, owner_id, expires_at, revoked_at, created_at"
)


class TokenError(Exception):
    """Ошибка работы с токеном с машинным кодом."""

    def __init__(self, error_code: str, message: str) -> None:
        super().__init__(message)
        self.error_code = error_code
        self.message = message


def _now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _hash_token(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _new_raw_token() -> str:
    return TOKEN_PREFIX + secrets.token_urlsafe(TOKEN_RANDOM_BYTES)


def _parse_iso(ts: str | None) -> datetime | None:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts)
    except ValueError:
        return None


class TokenService:
    """Сервис Bearer-токенов. Один инстанс на процесс."""

    # ------------------------------------------------------------- manage

    async def create(
        self,
        db: Database,
        *,
        owner_id: int,
        owner_role: str,
        name: str,
        ttl_seconds: int | None = None,
    ) -> tuple[str, dict[str, Any]]:
        """Создать токен; вернуть (raw, запись). raw виден только здесь."""
        if owner_role not in ("admin", "support"):
            raise TokenError("insufficient_role", "Only admin/support may own API tokens")
        active = await db.fetch_one(
            "SELECT COUNT(*) AS n FROM api_tokens "
            "WHERE owner_id = ? AND revoked_at IS NULL",
            (owner_id,),
        )
        if active and int(active["n"]) >= MAX_ACTIVE_TOKENS:
            raise TokenError(
                "too_many_tokens",
                f"Maximum {MAX_ACTIVE_TOKENS} active tokens per owner",
            )
        raw = _new_raw_token()
        expires_at = (
            (datetime.now(UTC) + timedelta(seconds=ttl_seconds)).isoformat(timespec="seconds")
            if ttl_seconds is not None
            else None
        )
        created_at = _now_iso()
        token_id = await db.execute(
            "INSERT INTO api_tokens"
            " (name, token_hash, owner_id, expires_at, revoked_at, created_at)"
            " VALUES (?, ?, ?, ?, NULL, ?)",
            (name, _hash_token(raw), owner_id, expires_at, created_at),
        )
        row = await db.fetch_one(
            f"SELECT {_DEFAULT_COLUMNS} FROM api_tokens WHERE id = ?",  # noqa: S608
            (token_id,),
        )
        return raw, dict(row) if row else {}

    async def list_tokens(self, db: Database, owner_id: int) -> list[dict[str, Any]]:
        """Токены владельца (без хэшей)."""
        rows = await db.fetch_all(
            f"SELECT {_DEFAULT_COLUMNS} FROM api_tokens WHERE owner_id = ?"  # noqa: S608
            " ORDER BY created_at DESC, id DESC",
            (owner_id,),
        )
        return [dict(r) for r in rows]

    async def get_owned(
        self, db: Database, owner_id: int, token_id: int
    ) -> dict[str, Any] | None:
        row = await db.fetch_one(
            f"SELECT {_DEFAULT_COLUMNS} FROM api_tokens WHERE id = ? AND owner_id = ?",  # noqa: S608
            (token_id, owner_id),
        )
        return dict(row) if row else None

    async def rotate(
        self, db: Database, *, owner_id: int, owner_role: str, token_id: int
    ) -> tuple[str, dict[str, Any]]:
        """Ротация: старый отзывается, создаётся новый с тем же именем/TTL."""
        old = await self.get_owned(db, owner_id, token_id)
        if old is None:
            raise TokenError("token_not_found", "Token not found")
        if old["revoked_at"] is not None:
            raise TokenError("token_revoked", "Token already revoked")
        remaining: timedelta | None = None
        exp = _parse_iso(old["expires_at"])
        if exp is not None:
            remaining = exp - datetime.now(UTC)
            if remaining.total_seconds() <= 0:
                raise TokenError("token_expired", "Token already expired")
        ttl = int(remaining.total_seconds()) if remaining is not None else None
        await self.revoke(db, owner_id=owner_id, token_id=token_id)
        return await self.create(
            db,
            owner_id=owner_id,
            owner_role=owner_role,
            name=str(old["name"]),
            ttl_seconds=ttl,
        )

    async def revoke(self, db: Database, *, owner_id: int, token_id: int) -> bool:
        """Мгновенный отзыв одного своего токена."""
        old = await self.get_owned(db, owner_id, token_id)
        if old is None:
            raise TokenError("token_not_found", "Token not found")
        if old["revoked_at"] is not None:
            return False
        await db.execute(
            "UPDATE api_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
            (_now_iso(), token_id),
        )
        return True

    async def revoke_user_tokens(self, db: Database, user_id: int) -> int:
        """Hook UserService: отозвать все токены пользователя."""
        before = await db.fetch_one(
            "SELECT COUNT(*) AS n FROM api_tokens WHERE owner_id = ? AND revoked_at IS NULL",
            (user_id,),
        )
        await db.execute(
            "UPDATE api_tokens SET revoked_at = ? WHERE owner_id = ? AND revoked_at IS NULL",
            (_now_iso(), user_id),
        )
        return int(before["n"]) if before else 0

    # -------------------------------------------------------- authenticate

    async def authenticate(self, db: Database, raw: str) -> SessionData:
        """Аутентификация по Bearer-токену.

        Роль берётся живой из ``users.role`` (наследование актуальное);
        при disable/role=none владельца токен недействителен.
        """
        if not raw.startswith(TOKEN_PREFIX):
            raise TokenError("invalid_token", "Malformed token")
        row = await db.fetch_one(
            "SELECT t.id, t.token_hash, t.expires_at, t.revoked_at,"
            " u.id AS user_id, u.username, u.role, u.enabled"
            " FROM api_tokens t JOIN users u ON u.id = t.owner_id"
            " WHERE t.token_hash = ?",
            (_hash_token(raw),),
        )
        if row is None:
            raise TokenError("invalid_token", "Unknown token")
        if row["revoked_at"] is not None:
            raise TokenError("token_revoked", "Token revoked")
        exp = _parse_iso(row["expires_at"])
        if exp is not None and datetime.now(UTC) >= exp:
            raise TokenError("token_expired", "Token expired")
        if not row["enabled"] or row["role"] in ("none", "user"):
            # Токены выдаются только admin/support; user/none — недействительны
            raise TokenError("token_revoked", "Owner is not allowed API access")
        created = _parse_iso(str(row.get("created_at")))
        return SessionData(
            user_id=row["user_id"],
            username=row["username"],
            role=row["role"],
            must_change_password=False,
            issued_at=created.timestamp() if created else 0.0,
        )
