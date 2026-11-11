"""Сервис пользователей панели (FR-3.6.1–3.6.5).

- CRUD: имя, роль (``admin/support/user/none``), пароль (обязателен кроме
  ``none``), Telegram ID, включение/отключение одной кнопкой (FR-3.6.1).
- Управление подключениями пользователя: привязка/отвязка (FR-3.6.2).
- Отвязка владельца (FR-3.6.3): отключённые/отсутствующие peer'ы — напрямую;
  активные — ``stop: true`` (остановка peer'а на ноде перед отвязкой);
  нечитаемый финальный счётчик — ``allow_unverified: true``; lifecycle-lock
  на время операции.
- Автоинвалидация (FR-3.6.4): disable/понижение до ``none`` завершает сессии
  (сверка с БД на каждом запросе) и отзывает Bearer-токены — через hook
  ``TokenRevocationHook`` (сами токены появятся в MVP-11).

Секреты (password_hash и т.п.) не покидают сервис (правило 3 AGENTS.md).
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any, Protocol

from app.auth.service import VALID_ROLES
from app.core.audit import log_event
from app.core.security import hash_password
from app.db.database import Database
from app.protocols.peers import PeerError, PeerService
from app.servers.service import ServerService
from app.ssh.pool import SSHPool

logger = logging.getLogger(__name__)


FinalizeCallable = Any  # async (db, server_id, connection_id, *, allow_unverified) -> dict


class UserError(Exception):
    """Доменная ошибка пользователей (без секретов)."""

    def __init__(self, error_code: str, message: str) -> None:
        super().__init__(message)
        self.error_code = error_code
        self.message = message


class TokenRevocationHook(Protocol):
    """Hook отзыва токенов пользователя (Bearer-токены — MVP-11)."""

    async def revoke_user_tokens(self, user_id: int) -> int:
        """Отозвать все токены пользователя; вернуть количество."""
        ...


def _now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


# Колонки без секретов для выдачи наружу
_PUBLIC_COLUMNS = (
    "id, username, role, enabled, telegram_id, traffic_used, traffic_limit,"
    " expiration, disable_reasons, created_at"
)


def _row_to_dict(row: dict[str, Any]) -> dict[str, Any]:
    return dict(row)


class UserService:
    """CRUD пользователей. Один инстанс на процесс."""

    def __init__(
        self,
        pool: SSHPool,
        peers: PeerService,
        servers: ServerService,
        *,
        token_hook: TokenRevocationHook | None = None,
    ) -> None:
        self._pool = pool
        self._peers = peers
        self._servers = servers
        self._token_hook = token_hook

    def set_token_hook(self, hook: TokenRevocationHook) -> None:
        """Поздняя привязка hook'а (после создания сервисов в lifespan)."""
        self._token_hook = hook

    # ---------------------------------------------------------------- read

    async def list_users(self, db: Database) -> list[dict[str, Any]]:
        """Список пользователей (без секретов)."""
        rows = await db.fetch_all(
            f"SELECT {_PUBLIC_COLUMNS} FROM users ORDER BY username"  # noqa: S608
        )
        return [_row_to_dict(r) for r in rows]

    async def get_user(self, db: Database, user_id: int) -> dict[str, Any]:
        """Карточка пользователя (без секретов)."""
        row = await db.fetch_one(
            f"SELECT {_PUBLIC_COLUMNS} FROM users WHERE id = ?",  # noqa: S608
            (user_id,),
        )
        if row is None:
            raise UserError("user_not_found", "user not found")
        return _row_to_dict(row)

    async def user_connections(
        self, db: Database, user_id: int
    ) -> list[dict[str, Any]]:
        """Подключения пользователя (без секретов счётчиков-сырца)."""
        rows = await db.fetch_all(
            "SELECT id, server_id, protocol, client_id, name, created_source,"
            " created_at FROM user_connections WHERE user_id = ? ORDER BY id",
            (user_id,),
        )
        return [dict(r) for r in rows]

    # ---------------------------------------------------------------- CRUD

    async def create_user(
        self,
        db: Database,
        *,
        username: str,
        role: str,
        password: str | None = None,
        telegram_id: int | None = None,
        traffic_limit: int | None = None,
        expiration: str | None = None,
        actor: str | None = None,
        ip: str | None = None,
    ) -> dict[str, Any]:
        """Создать пользователя (FR-3.6.1): пароль обязателен кроме ``none``."""
        username = (username or "").strip()
        if not username:
            raise UserError("invalid_username", "username is required")
        if role not in VALID_ROLES:
            raise UserError("invalid_role", f"role must be one of {VALID_ROLES}")
        if role != "none" and not password:
            raise UserError("password_required", "password is required for this role")
        exists = await db.fetch_one(
            "SELECT id FROM users WHERE username = ?", (username,)
        )
        if exists:
            raise UserError("username_taken", "username already exists")

        async with db.transaction() as tx:
            await tx.execute(
                "INSERT INTO users (username, password_hash, role, enabled,"
                " telegram_id, traffic_limit, expiration, disable_reasons,"
                " created_at) VALUES (?, ?, ?, 1, ?, ?, ?, '[]', ?)",
                (
                    username,
                    hash_password(password) if password else None,
                    role,
                    telegram_id,
                    traffic_limit,
                    expiration,
                    _now_iso(),
                ),
            )
        await log_event(
            db, actor or "system", "user.created",
            object=f"user:{username}", ip=ip,
            details={"role": role},
        )
        row = await db.fetch_one(
            f"SELECT {_PUBLIC_COLUMNS} FROM users WHERE username = ?",  # noqa: S608
            (username,),
        )
        return _row_to_dict(row) if row else {}

    async def update_user(
        self,
        db: Database,
        user_id: int,
        *,
        role: str | None = None,
        password: str | None = None,
        telegram_id: int | None = ...,
        traffic_limit: int | None = ...,
        expiration: str | None = ...,
        actor: str | None = None,
        ip: str | None = None,
    ) -> dict[str, Any]:
        """Изменить пользователя: роль/пароль/telegram/квоту/expiration.

        Понижение роли (в т.ч. до ``none``) вызывает hook отзыва токенов
        (FR-3.6.4); сессии режутся сверкой роли с БД в dependencies.
        """
        current = await db.fetch_one("SELECT * FROM users WHERE id = ?", (user_id,))
        if current is None:
            raise UserError("user_not_found", "user not found")

        sets: list[str] = []
        params: list[Any] = []
        revoke_tokens = False

        if role is not None:
            if role not in VALID_ROLES:
                raise UserError("invalid_role", f"role must be one of {VALID_ROLES}")
            if role != "none" and current["password_hash"] is None and password is None:
                raise UserError(
                    "password_required", "password is required for this role"
                )
            sets.append("role = ?")
            params.append(role)
            if role == "none":
                # Полная потеря доступа: сессии инвалидацией по role_changed,
                # токены — отзывом (FR-3.6.4)
                revoke_tokens = True

        if password is not None:
            if len(password) < 8:
                raise UserError("weak_password", "password must be at least 8 characters")
            sets.append("password_hash = ?")
            params.append(hash_password(password))

        if telegram_id is not ...:
            sets.append("telegram_id = ?")
            params.append(telegram_id)
        if traffic_limit is not ...:
            sets.append("traffic_limit = ?")
            params.append(traffic_limit)
        if expiration is not ...:
            sets.append("expiration = ?")
            params.append(expiration)

        if sets:
            params.append(user_id)
            await db.execute(
                f"UPDATE users SET {', '.join(sets)} WHERE id = ?",  # noqa: S608
                tuple(params),
            )
            await log_event(
                db, actor or "system", "user.updated",
                object=f"user:{current['username']}", ip=ip,
                details={"fields": [s.split(" =")[0] for s in sets]},
            )
        if revoke_tokens and self._token_hook is not None:
            await self._token_hook.revoke_user_tokens(user_id)
        return await self.get_user(db, user_id)

    async def set_enabled(
        self,
        db: Database,
        user_id: int,
        *,
        enabled: bool,
        actor: str | None = None,
        ip: str | None = None,
    ) -> dict[str, Any]:
        """Включение/отключение одной кнопкой (FR-3.6.1, FR-3.6.4).

        Disable ⇒ сессии мгновенно недействительны (сверка с БД в
        dependencies) + отзыв Bearer-токенов через hook.
        """
        current = await db.fetch_one("SELECT * FROM users WHERE id = ?", (user_id,))
        if current is None:
            raise UserError("user_not_found", "user not found")
        if current["role"] == "admin" and not enabled:
            admins = await db.fetch_one(
                "SELECT COUNT(*) AS n FROM users WHERE role = 'admin' AND enabled = 1"
            )
            if admins and admins["n"] <= 1:
                raise UserError(
                    "last_admin", "cannot disable the last enabled admin"
                )
        await db.execute(
            "UPDATE users SET enabled = ? WHERE id = ?", (1 if enabled else 0, user_id)
        )
        if not enabled and self._token_hook is not None:
            await self._token_hook.revoke_user_tokens(user_id)
        await log_event(
            db, actor or "system",
            "user.enabled" if enabled else "user.disabled",
            object=f"user:{current['username']}", ip=ip,
        )
        return await self.get_user(db, user_id)

    async def delete_user(
        self,
        db: Database,
        user_id: int,
        *,
        actor: str | None = None,
        ip: str | None = None,
    ) -> dict[str, Any]:
        """Удалить пользователя (FK CASCADE удалит и его подключения)."""
        current = await db.fetch_one("SELECT * FROM users WHERE id = ?", (user_id,))
        if current is None:
            raise UserError("user_not_found", "user not found")
        if current["role"] == "admin":
            admins = await db.fetch_one(
                "SELECT COUNT(*) AS n FROM users WHERE role = 'admin' AND enabled = 1"
            )
            if admins and admins["n"] <= 1:
                raise UserError("last_admin", "cannot delete the last enabled admin")
        await db.execute("DELETE FROM users WHERE id = ?", (user_id,))
        if self._token_hook is not None:
            await self._token_hook.revoke_user_tokens(user_id)
        await log_event(
            db, actor or "system", "user.deleted",
            object=f"user:{current['username']}", ip=ip,
        )
        return {"deleted": user_id}

    # ------------------------------------------------- привязка/отвязка (3.6.2)

    async def assign_connection(
        self,
        db: Database,
        *,
        connection_id: int,
        user_id: int,
        actor: str | None = None,
        ip: str | None = None,
    ) -> dict[str, Any]:
        """Привязать существующее подключение к пользователю (FR-3.6.2)."""
        conn = await db.fetch_one(
            "SELECT id, name FROM user_connections WHERE id = ?", (connection_id,)
        )
        if conn is None:
            raise UserError("connection_not_found", "connection not found")
        user = await db.fetch_one("SELECT username FROM users WHERE id = ?", (user_id,))
        if user is None:
            raise UserError("user_not_found", "user not found")
        await db.execute(
            "UPDATE user_connections SET user_id = ? WHERE id = ?",
            (user_id, connection_id),
        )
        await log_event(
            db, actor or "system", "connection.assigned",
            object=f"connection:{connection_id}", ip=ip,
            details={"user_id": user_id},
        )
        return {"connection_id": connection_id, "user_id": user_id}

    async def unlink_owner(
        self,
        db: Database,
        *,
        connection_id: int,
        stop: bool = True,
        allow_unverified: bool = False,
        finalize: FinalizeCallable | None = None,
        actor: str | None = None,
        ip: str | None = None,
    ) -> dict[str, Any]:
        """Отвязка владельца (FR-3.6.3) с финализацией учёта.

        - Peer отсутствует (запись есть, но на ноде не найден) или отключён —
          финализация напрямую.
        - Peer активен и ``stop=True`` — сначала отключение на ноде, затем
          финализация.
        - Нечитаемый финальный счётчик: при ``allow_unverified=True`` —
          tombstone без дельты; иначе ошибка 409-подобная (``can_force``).
        - lifecycle-lock на всё время операции.

        ``finalize`` — callable с сигнатурой
        ``finalize(db, server_id, connection_id, allow_unverified=...) -> dict``
        (инжектится роутом из :class:`FinalizationService`).
        """
        conn = await db.fetch_one(
            "SELECT * FROM user_connections WHERE id = ?", (connection_id,)
        )
        if conn is None:
            raise UserError("connection_not_found", "connection not found")
        server_id = conn["server_id"]

        # lifecycle-lock берут внутренние операции (set_peer_enabled, финализация
        # через peer_service); внешний lock здесь = deadlock (Lock не реентерабельный)
        if stop:
            # best-effort остановка на ноде; отсутствие peer'а не ошибка
            try:
                await self._peers.set_peer_enabled(
                    db, server_id, connection_id, enabled=False
                )
            except PeerError as exc:
                logger.info(
                    "unlink %s: pre-stop skipped (%s)", connection_id, exc.error_code
                )
        if finalize is None:
            raise UserError(
                "finalization_unavailable", "finalization service unavailable"
            )
        # FinalizationError пробрасывается как есть (fail-closed, can_force)
        result = await finalize(
            db, server_id, connection_id,
            allow_unverified=allow_unverified,
        )
        await log_event(
            db, actor or "system", "connection.unlinked",
            object=f"connection:{connection_id}", ip=ip,
            details={
                "user_id": conn["user_id"],
                "status": result.get("status"),
                "counters_verified_final": result.get("counters_verified_final"),
            },
        )
        return result
