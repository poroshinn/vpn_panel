"""CRUD peer'ов/подключений (FR-3.4.1, FR-3.4.3, FR-3.4.4, FR-3.4.8).

Ключевые свойства:
- **идемпотентность**: ``operation_id`` в ``peer_creations``; повтор того же
  ``operation_id`` не создаёт дубликат (ретрай безопасен);
- **fail-closed**: неопределённый SSH-исход → запись в ``lifecycle_uncertain``,
  счётчики не обнуляются, ретрай разрешён;
- **lifecycle-lock**: ``asyncio.Lock`` на инстанс — взаимное исключение между
  созданием/удалением/raw-config/ownership-операциями;
- **атомарная запись** таблиц клиентов (rename и др.) — в одной транзакции.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from datetime import UTC, datetime
from typing import Any

from app.db.database import Database
from app.protocols.installer import record_uncertain
from app.servers.service import ServerService, credentials_from_row
from app.ssh.pool import SSHError, SSHPool

logger = logging.getLogger(__name__)

PEER_COMMAND_TIMEOUT = 60.0


class PeerError(Exception):
    """Доменная ошибка peer-операций (без секретов в сообщении)."""

    def __init__(self, error_code: str, message: str) -> None:
        super().__init__(message)
        self.error_code = error_code
        self.message = message


class PeerUncertainError(PeerError):
    """Неопределённый исход мутации на ноде (ретрай разрешён)."""

    def __init__(self, message: str) -> None:
        super().__init__("lifecycle_uncertain", message)


def _now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


# Команды контейнера AWG/WG (исполняются внутри контейнера через docker exec)
_PEER_ADD_CMD = "docker exec {instance} awg-pc add {client_id} {name_quoted}"
_PEER_REMOVE_CMD = "docker exec {instance} awg-pc remove {client_id}"
_PEER_RENAME_CMD = "docker exec {instance} awg-pc rename {client_id} {name_quoted}"
_PEER_ENABLE_CMD = "docker exec {instance} awg-pc enable {client_id}"
_PEER_DISABLE_CMD = "docker exec {instance} awg-pc disable {client_id}"
_PEER_CONFIG_CMD = "docker exec {instance} awg-pc config {client_id}"


def _quote(name: str) -> str:
    """Кавычки для имени peer'а в shell (без инъекций)."""
    return "'" + name.replace("'", "'\\''") + "'"


class PeerService:
    """Управление peer'ами. Один инстанс на процесс."""

    def __init__(self, pool: SSHPool, servers: ServerService) -> None:
        self._pool = pool
        self._servers = servers
        # lifecycle-lock на инстанс (server_id, protocol): создаётся лениво.
        # Защищает конкурентные create/delete/raw-config/ownership.
        self._locks: dict[tuple[int, str], asyncio.Lock] = {}
        self._locks_guard = asyncio.Lock()

    async def lifecycle_lock(self, server_id: int, protocol: str) -> asyncio.Lock:
        async with self._locks_guard:
            lock = self._locks.get((server_id, protocol))
            if lock is None:
                lock = asyncio.Lock()
                self._locks[(server_id, protocol)] = lock
            return lock

    # -------------------------------------------------------------- helpers

    async def _server_row(self, db: Database, server_id: int) -> dict[str, Any]:
        row = await self._servers._get_row(db, server_id)  # noqa: SLF001
        return row

    @staticmethod
    def _require_instance(row: dict[str, Any], instance: str) -> dict[str, Any]:
        try:
            protocols = json.loads(row.get("protocols") or "{}")
        except json.JSONDecodeError as exc:
            raise PeerError("protocol_state_corrupted", "bad protocols JSON") from exc
        info = protocols.get(instance)
        if not isinstance(info, dict):
            raise PeerError("instance_not_found", f"instance {instance} not installed")
        return info

    # ----------------------------------------------------------- operation

    async def _start_operation(
        self,
        db: Database,
        operation_id: str,
        *,
        server_id: int,
        instance: str,
        client_id: str | None,
        params: dict[str, Any],
    ) -> dict[str, Any] | None:
        """Зарегистрировать операцию; существующая завершённая → вернуть её.

        Идемпотентность (FR-3.4.4): если ``operation_id`` уже завершён успешно
        (``done``) — повтор не выполняет SSH-мутацию; ``pending``/``uncertain``
        допускают ретрай.
        """
        now = _now_iso()
        existing = await db.fetch_one(
            "SELECT * FROM peer_creations WHERE operation_id = ?", (operation_id,)
        )
        if existing is None:
            await db.execute(
                "INSERT INTO peer_creations (operation_id, server_id, protocol,"
                " client_id, params_json, status, created_at, updated_at)"
                " VALUES (?, ?, ?, ?, ?, 'pending', ?, ?)",
                (
                    operation_id, server_id, instance, client_id,
                    json.dumps(params, ensure_ascii=False), now, now,
                ),
            )
            return None
        if existing["status"] == "done":
            return dict(existing)
        # pending/uncertain → обновляем и ретраим
        await db.execute(
            "UPDATE peer_creations SET status = 'pending', updated_at = ?"
            " WHERE operation_id = ?",
            (now, operation_id),
        )
        return None

    async def _finish_operation(
        self, db: Database, operation_id: str, status: str, client_id: str | None = None
    ) -> None:
        sets = "status = ?, updated_at = ?"
        params: list[Any] = [status, _now_iso()]
        if client_id is not None:
            sets += ", client_id = ?"
            params.append(client_id)
        params.append(operation_id)
        await db.execute(
            f"UPDATE peer_creations SET {sets} WHERE operation_id = ?",  # noqa: S608
            tuple(params),
        )

    # --------------------------------------------------------------- create

    async def create_peer(
        self,
        db: Database,
        *,
        server_id: int,
        instance: str,
        user_id: int,
        name: str,
        client_id: str | None = None,
        operation_id: str | None = None,
        created_source: str = "panel",
        created_by: str | None = None,
    ) -> dict[str, Any]:
        """Создать peer (FR-3.4.1, FR-3.4.3, FR-3.4.4).

        Идемпотентно по ``operation_id``; ретрай после неопределённого исхода
        безопасен (``UNIQUE(server_id, protocol, client_id)`` + повторная
        команда добавления на ноде).
        """
        op_id = operation_id or uuid.uuid4().hex
        row = await self._server_row(db, server_id)
        self._require_instance(row, instance)
        creds = credentials_from_row(row)

        # существующая операция → используем сохранённый client_id (ретрай
        # с тем же operation_id не создаёт дубликат с новым client_id)
        existing_op = await db.fetch_one(
            "SELECT * FROM peer_creations WHERE operation_id = ?", (op_id,)
        )
        if existing_op is not None and existing_op["client_id"]:
            client_id = existing_op["client_id"]
        else:
            client_id = client_id or uuid.uuid4().hex[:16]

        params = {"name": name, "user_id": user_id, "created_source": created_source}
        done = await self._start_operation(
            db, op_id,
            server_id=server_id, instance=instance, client_id=client_id,
            params=params,
        )
        if done is not None:
            # идемпотентный ретрай: операция уже завершена
            conn = await db.fetch_one(
                "SELECT * FROM user_connections WHERE server_id = ? AND protocol = ?"
                " AND client_id = ?",
                (server_id, instance, client_id),
            )
            if conn is not None:
                return dict(conn)
            raise PeerError(
                "operation_done_but_missing",
                "operation completed earlier but connection record is missing",
            )

        lock = await self.lifecycle_lock(server_id, instance)
        async with lock:
            command = _PEER_ADD_CMD.format(
                instance=instance, client_id=client_id, name_quoted=_quote(name)
            )
            try:
                result = await self._pool.call(
                    server_id, creds, command, timeout=PEER_COMMAND_TIMEOUT
                )
            except SSHError as exc:
                await self._finish_operation(db, op_id, "uncertain")
                await record_uncertain(
                    db, operation_id=op_id, server_id=server_id,
                    protocol=instance, description=f"peer add ssh error: {exc}",
                )
                raise PeerUncertainError(str(exc)) from exc

            if result.exit_code != 0:
                await self._finish_operation(db, op_id, "failed")
                raise PeerError(
                    "peer_create_failed",
                    f"node command failed (exit {result.exit_code})",
                )

            try:
                async with db.transaction() as conn_tx:
                    await conn_tx.execute(
                        "INSERT INTO user_connections (user_id, server_id, protocol,"
                        " client_id, name, created_by, created_source, created_at)"
                        " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                        (
                            user_id, server_id, instance, client_id, name,
                            created_by, created_source, _now_iso(),
                        ),
                    )
            except Exception as exc:  # noqa: BLE001
                # дубликат UNIQUE → peer уже создан ранее (напр. ретрай)
                await self._finish_operation(db, op_id, "failed")
                existing = await db.fetch_one(
                    "SELECT id FROM user_connections WHERE server_id = ?"
                    " AND protocol = ? AND client_id = ?",
                    (server_id, instance, client_id),
                )
                if existing is not None:
                    await self._finish_operation(db, op_id, "done", client_id)
                    conn = await db.fetch_one(
                        "SELECT * FROM user_connections WHERE id = ?", (existing["id"],)
                    )
                    return dict(conn) if conn else {}
                raise PeerError("peer_record_failed", "cannot record connection") from exc

            await self._finish_operation(db, op_id, "done", client_id)
            created = await db.fetch_one(
                "SELECT * FROM user_connections WHERE server_id = ? AND protocol = ?"
                " AND client_id = ?",
                (server_id, instance, client_id),
            )
            return dict(created) if created else {
                "user_id": user_id,
                "server_id": server_id,
                "protocol": instance,
                "client_id": client_id,
                "name": name,
                "created_source": created_source,
            }

    # --------------------------------------------------------------- rename

    async def rename_peer(
        self, db: Database, server_id: int, connection_id: int, *, name: str
    ) -> dict[str, Any]:
        """Переименование без гонок (FR-3.4.8): lifecycle-lock + атомарная запись."""
        conn = await db.fetch_one(
            "SELECT * FROM user_connections WHERE id = ?", (connection_id,)
        )
        if conn is None or conn["server_id"] != server_id:
            raise PeerError("connection_not_found", "connection not found")
        row = await self._server_row(db, server_id)
        self._require_instance(row, conn["protocol"])
        creds = credentials_from_row(row)

        lock = await self.lifecycle_lock(server_id, conn["protocol"])
        async with lock:
            command = _PEER_RENAME_CMD.format(
                instance=conn["protocol"], client_id=conn["client_id"],
                name_quoted=_quote(name),
            )
            try:
                result = await self._pool.call(
                    server_id, creds, command, timeout=PEER_COMMAND_TIMEOUT
                )
            except SSHError as exc:
                await record_uncertain(
                    db, operation_id=uuid.uuid4().hex, server_id=server_id,
                    protocol=conn["protocol"],
                    description=f"peer rename ssh error: {exc}",
                )
                raise PeerUncertainError(str(exc)) from exc
            if result.exit_code != 0:
                raise PeerError(
                    "peer_rename_failed",
                    f"node command failed (exit {result.exit_code})",
                )
            # атомарная запись таблицы клиентов (FR-3.4.8)
            async with db.transaction() as tx:
                await tx.execute(
                    "UPDATE user_connections SET name = ? WHERE id = ?",
                    (name, connection_id),
                )
        updated = await db.fetch_one(
            "SELECT * FROM user_connections WHERE id = ?", (connection_id,)
        )
        return dict(updated) if updated else {}

    # ------------------------------------------------------- enable/disable

    async def set_peer_enabled(
        self, db: Database, server_id: int, connection_id: int, *, enabled: bool
    ) -> dict[str, Any]:
        """Включение/отключение peer'а (FR-3.4.1)."""
        conn = await db.fetch_one(
            "SELECT * FROM user_connections WHERE id = ?", (connection_id,)
        )
        if conn is None or conn["server_id"] != server_id:
            raise PeerError("connection_not_found", "connection not found")
        row = await self._server_row(db, server_id)
        self._require_instance(row, conn["protocol"])
        creds = credentials_from_row(row)

        lock = await self.lifecycle_lock(server_id, conn["protocol"])
        async with lock:
            command = (
                _PEER_ENABLE_CMD if enabled else _PEER_DISABLE_CMD
            ).format(instance=conn["protocol"], client_id=conn["client_id"])
            try:
                result = await self._pool.call(
                    server_id, creds, command, timeout=PEER_COMMAND_TIMEOUT
                )
            except SSHError as exc:
                await record_uncertain(
                    db, operation_id=uuid.uuid4().hex, server_id=server_id,
                    protocol=conn["protocol"],
                    description=f"peer {'enable' if enabled else 'disable'} ssh error: {exc}",
                )
                raise PeerUncertainError(str(exc)) from exc
            if result.exit_code != 0:
                raise PeerError(
                    "peer_state_failed",
                    f"node command failed (exit {result.exit_code})",
                )
        return {"connection_id": connection_id, "enabled": enabled}

    # --------------------------------------------------------------- delete

    async def delete_peer(
        self,
        db: Database,
        server_id: int,
        connection_id: int,
        *,
        operation_id: str | None = None,
    ) -> dict[str, Any]:
        """Удалить peer (FR-3.4.1) с идемпотентностью по ``operation_id``."""
        op_id = operation_id or uuid.uuid4().hex
        conn = await db.fetch_one(
            "SELECT * FROM user_connections WHERE id = ?", (connection_id,)
        )
        if conn is None or conn["server_id"] != server_id:
            raise PeerError("connection_not_found", "connection not found")
        row = await self._server_row(db, server_id)
        self._require_instance(row, conn["protocol"])
        creds = credentials_from_row(row)

        done = await self._start_operation(
            db, op_id,
            server_id=server_id, instance=conn["protocol"],
            client_id=conn["client_id"], params={"action": "delete"},
        )
        if done is not None:
            return {"status": "deleted", "operation_id": op_id}

        lock = await self.lifecycle_lock(server_id, conn["protocol"])
        async with lock:
            command = _PEER_REMOVE_CMD.format(
                instance=conn["protocol"], client_id=conn["client_id"]
            )
            try:
                result = await self._pool.call(
                    server_id, creds, command, timeout=PEER_COMMAND_TIMEOUT
                )
            except SSHError as exc:
                await self._finish_operation(db, op_id, "uncertain")
                await record_uncertain(
                    db, operation_id=op_id, server_id=server_id,
                    protocol=conn["protocol"],
                    description=f"peer remove ssh error: {exc}",
                )
                raise PeerUncertainError(str(exc)) from exc
            if result.exit_code != 0:
                await self._finish_operation(db, op_id, "failed")
                raise PeerError(
                    "peer_delete_failed",
                    f"node command failed (exit {result.exit_code})",
                )
            # атомарное удаление записи подключения (+ tombstone для учёта — MVP-07)
            tombstone = {
                "server_id": server_id,
                "protocol": conn["protocol"],
                "client_id": conn["client_id"],
                "counters_json": json.loads(conn.get("counters_json") or "{}"),
                "deleted_at": _now_iso(),
            }
            async with db.transaction() as tx:
                await tx.execute(
                    "DELETE FROM user_connections WHERE id = ?", (connection_id,)
                )
                await tx.execute(
                    "INSERT INTO accounting_recoveries (connection_id, tombstone_json,"
                    " counters_verified_final, reason, created_at)"
                    " VALUES (NULL, ?, 0, 'peer_deleted', ?)",
                    (json.dumps(tombstone, ensure_ascii=False), _now_iso()),
                )
        await self._finish_operation(db, op_id, "done")
        return {"status": "deleted", "operation_id": op_id}

    # ----------------------------------------------------------- raw config

    async def raw_config(
        self, db: Database, server_id: int, connection_id: int
    ) -> str:
        """Получить raw-конфиг peer'а с ноды (под lifecycle-lock, FR-3.4.4)."""
        conn = await db.fetch_one(
            "SELECT * FROM user_connections WHERE id = ?", (connection_id,)
        )
        if conn is None or conn["server_id"] != server_id:
            raise PeerError("connection_not_found", "connection not found")
        row = await self._server_row(db, server_id)
        self._require_instance(row, conn["protocol"])
        creds = credentials_from_row(row)

        lock = await self.lifecycle_lock(server_id, conn["protocol"])
        async with lock:
            command = _PEER_CONFIG_CMD.format(
                instance=conn["protocol"], client_id=conn["client_id"]
            )
            try:
                result = await self._pool.call(
                    server_id, creds, command, timeout=PEER_COMMAND_TIMEOUT
                )
            except SSHError as exc:
                raise PeerUncertainError(str(exc)) from exc
        if result.exit_code != 0:
            raise PeerError(
                "peer_config_failed",
                f"node command failed (exit {result.exit_code})",
            )
        return result.stdout

    # ----------------------------------------------------------------- list

    async def list_peers(
        self, db: Database, *, server_id: int | None = None, user_id: int | None = None
    ) -> list[dict[str, Any]]:
        """Список подключений с фильтрами (без секретов)."""
        query = "SELECT * FROM user_connections"
        clauses, params = [], []
        if server_id is not None:
            clauses.append("server_id = ?")
            params.append(server_id)
        if user_id is not None:
            clauses.append("user_id = ?")
            params.append(user_id)
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY id"
        rows = await db.fetch_all(query, tuple(params))
        return [dict(r) for r in rows]
