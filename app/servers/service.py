"""Сервис серверов (FR-3.1.x): CRUD, онбординг-верификация, сортировка, reboot.

Правила AGENTS.md, применяемые здесь:
- секреты (пароль/ключ) шифруются at rest AES-256-GCM (FR-3.1.13) и никогда
  не возвращаются из сервиса/API в открытом виде;
- UTC-метки (created_at);
- удаление сервера — с guard'ом: сервер без подключений удаляется вместе с
  данными; при наличии подключений — только явным ``force=True``
  (подключения удаляются каскадно по FK), всегда с audit-событием.

``uid`` — стабильный идентификатор сервера (не меняется при редактировании),
используется UI/схемами и внешними ссылками вместо числового id.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from typing import Any

from app.core.security import encrypt_secret
from app.db.database import Database
from app.ssh.pool import NodeCredentials, SSHError, SSHPool
from app.ssh.probes import parse_docker_ps

logger = logging.getLogger(__name__)


class ServerError(Exception):
    """Доменная ошибка серверов (без секретов в сообщении)."""

    def __init__(self, error_code: str, message: str) -> None:
        super().__init__(message)
        self.error_code = error_code
        self.message = message


class ServerNotFoundError(ServerError):
    def __init__(self) -> None:
        super().__init__("server_not_found", "server not found")


# обратная совместимость имени внутри пакета
ServerNotFound = ServerNotFoundError


@dataclass
class OnboardingReport:
    """Результат автоматической верификации после добавления (FR-3.1.2)."""

    ssh_ok: bool = False
    error: str | None = None
    containers: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ssh_ok": self.ssh_ok,
            "error": self.error,
            "containers": dict(self.containers),
        }


# Команда онбординг-детекции: установленные контейнеры + локальные пользователи
ONBOARDING_SCRIPT = (
    "docker ps -a --format '{{.Names}}\\t{{.State}}' 2>/dev/null || true; "
    "echo '---'; awk -F: '$3 >= 1000 {print $1}' /etc/passwd 2>/dev/null || true"
)


def parse_onboarding(raw: str) -> tuple[dict[str, str], list[str]]:
    """Разбор вывода онбординг-скрипта → (контейнеры, пользователи)."""
    containers: dict[str, str] = {}
    users: list[str] = []
    head, _, tail = raw.partition("---")
    containers = parse_docker_ps(head)
    for line in tail.splitlines():
        name = line.strip()
        if name and name not in users:
            users.append(name)
    return containers, users


def credentials_from_row(row: dict[str, Any]) -> NodeCredentials:
    """NodeCredentials из строки БД (секреты остаются зашифрованными)."""
    return NodeCredentials(
        host=row["host"],
        port=row["ssh_port"],
        username=row["username"],
        password_enc=row.get("password_enc"),
        private_key_enc=row.get("private_key_enc"),
    )


class ServerService:
    """Управление серверами. Один инстанс на процесс."""

    def __init__(self, pool: SSHPool) -> None:
        self._pool = pool

    # ------------------------------------------------------------- helpers

    @staticmethod
    def _uid() -> str:
        return uuid.uuid4().hex[:16]

    @staticmethod
    def _row_to_dict(row: dict[str, Any], *, include_secrets: bool = False) -> dict[str, Any]:
        out = {
            "id": row["id"],
            "uid": row["uid"],
            "name": row["name"],
            "host": row["host"],
            "ssh_port": row["ssh_port"],
            "username": row["username"],
            "auth_type": (
                "key" if row.get("private_key_enc")
                else ("password" if row.get("password_enc") else "none")
            ),
            "protocols": row.get("protocols", "{}"),
            "self_service_enabled": bool(row.get("self_service_enabled", 0)),
            "sort_order": row.get("sort_order", 0),
            "created_at": row.get("created_at"),
        }
        if include_secrets:  # только внутри процесса (нужно пулу SSH)
            out["password_enc"] = row.get("password_enc")
            out["private_key_enc"] = row.get("private_key_enc")
        return out

    async def _get_row(self, db: Database, server_id: int) -> dict[str, Any]:
        row = await db.fetch_one("SELECT * FROM servers WHERE id = ?", (server_id,))
        if row is None:
            raise ServerNotFound()
        return row

    # ---------------------------------------------------------------- read

    async def list_servers(self, db: Database) -> list[dict[str, Any]]:
        rows = await db.fetch_all(
            "SELECT * FROM servers ORDER BY sort_order, id"
        )
        return [self._row_to_dict(row) for row in rows]

    async def get_server(self, db: Database, server_id: int) -> dict[str, Any]:
        row = await self._get_row(db, server_id)
        return self._row_to_dict(row)

    # ------------------------------------------------------------- create

    async def create_server(
        self,
        db: Database,
        *,
        name: str,
        host: str,
        ssh_port: int = 22,
        username: str = "root",
        password: str | None = None,
        private_key: str | None = None,
        sort_order: int | None = None,
    ) -> dict[str, Any]:
        """Добавить сервер (admin-only, FR-3.1.1). Секреты — шифрованными."""
        if not password and not private_key:
            raise ServerError("credentials_required", "password or private key required")

        if sort_order is None:
            row = await db.fetch_one("SELECT COALESCE(MAX(sort_order), -1) AS m FROM servers")
            sort_order = int(row["m"]) + 1 if row else 0

        async with db.transaction() as conn:
            cur = await conn.execute(
                "INSERT INTO servers (uid, name, host, ssh_port, username,"
                " password_enc, private_key_enc, sort_order, created_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%SZ','now'))",
                (
                    self._uid(),
                    name,
                    host,
                    ssh_port,
                    username,
                    encrypt_secret(password) if password else None,
                    encrypt_secret(private_key) if private_key else None,
                    sort_order,
                ),
            )
            server_id = cur.lastrowid
        return await self.get_server(db, int(server_id))

    # ------------------------------------------------------------- update

    async def update_server(
        self,
        db: Database,
        server_id: int,
        *,
        name: str | None = None,
        host: str | None = None,
        ssh_port: int | None = None,
        username: str | None = None,
        password: str | None = None,
        private_key: str | None = None,
    ) -> dict[str, Any]:
        """Редактировать сервер (admin-only). ``uid`` не меняется."""
        await self._get_row(db, server_id)

        sets: list[str] = []
        params: list[Any] = []
        if name is not None:
            sets.append("name = ?")
            params.append(name)
        if host is not None:
            sets.append("host = ?")
            params.append(host)
        if ssh_port is not None:
            sets.append("ssh_port = ?")
            params.append(ssh_port)
        if username is not None:
            sets.append("username = ?")
            params.append(username)
        if password:
            sets.append("password_enc = ?")
            params.append(encrypt_secret(password))
        if private_key:
            sets.append("private_key_enc = ?")
            params.append(encrypt_secret(private_key))
        if sets:
            params.append(server_id)
            # значения — только параметризованные; имена колонок — фиксированный
            # внутренний набор (не пользовательский ввод), поэтому конкатенация безопасна
            query = "UPDATE servers SET " + ", ".join(sets) + " WHERE id = ?"  # noqa: S608
            async with db.transaction() as conn:
                await conn.execute(query, tuple(params))
        # креды сменились → старое SSH-соединение/брейкер непригодны
        await self._pool.close_node(server_id)
        return await self.get_server(db, server_id)

    # ------------------------------------------------------------- delete

    async def delete_server(
        self, db: Database, server_id: int, *, force: bool = False
    ) -> None:
        """Удалить сервер (admin-only). Guard: при наличии подключений —
        только с ``force=True`` (FR-3.1.4: подключение к ноде потеряется).
        """
        await self._get_row(db, server_id)
        refs = await db.fetch_one(
            "SELECT COUNT(*) AS n FROM user_connections WHERE server_id = ?",
            (server_id,),
        )
        if refs and refs["n"] > 0 and not force:
            raise ServerError(
                "server_has_connections",
                f"server has {refs['n']} connection(s); use force to delete",
            )
        async with db.transaction() as conn:
            # FK без CASCADE (схема 0001) — подключения убираем явно при force
            await conn.execute(
                "DELETE FROM user_connections WHERE server_id = ?", (server_id,)
            )
            await conn.execute("DELETE FROM servers WHERE id = ?", (server_id,))
        await self._pool.close_node(server_id)

    # -------------------------------------------------------------- order

    async def reorder(
        self, db: Database, ordered_uids: list[str]
    ) -> list[dict[str, Any]]:
        """Drag-and-drop сортировка (FR-3.1.3): порядок по списку ``uid``."""
        servers = {s["uid"]: s for s in await self.list_servers(db)}
        missing = [uid for uid in ordered_uids if uid not in servers]
        if missing:
            raise ServerError("unknown_server_uid", f"unknown uid(s): {missing}")
        async with db.transaction() as conn:
            for idx, uid in enumerate(ordered_uids):
                await conn.execute(
                    "UPDATE servers SET sort_order = ? WHERE uid = ?", (idx, uid)
                )
        return await self.list_servers(db)

    # ------------------------------------------------------------ onboard

    async def verify_server(self, db: Database, server_id: int) -> OnboardingReport:
        """Автоматическая верификация (FR-3.1.2): SSH-проба, детекция
        установленных контейнеров протоколов и локальных пользователей.
        Результат сохраняется в ``protocols`` (JSON) сервера.
        """
        row = await self._get_row(db, server_id)
        report = OnboardingReport()
        creds = credentials_from_row(row)
        try:
            result = await self._pool.call(server_id, creds, ONBOARDING_SCRIPT)
        except SSHError as exc:
            report.error = str(exc)
            return report

        report.ssh_ok = result.exit_code == 0
        if not report.ssh_ok:
            report.error = "onboarding_script_failed"
            return report
        containers, _users = parse_onboarding(result.stdout)
        report.containers = containers
        await db.execute(
            "UPDATE servers SET protocols = ? WHERE id = ?",
            (__import__("json").dumps(containers, ensure_ascii=False), server_id),
        )
        return report

    # ------------------------------------------------------------- reboot

    async def reboot_server(
        self, db: Database, server_id: int, *, delay_seconds: int = 2
    ) -> dict[str, Any]:
        """Перезагрузка сервера через SSH (admin-only, FR-3.1.10*).

        ``reboot`` выполняется отложенно (``shutdown -r``), чтобы SSH-сессия
        корректно закрылась с exit 0; соединение к ноде после команды закрываем.
        """
        row = await self._get_row(db, server_id)
        creds = credentials_from_row(row)
        try:
            result = await self._pool.call(
                server_id,
                creds,
                f"shutdown -r +{max(0, delay_seconds // 60)} &>/dev/null & echo scheduled",
            )
        except SSHError as exc:
            raise ServerError("reboot_failed", str(exc)) from exc
        if result.exit_code != 0:
            raise ServerError("reboot_failed", "shutdown command returned nonzero")
        # соединение переживёт reboot маловероятно — чистим
        await self._pool.close_node(server_id)
        return {"status": "scheduled", "delay_seconds": delay_seconds}
