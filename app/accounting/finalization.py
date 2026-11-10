"""Финализация linked-peer'ов (FR-3.11.4).

Чтение финального счётчика с удалённого peer'а, коммит дельты, tombstone в
``accounting_recoveries``; нечитаемый счётчик ⇒ fail-closed 409 с ``can_force``
и ретраем ``allow_unverified`` (правило 5 AGENTS.md: никаких обнулений
«для успеха»).
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from typing import Any

from app.accounting.epochs import EPOCH_META_SCRIPT, parse_epoch_meta, parse_transfer
from app.db.database import Database
from app.servers.service import ServerService, credentials_from_row
from app.ssh.pool import SSHPool

logger = logging.getLogger(__name__)

FINALIZE_COMMAND_TIMEOUT = 30.0


class FinalizationError(Exception):
    """Доменная ошибка финализации (без секретов)."""

    def __init__(self, error_code: str, message: str, *, can_force: bool = False) -> None:
        super().__init__(message)
        self.error_code = error_code
        self.message = message
        self.can_force = can_force


def _now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


class FinalizationService:
    """Финализация peer'а перед удалением. Один инстанс на процесс."""

    def __init__(self, pool: SSHPool, servers: ServerService) -> None:
        self._pool = pool
        self._servers = servers

    async def finalize_peer(
        self,
        db: Database,
        server_id: int,
        connection_id: int,
        *,
        allow_unverified: bool = False,
    ) -> dict[str, Any]:
        """Прочитать финальный счётчик, закоммитить дельту, оставить tombstone.

        Возвращает итог финализации. Нечитаемый счётчик (SSH-сбой, exit != 0,
        pubkey не найден в transfer) ⇒ :class:`FinalizationError` с
        ``error_code='counter_unreadable'``, ``can_force=True``; повторный
        вызов с ``allow_unverified=True`` коммитит tombstone без дельты,
        ``counters_verified_final=0``.
        """
        conn = await db.fetch_one(
            "SELECT * FROM user_connections WHERE id = ?", (connection_id,)
        )
        if conn is None or conn["server_id"] != server_id:
            raise FinalizationError("connection_not_found", "connection not found")

        server = await self._servers._get_row(db, server_id)  # noqa: SLF001
        creds = credentials_from_row(server)

        try:
            meta_res = await self._pool.call(
                server_id, creds,
                EPOCH_META_SCRIPT.format(instance=conn["protocol"]),
                timeout=FINALIZE_COMMAND_TIMEOUT,
            )
            transfer_res = await self._pool.call(
                server_id, creds,
                _transfer_cmd(conn["protocol"]), timeout=FINALIZE_COMMAND_TIMEOUT,
            )
        except Exception as exc:  # noqa: BLE001 — SSHError нормализован
            if allow_unverified:
                return await self._tombstone_unverified(db, conn, f"ssh error: {exc}")
            raise FinalizationError(
                "counter_unreadable", "cannot read final counter", can_force=True
            ) from exc

        if transfer_res.exit_code != 0:
            if allow_unverified:
                return await self._tombstone_unverified(
                    db, conn, f"transfer exit {transfer_res.exit_code}"
                )
            raise FinalizationError(
                "counter_unreadable", "cannot read final counter", can_force=True
            )

        samples = parse_transfer(transfer_res.stdout)
        try:
            counters = json.loads(conn.get("counters_json") or "{}")
        except json.JSONDecodeError:
            counters = {}
        pubkey = str(counters.get("pubkey", ""))
        sample = samples.get(pubkey) if pubkey else None

        if sample is None:
            if allow_unverified:
                return await self._tombstone_unverified(
                    db, conn, "peer key not found in transfer output"
                )
            raise FinalizationError(
                "counter_unreadable", "peer not present in transfer output",
                can_force=True,
            )

        # коммит дельты: полные текущие значения = lifetime + (raw - base)
        base_rx = conn.get("rx_base", 0) or 0
        base_tx = conn.get("tx_base", 0) or 0
        delta = max(0, sample.rx - base_rx) + max(0, sample.tx - base_tx)
        lifetime_rx = (conn.get("lifetime_rx", 0) or 0) + max(0, sample.rx - base_rx)
        lifetime_tx = (conn.get("lifetime_tx", 0) or 0) + max(0, sample.tx - base_tx)
        meta = parse_epoch_meta(meta_res.stdout, conn["protocol"])

        tombstone = {
            "server_id": server_id,
            "protocol": conn["protocol"],
            "client_id": conn["client_id"],
            "final_rx": sample.rx,
            "final_tx": sample.tx,
            "lifetime_rx": lifetime_rx,
            "lifetime_tx": lifetime_tx,
            "epoch_hash_meta": meta.as_dict(),
            "finalized_by": "finalization_service",
            "deleted_at": _now_iso(),
        }
        now = _now_iso()
        async with db.transaction() as tx:
            await tx.execute(
                "UPDATE users SET traffic_used = traffic_used + ? WHERE id = ?",
                (delta, conn["user_id"]),
            )
            await tx.execute(
                "DELETE FROM user_connections WHERE id = ?", (connection_id,)
            )
            await tx.execute(
                "INSERT INTO accounting_recoveries (connection_id, tombstone_json,"
                " counters_verified_final, reason, created_at)"
                " VALUES (?, ?, 1, 'finalized', ?)",
                (connection_id, json.dumps(tombstone, ensure_ascii=False), now),
            )
        logger.info(
            "peer %s finalized (delta %d bytes, verified)", connection_id, delta
        )
        return {
            "status": "finalized",
            "connection_id": connection_id,
            "counters_verified_final": True,
            "delta_bytes": delta,
            "lifetime_rx": lifetime_rx,
            "lifetime_tx": lifetime_tx,
        }

    async def _tombstone_unverified(
        self, db: Database, conn: dict[str, Any], reason: str
    ) -> dict[str, Any]:
        """Tombstone без дельты (``allow_unverified``): счётчик недоказан."""
        tombstone = {
            "server_id": conn["server_id"],
            "protocol": conn["protocol"],
            "client_id": conn["client_id"],
            "lifetime_rx": conn.get("lifetime_rx", 0) or 0,
            "lifetime_tx": conn.get("lifetime_tx", 0) or 0,
            "unverified_reason": reason,
            "deleted_at": _now_iso(),
        }
        async with db.transaction() as tx:
            await tx.execute(
                "DELETE FROM user_connections WHERE id = ?", (conn["id"],)
            )
            await tx.execute(
                "INSERT INTO accounting_recoveries (connection_id, tombstone_json,"
                " counters_verified_final, reason, created_at)"
                " VALUES (?, ?, 0, 'finalized_unverified', ?)",
                (
                    conn["id"], json.dumps(tombstone, ensure_ascii=False), _now_iso(),
                ),
            )
        logger.warning(
            "peer %s finalized UNVERIFIED (%s) — delta not committed",
            conn["id"], reason,
        )
        return {
            "status": "finalized_unverified",
            "connection_id": conn["id"],
            "counters_verified_final": False,
            "unverified_reason": reason,
        }


def _transfer_cmd(instance: str) -> str:
    protocol = "awg" if instance.startswith("awg") else "wg"
    return f"docker exec {instance} {protocol} show {instance} transfer 2>/dev/null"
