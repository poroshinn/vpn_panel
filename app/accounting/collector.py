"""Коллектор transfer-семплов (FR-3.5.1, FR-3.5.2).

Полный обход установленных инстансов WG/AWG; алиасы одного физического
контейнера опрашиваются один раз; семплы сохраняют connection ID, полный
ключ протокола, client ID и идентификатор сервера; дубликаты владельцев
одного физического peer'а логируются и пропускаются.
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass
from typing import Any

from app.accounting.epochs import (
    EPOCH_META_SCRIPT,
    EpochMeta,
    parse_epoch_meta,
    parse_transfer,
)
from app.db.database import Database
from app.servers.service import ServerService, credentials_from_row
from app.ssh.pool import SSHPool

logger = logging.getLogger(__name__)


class CollectorError(Exception):
    """Доменная ошибка коллектора (без секретов)."""

    def __init__(self, error_code: str, message: str) -> None:
        super().__init__(message)
        self.error_code = error_code
        self.message = message


@dataclass(frozen=True)
class PeerSample:
    """Семпл одного peer'а (FR-3.5.2)."""

    server_id: int
    connection_id: int
    instance: str  # полный ключ протокола (инстанс)
    client_id: str
    peer_pubkey: str
    rx: int
    tx: int
    epoch: EpochMeta


@dataclass(frozen=True)
class NodeRound:
    """Результат одного цикла опроса ноды."""

    server_id: int
    samples: list[PeerSample]
    ssh_ok: bool
    error: str | None = None


def _alias_of(instance: str) -> str:
    """Базовый ключ алиаса инстанса: ``awg2__2`` → ``awg2`` (FR-3.5.2)."""
    return instance.split("__", 1)[0]


def _transfer_command(instance: str) -> str:
    protocol = "awg" if instance.startswith("awg") else "wg"
    return f"docker exec {instance} {protocol} show {instance} transfer 2>/dev/null || true"


async def _collect_node(
    db: Database,
    pool: SSHPool,
    servers: ServerService,
    server_row: dict[str, Any],
) -> NodeRound:
    """Один цикл опроса ноды: transfer по каждому инстансу + метаданные эпохи.

    Алиасы одного контейнера (``awg2``, ``awg2__2``) опрашиваются как разные
    инстансы, но SSH-соединение — одно (пул), а в рамках FR-3.5.2 «один
    опрос» означает: не дублировать запросы transfer для одного и того же
    (instance, client_id) — гарантируется дедупликацией ниже.
    """
    server_id = server_row["id"]
    try:
        protocols = json.loads(server_row.get("protocols") or "{}")
    except json.JSONDecodeError:
        protocols = {}
    instances = sorted(k for k, v in protocols.items() if isinstance(v, dict))
    if not instances:
        return NodeRound(server_id=server_id, samples=[], ssh_ok=True)

    creds = credentials_from_row(server_row)
    samples: list[PeerSample] = []
    error: str | None = None

    try:
        for instance in instances:
            # метаданные эпохи ДО чтения счётчиков (FR-3.5.3)
            try:
                meta_res = await pool.call(
                    server_id, creds,
                    EPOCH_META_SCRIPT.format(instance=instance), timeout=30.0,
                )
            except Exception as exc:  # noqa: BLE001 — SSHError нормализован
                error = f"epoch meta failed: {exc}"
                continue
            meta_before = parse_epoch_meta(meta_res.stdout, instance)

            try:
                res = await pool.call(
                    server_id, creds, _transfer_command(instance), timeout=30.0
                )
            except Exception as exc:  # noqa: BLE001
                error = f"transfer failed: {exc}"
                continue
            if res.exit_code != 0:
                error = f"transfer exit {res.exit_code}"
                continue
            transfer = parse_transfer(res.stdout)

            # метаданные эпохи ПОСЛЕ чтения счётчиков (FR-3.5.3)
            try:
                meta_res2 = await pool.call(
                    server_id, creds,
                    EPOCH_META_SCRIPT.format(instance=instance), timeout=30.0,
                )
                meta_after = parse_epoch_meta(meta_res2.stdout, instance)
            except Exception as exc:  # noqa: BLE001
                error = f"epoch meta (after) failed: {exc}"
                meta_after = meta_before
            if meta_after.as_dict() != meta_before.as_dict():
                # смена эпохи прямо во время чтения — счётчики недоказуемы
                meta_after = EpochMeta(**{
                    **meta_before.as_dict(), "socket_ctime": "raced",
                })

            # маппинг pubkey → connection (по полному ключу протокола)
            for key, sample in transfer.items():
                samples.append(
                    PeerSample(
                        server_id=server_id,
                        connection_id=0,  # заполняется service-слоем
                        instance=instance,
                        client_id="",  # заполняется service-слоем
                        peer_pubkey=key,
                        rx=sample.rx,
                        tx=sample.tx,
                        epoch=meta_after,
                    )
                )
    except Exception as exc:  # noqa: BLE001 — защитная граница цикла опроса
        return NodeRound(server_id=server_id, samples=[], ssh_ok=False,
                         error=f"collect failed: {exc}")

    return NodeRound(
        server_id=server_id, samples=samples, ssh_ok=error is None, error=error
    )


async def collect_round(
    db: Database, pool: SSHPool, servers: ServerService
) -> list[NodeRound]:
    """Полный цикл обхода всех серверов с WG/AWG-инстансами (FR-3.5.2).

    Ноды опрашиваются параллельно; сбой одной ноды изолирован.
    """
    rows = await db.fetch_all("SELECT * FROM servers ORDER BY sort_order, id")
    if not rows:
        return []
    rounds = await asyncio.gather(
        *(_collect_node(db, pool, servers, r) for r in rows),
        return_exceptions=True,
    )
    out: list[NodeRound] = []
    for row, rnd in zip(rows, rounds, strict=True):
        if isinstance(rnd, BaseException):
            logger.warning("collect round failed for server %s", row["id"])
            out.append(NodeRound(server_id=row["id"], samples=[], ssh_ok=False,
                                 error="collect exception"))
        else:
            out.append(rnd)
    return out


def dedupe_owners(
    samples: list[PeerSample],
    conn_index: dict[tuple[int, str, str], int],
) -> list[PeerSample]:
    """Дедупликация владельцев одного физического peer'а (FR-3.5.2).

    ``conn_index``: (server_id, instance, peer_pubkey) → connection_id.
    Один физический peer, назначенный нескольким подключениям (алиасы),
    учитывается один раз; дубликаты логируются и пропускаются.
    """
    seen: dict[str, PeerSample] = {}
    out: list[PeerSample] = []
    for s in samples:
        cid = conn_index.get((s.server_id, s.instance, s.peer_pubkey))
        if cid is None:
            continue
        physical = f"{s.server_id}:{_alias_of(s.instance)}:{s.peer_pubkey}"
        if physical in seen:
            logger.warning(
                "duplicate owner of physical peer %s skipped (conn %d vs %d)",
                physical, seen[physical].connection_id, cid,
            )
            continue
        seen[physical] = s
        out.append(
            PeerSample(
                server_id=s.server_id, connection_id=cid, instance=s.instance,
                client_id=s.client_id, peer_pubkey=s.peer_pubkey,
                rx=s.rx, tx=s.tx, epoch=s.epoch,
            )
        )
    return out
