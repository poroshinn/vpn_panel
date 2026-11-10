"""Accounting-сервис (FR-3.5.4, FR-3.5.5): базлайны, дельты, квоты, сброс.

Fail-closed (правило 5 AGENTS.md): недоказанные счётчики помечаются
``counters_verified_final=false``; смена эпохи/сброс счётчика фиксируется
диагностикой ``traffic_accounting_gap`` и НЕ обнуляет итоги.

Ключевые свойства:
- базлайны и lifetime-итоги переживают перезапуск панели (в БД);
- календарный сброс квот — UTC, сырые базлайны сохраняются;
- недоступность SSH в неизменной эпохе — догон при следующем успешном чтении
  (базлайн не трогается, дельта не пропадает);
- квота: исчерпание ⇒ автоотключение (``disable_reasons`` += ``quota``),
  применение ≤ 2 интервалов опроса (контроль в конце каждого цикла);
- access reconciliation при смене статусов.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import UTC, datetime
from typing import Any

from app.accounting.collector import (
    NodeRound,
    PeerSample,
    collect_round,
    dedupe_owners,
)
from app.accounting.epochs import epochs_differ
from app.db.database import Database
from app.protocols.peers import PeerError, PeerService
from app.servers.service import ServerService
from app.ssh.pool import SSHPool

logger = logging.getLogger(__name__)

# интервал опроса по умолчанию (сек) — настройка 30–300 (FR-3.5.5)
POLL_INTERVAL_DEFAULT = 60
POLL_INTERVAL_MIN = 30
POLL_INTERVAL_MAX = 300


class AccountingService:
    """Фоновая задача учёта. Один инстанс на процесс."""

    def __init__(
        self,
        db: Database,
        pool: SSHPool,
        servers: ServerService,
        peers: PeerService,
        *,
        poll_interval: int = POLL_INTERVAL_DEFAULT,
    ) -> None:
        self._db = db
        self._pool = pool
        self._servers = servers
        self._peers = peers
        self.poll_interval = max(
            POLL_INTERVAL_MIN, min(POLL_INTERVAL_MAX, poll_interval)
        )
        self._task: asyncio.Task | None = None
        self._stopping = asyncio.Event()
        # сериализация коммита семплов (правило 1: один writer)
        self._commit_lock = asyncio.Lock()

    # ----------------------------------------------------------- lifecycle

    def start(self) -> None:
        if self._task is None or self._task.done():
            self._stopping = asyncio.Event()
            self._task = asyncio.create_task(self._run(), name="accounting-collector")

    async def stop(self) -> None:
        self._stopping.set()
        if self._task is not None:
            try:
                await asyncio.wait_for(self._task, timeout=10.0)
            except (TimeoutError, asyncio.CancelledError):
                self._task.cancel()
            self._task = None

    async def _run(self) -> None:
        """Фоновый цикл: опрос → коммит → проверка квот (FR-3.5.5)."""
        while not self._stopping.is_set():
            try:
                await self.tick()
            except Exception:  # noqa: BLE001 — цикл обязан пережить любой сбой
                logger.exception("accounting tick failed")
            try:
                await asyncio.wait_for(
                    self._stopping.wait(), timeout=self.poll_interval
                )
            except TimeoutError:
                pass

    # ------------------------------------------------------------ tick

    async def tick(self) -> dict[str, Any]:
        """Один цикл: обход инстансов, коммит дельт, применение квот."""
        rounds = await collect_round(self._db, self._pool, self._servers)
        processed = 0
        for rnd in rounds:
            if rnd.ssh_ok or rnd.samples:
                processed += await self._process_round(rnd)
        await self._apply_quotas()
        return {"nodes": len(rounds), "samples": processed}

    # -------------------------------------------------------- processing

    async def _conn_index(self, server_id: int) -> dict[tuple[str, str], dict[str, Any]]:
        rows = await self._db.fetch_all(
            "SELECT * FROM user_connections WHERE server_id = ?", (server_id,)
        )
        return {
            (r["protocol"], r["client_id"]): dict(r) for r in rows
        }

    async def _process_round(self, rnd: NodeRound) -> int:
        rows = await self._db.fetch_all(
            "SELECT * FROM user_connections WHERE server_id = ?", (rnd.server_id,)
        )
        # pubkey маппим по полному ключу протокола (instance)
        index: dict[tuple[int, str, str], int] = {}
        cid_by_row: dict[int, dict[str, Any]] = {}
        for r in rows:
            pubkey = self._pubkey_of(r)
            index[(rnd.server_id, r["protocol"], pubkey)] = r["id"]
            cid_by_row[r["id"]] = r

        deduped = dedupe_owners(
            [
                PeerSample(
                    server_id=s.server_id, connection_id=0, instance=s.instance,
                    client_id="", peer_pubkey=s.peer_pubkey,
                    rx=s.rx, tx=s.tx, epoch=s.epoch,
                )
                for s in rnd.samples
            ],
            index,
        )
        # восстановим client_id из строк БД
        samples: list[PeerSample] = []
        for s in deduped:
            row = cid_by_row.get(s.connection_id)
            if row is None:
                continue
            samples.append(
                PeerSample(
                    server_id=s.server_id, connection_id=s.connection_id,
                    instance=s.instance, client_id=row["client_id"],
                    peer_pubkey=s.peer_pubkey, rx=s.rx, tx=s.tx, epoch=s.epoch,
                )
            )

        now_iso = datetime.now(UTC).isoformat(timespec="seconds")
        async with self._commit_lock:
            for s in samples:
                row = cid_by_row[s.connection_id]
                await self._commit_sample(row, s, now_iso)
        return len(samples)

    @staticmethod
    def _pubkey_of(row: dict[str, Any]) -> str:
        """Pubkey peer'а, сохранённый при создании (counters_json.pubkey).

        Отсутствие ключа = peer ещё не опрошен; такой peer не матчится
        с transfer-семплами до первого сопоставления.
        """
        try:
            counters = json.loads(row.get("counters_json") or "{}")
        except json.JSONDecodeError:
            return ""
        return str(counters.get("pubkey", ""))

    async def _commit_sample(
        self, row: dict[str, Any], s: PeerSample, now_iso: str
    ) -> None:
        """Коммит одного семпла: дельта или gap (fail-closed, FR-3.5.3/3.5.4)."""
        try:
            counters = json.loads(row.get("counters_json") or "{}")
        except json.JSONDecodeError:
            counters = {}

        prev_epoch = row.get("epoch_hash")
        new_epoch = s.epoch
        verified = True
        gap_reason: str | None = None

        if prev_epoch:
            try:
                prev_meta = json.loads(prev_epoch)
            except json.JSONDecodeError:
                prev_meta = {}
            # смена эпохи между семплами → gap
            if epochs_differ(
                _meta_from_stored(prev_meta), _meta_from_stored(new_epoch.as_dict())
            ):
                verified = False
                gap_reason = "epoch_changed"
        if not prev_epoch:
            # первый семпл — базлайн устанавливается, дельта не считается
            pass

        # сброс счётчика на неизменной эпохе (FR-3.5.3)
        base_rx, base_tx = row.get("rx_base", 0) or 0, row.get("tx_base", 0) or 0
        if verified and base_rx and (s.rx < base_rx or s.tx < base_tx):
            verified = False
            gap_reason = "counter_reset"

        if verified and prev_epoch:
            delta_rx = s.rx - base_rx
            delta_tx = s.tx - base_tx
        else:
            delta_rx, delta_tx = 0, 0

        lifetime_rx = (row.get("lifetime_rx", 0) or 0) + max(0, delta_rx)
        lifetime_tx = (row.get("lifetime_tx", 0) or 0) + max(0, delta_tx)

        counters["pubkey"] = s.peer_pubkey
        counters["last_raw_rx"] = s.rx
        counters["last_raw_tx"] = s.tx
        if gap_reason:
            counters["last_gap"] = {
                "reason": gap_reason, "at": now_iso,
                "raw_rx": s.rx, "raw_tx": s.tx,
            }

        async with self._db.transaction() as tx:
            await tx.execute(
                "UPDATE user_connections SET rx_base = ?, tx_base = ?,"
                " lifetime_rx = ?, lifetime_tx = ?, epoch_hash = ?,"
                " last_sample_at = ?, counters_json = ?,"
                " counters_verified_final = ? WHERE id = ?",
                (
                    s.rx, s.tx, lifetime_rx, lifetime_tx,
                    json.dumps(new_epoch.as_dict(), ensure_ascii=False),
                    now_iso, json.dumps(counters, ensure_ascii=False),
                    1 if verified else 0, row["id"],
                ),
            )
            if not verified:
                await tx.execute(
                    "INSERT INTO accounting_recoveries (connection_id,"
                    " tombstone_json, counters_verified_final, reason, created_at)"
                    " VALUES (?, ?, 0, 'traffic_accounting_gap', ?)",
                    (
                        row["id"],
                        json.dumps(
                            {
                                "gap": gap_reason,
                                "raw_rx": s.rx, "raw_tx": s.tx,
                                "epoch": new_epoch.as_dict(),
                            },
                            ensure_ascii=False,
                        ),
                        now_iso,
                    ),
                )
            # синхронизация traffic_used пользователя (сумма lifetime)
            if delta_rx or delta_tx:
                await tx.execute(
                    "UPDATE users SET traffic_used = traffic_used + ?"
                    " WHERE id = ?",
                    (delta_rx + delta_tx, row["user_id"]),
                )

    # -------------------------------------------------------------- квоты

    async def _apply_quotas(self) -> None:
        """Проверка квот/expiration, автоотключение при исчерпании (FR-3.5.5)."""
        users = await self._db.fetch_all("SELECT * FROM users")
        for user in users:
            reasons = _parse_reasons(user.get("disable_reasons"))
            changed = False

            # expiration (UTC)
            if user.get("expiration"):
                try:
                    exp = datetime.fromisoformat(str(user["expiration"]))
                    if exp.tzinfo is None:
                        exp = exp.replace(tzinfo=UTC)
                    if exp <= datetime.now(UTC) and "expiration" not in reasons:
                        reasons.append("expiration")
                        changed = True
                except ValueError:
                    pass

            # квота (traffic_limit = 0/NULL — без лимита)
            limit = user.get("traffic_limit")
            if limit is not None and int(limit) > 0:
                if (user.get("traffic_used", 0) or 0) >= int(limit):
                    if "quota" not in reasons:
                        reasons.append("quota")
                        changed = True
                elif "quota" in reasons:
                    # лимит поднят — причина исчерпана, ручное включение не нужно
                    reasons.remove("quota")
                    changed = True

            if changed:
                await self._db.execute(
                    "UPDATE users SET disable_reasons = ?, enabled = ? WHERE id = ?",
                    (json.dumps(reasons), 0 if reasons else 1, user["id"]),
                )
                await self._reconcile_access(user["id"])

    async def _reconcile_access(self, user_id: int) -> None:
        """Access reconciliation: включение/отключение peer'ов по статусу (FR-3.5.5)."""
        user = await self._db.fetch_one("SELECT * FROM users WHERE id = ?", (user_id,))
        if user is None:
            return
        disabled = not bool(user["enabled"]) or _parse_reasons(
            user.get("disable_reasons")
        )
        conns = await self._db.fetch_all(
            "SELECT * FROM user_connections WHERE user_id = ?", (user_id,)
        )
        for conn in conns:
            try:
                await self._peers.set_peer_enabled(
                    self._db, conn["server_id"], conn["id"], enabled=not disabled
                )
            except PeerError as exc:
                logger.warning(
                    "reconcile failed for connection %s: %s", conn["id"], exc.message
                )

    # ------------------------------------------------------ календарный сброс

    async def monthly_reset(self, now: datetime | None = None) -> int:
        """Календарный сброс квот (FR-3.5.4): UTC, сырые базлайны сохраняются.

        Вызывается лениво в начале ``tick`` (и вручную из API). Месяц
        определяется по UTC-времени; сброс обнуляет ``users.traffic_used``,
        но не трогает базлайны/lifetime peer'ов.
        """
        now = now or datetime.now(UTC)
        month = now.strftime("%Y-%m")
        users = await self._db.fetch_all(
            "SELECT id, traffic_reset_month FROM users"
        )
        reset = 0
        for user in users:
            if user.get("traffic_reset_month") == month:
                continue
            await self._db.execute(
                "UPDATE users SET traffic_used = 0, traffic_reset_month = ?"
                " WHERE id = ?",
                (month, user["id"]),
            )
            reset += 1
        return reset

    # ------------------------------------------------------------ API-данные

    async def user_accounting(self, db: Database, user_id: int) -> dict[str, Any]:
        """Сводка учёта пользователя (числа для UI, MVP-08)."""
        user = await db.fetch_one("SELECT * FROM users WHERE id = ?", (user_id,))
        if user is None:
            raise KeyError("user not found")
        conns = await db.fetch_all(
            "SELECT id, server_id, protocol, client_id, name, lifetime_rx,"
            " lifetime_tx, last_sample_at, counters_verified_final"
            " FROM user_connections WHERE user_id = ? ORDER BY id",
            (user_id,),
        )
        return {
            "traffic_used": user.get("traffic_used", 0) or 0,
            "traffic_total": user.get("traffic_total"),
            "traffic_limit": user.get("traffic_limit"),
            "expiration": user.get("expiration"),
            "disable_reasons": _parse_reasons(user.get("disable_reasons")),
            "connections": [
                {
                    "id": c["id"],
                    "server_id": c["server_id"],
                    "protocol": c["protocol"],
                    "client_id": c["client_id"],
                    "name": c["name"],
                    "lifetime_rx": c["lifetime_rx"],
                    "lifetime_tx": c["lifetime_tx"],
                    "last_sample_at": c["last_sample_at"],
                    "counters_verified_final": bool(c["counters_verified_final"]),
                }
                for c in conns
            ],
        }

    async def set_traffic_limit(
        self, db: Database, user_id: int, *, limit: int | None
    ) -> dict[str, Any]:
        """Установить/снять квоту пользователя (admin, FR-3.5.5)."""
        if limit is not None and limit < 0:
            raise ValueError("limit must be >= 0")
        await db.execute(
            "UPDATE users SET traffic_limit = ? WHERE id = ?", (limit, user_id)
        )
        await self._apply_quotas()
        user = await db.fetch_one(
            "SELECT traffic_used, traffic_limit FROM users WHERE id = ?", (user_id,)
        )
        return dict(user) if user else {}


def _meta_from_stored(data: dict[str, Any]):
    from app.accounting.epochs import EpochMeta

    return EpochMeta.from_mapping(data)


def _parse_reasons(raw: Any) -> list[str]:
    try:
        data = json.loads(raw or "[]")
        return [str(x) for x in data] if isinstance(data, list) else []
    except json.JSONDecodeError:
        return []
