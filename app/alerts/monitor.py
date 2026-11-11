"""Фоновый монитор наблюдаемости (FR-3.10.13, FR-3.16.1).

Раз в минуту:
- ping всех серверов → ``alert_server_down`` (N минут недоступен);
- диск → алерт при < критического порога, read-only при < аварийного
  (FR-3.15.7);
- SSL-сертификат панели → алерт ≤ 14 дней;
- сводка ``traffic_accounting_gap`` за последний час → алерт ≤ 1 раз/час.

Цикл переживает любой сбой; алерты не бросают исключений.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime
from typing import Any

from app.alerts.service import alert_server_down, alert_ssl_expiry, probe_host_tcp
from app.core.disk_guard import check_disk
from app.db.database import Database
from app.servers.service import ServerService

logger = logging.getLogger(__name__)

MONITOR_INTERVAL = 60.0


class ObservabilityMonitor:
    """Фоновая задача наблюдаемости. Один инстанс на процесс."""

    def __init__(
        self,
        db: Database,
        servers: ServerService,
        *,
        interval: float = MONITOR_INTERVAL,
    ) -> None:
        self._db = db
        self._servers = servers
        self._interval = interval
        self._task: asyncio.Task | None = None
        self._stopping = asyncio.Event()
        self.last_tick: dict[str, Any] | None = None

    def start(self) -> None:
        if self._task is None or self._task.done():
            self._stopping = asyncio.Event()
            self._task = asyncio.create_task(self._run(), name="observability-monitor")

    async def stop(self) -> None:
        self._stopping.set()
        if self._task is not None:
            try:
                await asyncio.wait_for(self._task, timeout=5.0)
            except (TimeoutError, asyncio.CancelledError):
                self._task.cancel()
            self._task = None

    async def _run(self) -> None:
        while not self._stopping.is_set():
            try:
                self.last_tick = await self.tick()
            except Exception:  # noqa: BLE001 — цикл обязан пережить любой сбой
                logger.exception("observability tick failed")
            try:
                await asyncio.wait_for(
                    self._stopping.wait(), timeout=self._interval
                )
            except TimeoutError:
                pass

    async def tick(self) -> dict[str, Any]:
        """Один цикл наблюдаемости."""
        # 1) серверы
        reachable: dict[int, bool] = {}
        try:
            servers = await self._servers.list_servers(self._db)
        except Exception:  # noqa: BLE001
            servers = []
        for server in servers:
            ok = await probe_host_tcp(server["host"], int(server["ssh_port"]))
            reachable[server["id"]] = ok
            await alert_server_down(self._db, server["id"], server["name"],
                                    reachable=ok)

        # 2) диск (FR-3.15.7)
        disk = await check_disk()

        # 3) SSL (FR-3.10.13)
        await alert_ssl_expiry(self._db)

        # 4) gap-сводка (≤ 1 раз/час — дедупликация в raise_alert)
        await self._alert_gap_summary()

        return {
            "at": datetime.now(UTC).isoformat(timespec="seconds"),
            "servers": {str(k): v for k, v in reachable.items()},
            "disk_free_mb": disk.free_mb,
            "disk_read_only": disk.read_only,
        }

    async def _alert_gap_summary(self) -> None:
        """Сводка gap'ов за последний час (только при включённом тумблере)."""
        from app.alerts.service import alert_accounting_gap, get_alert_config

        config = await get_alert_config(self._db)  # noqa: F811 — локальный импорт
        if not config.toggles.get("accounting_gap"):
            return
        cutoff = datetime.now(UTC).isoformat(timespec="seconds")
        row = await self._db.fetch_one(
            "SELECT COUNT(*) AS n FROM accounting_recoveries "
            "WHERE reason = 'traffic_accounting_gap' AND created_at >= ?",
            (cutoff[:11] + "00:00:00",),
        )
        count = int(row["n"]) if row else 0
        if count:
            await alert_accounting_gap(self._db, count)


def settings_or_default_free_mb() -> int:
    """Свободное место на разделе данных (MiB) — для /system/status."""
    from app.core.disk_guard import last_state

    state = last_state()
    return state.free_mb if state else -1
