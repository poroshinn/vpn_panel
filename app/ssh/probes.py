"""Пробы нод (FR-3.1.9, FR-3.1.11, FR-3.1.13): TCP-ping, статусы протоколов,
статистика хоста.

Все пробы — неблокирующие (TCP — чистый asyncio, SSH — через пул) и
выполняются параллельно по всем серверам. Частичный сбой пробы не роняет
остальные данные (fail-closed частично: недоказанные поля помечаются).
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from typing import Any

from app.ssh.pool import (
    NodeCredentials,
    SSHPool,
    tcp_ping,
)

logger = logging.getLogger(__name__)

# Единый bash-скрипт статистики хоста (FR-3.1.13): CPU, память, диск, load.
# Вывод — строго JSON (jq может отсутствовать, поэтому ключи формируем printf).
HOST_STATS_SCRIPT = r"""(
printf '{"cpu_percent":'; \
top -bn1 | grep -E '^%?Cpu' | head -n1 | \
awk '{for(i=1;i<=NF;i++) if($i ~ /^[0-9.]+$/){print $(i); exit}}' | tr -d '\n'
printf ',"load_1m":'; cut -d' ' -f1 /proc/loadavg | tr -d '\n'
printf ',"load_5m":'; cut -d' ' -f2 /proc/loadavg | tr -d '\n'
printf ',"load_15m":'; cut -d' ' -f3 /proc/loadavg | tr -d '\n'
printf ',"mem_total_kb":'; awk '/MemTotal/{print $2}' /proc/meminfo | tr -d '\n'
printf ',"mem_available_kb":'; awk '/MemAvailable/{print $2}' /proc/meminfo | tr -d '\n'
printf ',"disk_total_bytes":'; df -P / | awk 'NR==2{print $2}' | tr -d '\n'
printf ',"disk_used_bytes":'; df -P / | awk 'NR==2{print $3}' | tr -d '\n'
printf ',"disk_percent":'; df -P / | awk 'NR==2{gsub("%",""); print $5}' | tr -d '\n'
printf ',"uptime_s":'; awk '{print int($1)}' /proc/uptime | tr -d '\n'
printf '}'
) 2>/dev/null"""

# Статусы docker-контейнеров протоколов (FR-3.1.11)
DOCKER_PS_TEMPLATE = (
    "docker ps -a --format '{{{{.Names}}}}\\t{{{{.State}}}}\\t{{{{.Status}}}}' "
    "--filter name={prefix!r} 2>/dev/null || true"
)


@dataclass
class NodeProbeResult:
    """Результат пробы одной ноды: частичные данные допустимы."""

    node_id: int
    reachable: bool = False
    rtt_ms: float | None = None
    error: str | None = None
    protocols: dict[str, str] = field(default_factory=dict)  # инстанс -> состояние
    stats: dict[str, Any] = field(default_factory=dict)
    stats_partial: bool = False  # True — распарсились не все ключи


@dataclass
class ProbeReport:
    """Сводный отчёт проб по всем нодам."""

    results: dict[int, NodeProbeResult] = field(default_factory=dict)

    @property
    def reachable_count(self) -> int:
        return sum(1 for r in self.results.values() if r.reachable)


async def probe_tcp_all(
    targets: list[tuple[int, str, int]], timeout: float = 3.0  # noqa: ASYNC109
) -> dict[int, float | None]:
    """Параллельный TCP-ping всех нод: ``[(node_id, host, port), ...]``.

    Возвращает ``{node_id: rtt_ms | None}``. Ни один пинг не блокирует другие.
    """
    tasks = {nid: tcp_ping(host, port, timeout) for nid, host, port in targets}
    if not tasks:
        return {}
    gathered = await asyncio.gather(*tasks.values(), return_exceptions=True)
    out: dict[int, float | None] = {}
    for (nid, _, _), res in zip(targets, gathered, strict=False):
        if isinstance(res, BaseException):
            logger.debug("tcp ping failed for node %s", nid)
            out[nid] = None
        else:
            out[nid] = res
    return out


def parse_host_stats(raw_output: str) -> tuple[dict[str, Any], bool]:
    """Парсер JSON-вывода статистики хоста. Частичные данные — допустимы.

    Возвращает ``(stats, partial)``. ``partial=True`` — часть ожидаемых
    ключей отсутствует (fail-closed: отсутствующие поля не подменяются).
    """
    expected = (
        "cpu_percent",
        "load_1m",
        "load_5m",
        "load_15m",
        "mem_total_kb",
        "mem_available_kb",
        "disk_total_bytes",
        "disk_used_bytes",
        "disk_percent",
        "uptime_s",
    )
    stats: dict[str, Any] = {}
    raw = raw_output.strip()
    if not raw:
        return {}, True
    # Скрипт печатает ровно один JSON-объект; выделяем внешние скобки
    start, end = raw.find("{"), raw.rfind("}")
    if start == -1 or end <= start:
        return {}, True
    try:
        parsed = json.loads(raw[start : end + 1])
    except json.JSONDecodeError:
        logger.debug("host stats output is not valid JSON")
        return {}, True
    if not isinstance(parsed, dict):
        return {}, True
    for key in expected:
        value = parsed.get(key)
        if value is None:
            continue
        # числовые поля приводим; нечисловое — пропускаем (частичность)
        if isinstance(value, (int, float)):
            stats[key] = value
        else:
            try:
                stats[key] = int(value)
            except (TypeError, ValueError):
                try:
                    stats[key] = float(value)
                except (TypeError, ValueError):
                    logger.debug("non-numeric value for %s ignored", key)
    partial = any(key not in stats for key in expected)
    return stats, partial


def parse_docker_ps(raw_output: str) -> dict[str, str]:
    """Парсер ``docker ps --format names\\tstate\\tstatus`` → {имя: состояние}."""
    out: dict[str, str] = {}
    for line in raw_output.splitlines():
        line = line.strip()
        if not line or "\t" not in line:
            continue
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        name, state = parts[0].strip(), parts[1].strip().lower()
        if name:
            out[name] = state or "unknown"
    return out


class NodeProber:
    """SSH-пробы статусов протоколов и статистики хоста через пул."""

    def __init__(self, pool: SSHPool, docker_name_prefix: str = "awg") -> None:
        self._pool = pool
        self._prefix = docker_name_prefix

    async def probe_node(
        self,
        node_id: int,
        credentials: NodeCredentials,
        *,
        with_stats: bool = True,
        with_protocols: bool = True,
        command_timeout: float = 30.0,
    ) -> NodeProbeResult:
        """Полная SSH-проба ноды: статусы + статистика; частичный успех ок.

        Ошибки SSH не выбрасываются наружу — возвращаются в ``result.error``
        (проба не должна ломать цикл статусов страницы).
        """
        result = NodeProbeResult(node_id=node_id)
        coros: dict[str, Any] = {}
        if with_protocols:
            cmd = DOCKER_PS_TEMPLATE.format(prefix=self._prefix)
            coros["docker"] = self._pool.call(
                node_id, credentials, cmd, timeout=command_timeout
            )
        if with_stats:
            coros["stats"] = self._pool.call(
                node_id, credentials, HOST_STATS_SCRIPT, timeout=command_timeout
            )

        if not coros:
            return result

        keys = list(coros)
        gathered = await asyncio.gather(
            *(coros[k] for k in keys), return_exceptions=True
        )
        for key, res in zip(keys, gathered, strict=False):
            if isinstance(res, BaseException):
                result.error = "ssh_error"
                logger.debug("probe %s failed for node %s", key, node_id)
                continue
            if key == "docker":
                if res.exit_code == 0:
                    result.protocols = parse_docker_ps(res.stdout)
                else:
                    result.error = "docker_ps_failed"
            elif key == "stats":
                if res.exit_code == 0:
                    stats, partial = parse_host_stats(res.stdout)
                    result.stats = stats
                    result.stats_partial = partial
                else:
                    result.error = "host_stats_failed"
        # считаем ноду достижимой, если хотя бы одна SSH-команда выполнилась
        result.reachable = any(
            not isinstance(res, BaseException)
            and hasattr(res, "exit_code")
            and res.exit_code == 0
            for res in gathered
        )
        if result.reachable and result.error == "ssh_error":
            result.error = None
        return result

    async def probe_all(
        self,
        targets: list[tuple[int, NodeCredentials]],
        *,
        with_stats: bool = True,
    ) -> dict[int, NodeProbeResult]:
        """Параллельная SSH-проба всех нод; сбой одной не влияет на другие."""
        if not targets:
            return {}
        gathered = await asyncio.gather(
            *(
                self.probe_node(nid, creds, with_stats=with_stats)
                for nid, creds in targets
            ),
            return_exceptions=True,
        )
        out: dict[int, NodeProbeResult] = {}
        for (nid, _), res in zip(targets, gathered, strict=False):
            if isinstance(res, BaseException):
                logger.debug("probe failed for node %s", nid)
                out[nid] = NodeProbeResult(node_id=nid, error="ssh_error")
            else:
                out[nid] = res
        return out
