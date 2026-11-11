"""Дисковая деградация (FR-3.15.7).

Проверка свободного места на разделе данных панели:
- свободно < ``CRITICAL_THRESHOLD_MB`` (по умолчанию 200 MiB) ⇒ алерт
  (тумблер ``disk_space`` — из app/alerts);
- свободно < ``EMERGENCY_THRESHOLD_MB`` (по умолчанию 50 MiB) ⇒ read-only
  для мутирующих операций панели (кроме снятия блокировок и алертинга).

In-process стор (1 воркер, правило 1 AGENTS.md); проверка — раз в минуту
в фоновом цикле и по требованию из API.
"""

from __future__ import annotations

import asyncio
import logging
import shutil
from dataclasses import dataclass
from pathlib import Path

from app.core.config import get_settings

logger = logging.getLogger(__name__)

EMERGENCY_THRESHOLD_MB = 50  # ниже — read-only
CRITICAL_THRESHOLD_MB = 200  # ниже — алерт

READ_ONLY_ERROR = "disk_full_read_only"


@dataclass(frozen=True)
class DiskState:
    """Снимок состояния диска."""

    free_mb: int
    critical: bool  # < CRITICAL → алерт
    emergency: bool  # < EMERGENCY → read-only

    @property
    def read_only(self) -> bool:
        return self.emergency


_last_state: DiskState | None = None
_lock = asyncio.Lock()


def reset_state() -> None:
    """Сброс состояния (изоляция тестов)."""
    global _last_state
    _last_state = None


async def check_disk(path: Path | None = None) -> DiskState:
    """Проверить свободное место; кэшировать последний результат."""
    global _last_state
    async with _lock:
        target = path or Path(get_settings().db_file)
        probe = target if target.is_dir() else target.parent
        try:
            usage = shutil.disk_usage(probe)
            free_mb = int(usage.free // (1024 * 1024))
        except OSError:
            # не смогли определить — fail-open для доступности, но логируем
            logger.exception("disk usage check failed")
            free_mb = CRITICAL_THRESHOLD_MB  # «норма»
        state = DiskState(
            free_mb=free_mb,
            critical=free_mb < CRITICAL_THRESHOLD_MB,
            emergency=free_mb < EMERGENCY_THRESHOLD_MB,
        )
        _last_state = state
        return state


def last_state() -> DiskState | None:
    """Последний измеренный статус (None — до первой проверки)."""
    return _last_state


def is_read_only() -> bool:
    """Панель в read-only-режиме из-за диска? (без проверки — из кэша)."""
    return _last_state.read_only if _last_state else False


async def ensure_writable() -> None:
    """Guard для мутирующих операций (FR-3.15.7).

    :raises RuntimeError: read_only — диск в аварийном состоянии.
    """
    state = _last_state or await check_disk()
    if state.read_only:
        raise RuntimeError(READ_ONLY_ERROR)
