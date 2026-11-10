"""Circuit breaker для SSH-нод (FR-3.1.8).

N подряд неудач к ноде ⇒ размыкание на T секунд (попыток нет вовсе), затем
полуоткрытое состояние: одна пробная попытка, успех закрывает цепь, неудача
открывает снова. In-process состояние (правило 1 AGENTS.md — один процесс).

Состояния: ``closed`` (норм), ``open`` (блок), ``half_open`` (проба).
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from enum import Enum
from typing import Any


class BreakerState(str, Enum):  # noqa: UP042 — строковое значение нужно для API
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class BreakerOpenError(Exception):
    """Вызов отклонён: цепь разомкнута (попытки к ноде приостановлены)."""


class CircuitBreaker:
    """Circuit breaker для одной ноды.

    :param failure_threshold: сколько подряд неудач открывают цепь.
    :param reset_timeout: секунд в состоянии ``open`` до полуоткрытого.
    :param clock: монотонные секунды (инъекция для тестов).
    """

    def __init__(
        self,
        failure_threshold: int = 3,
        reset_timeout: float = 30.0,
        clock: Callable[[], float] | None = None,
    ) -> None:
        if failure_threshold < 1:
            raise ValueError("failure_threshold must be >= 1")
        self._failure_threshold = failure_threshold
        self._reset_timeout = reset_timeout
        self._clock = clock or time.monotonic
        self._state = BreakerState.CLOSED
        self._consecutive_failures = 0
        self._opened_at: float | None = None
        self._half_open_inflight = False
        self._lock = asyncio.Lock()

    # ------------------------------------------------------------- inspect

    @property
    def state(self) -> BreakerState:
        self._refresh()
        return self._state

    @property
    def consecutive_failures(self) -> int:
        return self._consecutive_failures

    def _refresh(self) -> None:
        """OPEN → HALF_OPEN по истечении таймаута (без side-effect'ов иначе)."""
        if (
            self._state is BreakerState.OPEN
            and self._opened_at is not None
            and self._clock() - self._opened_at >= self._reset_timeout
        ):
            self._state = BreakerState.HALF_OPEN
            self._half_open_inflight = False

    def seconds_until_half_open(self) -> float:
        """Сколько секунд осталось до полуоткрытого (0, если не OPEN)."""
        if self._state is not BreakerState.OPEN or self._opened_at is None:
            return 0.0
        remaining = self._reset_timeout - (self._clock() - self._opened_at)
        return max(0.0, remaining)

    # -------------------------------------------------------------- record

    def record_success(self) -> None:
        """Успех: цепь закрывается, счётчик обнуляется."""
        self._state = BreakerState.CLOSED
        self._consecutive_failures = 0
        self._opened_at = None
        self._half_open_inflight = False

    def record_failure(self) -> None:
        """Неудача: инкремент; порог → OPEN. Неудача в HALF_OPEN → снова OPEN."""
        if self._state is BreakerState.HALF_OPEN:
            self._open()
            return
        self._consecutive_failures += 1
        if self._consecutive_failures >= self._failure_threshold:
            self._open()

    def _open(self) -> None:
        self._state = BreakerState.OPEN
        self._opened_at = self._clock()
        self._consecutive_failures = self._failure_threshold
        self._half_open_inflight = False

    def reset(self) -> None:
        """Ручной сброс (например, после редактирования сервера в панели)."""
        self.record_success()

    # --------------------------------------------------------------- call

    async def acquire_slot(self) -> None:
        """Занять слот пробной попытки в HALF_OPEN (или пройти в CLOSED).

        OPEN → :class:`BreakerOpenError`. HALF_OPEN: одна попытка за раз,
        конкурентные вызовы получают :class:`BreakerOpenError`.
        """
        async with self._lock:
            self._refresh()
            if self._state is BreakerState.OPEN:
                raise BreakerOpenError(
                    "circuit open, retry in "
                    f"{self.seconds_until_half_open():.1f}s"
                )
            if self._state is BreakerState.HALF_OPEN:
                if self._half_open_inflight:
                    raise BreakerOpenError("half-open probe already in flight")
                self._half_open_inflight = True

    async def call(
        self,
        operation: Callable[..., Awaitable[Any]],
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        """Выполнить операцию под защитой breaker'а.

        Ошибка операции → ``record_failure``; успех → ``record_success``.
        В HALF_OPEN попытка одна: конкурентные вызовы отклонены.
        """
        await self.acquire_slot()
        try:
            result = await operation(*args, **kwargs)
        except BaseException:
            await asyncio.to_thread(self.record_failure)
            raise
        if self._state is BreakerState.HALF_OPEN:
            # success в HALF_OPEN закрывает цепь
            self.record_success()
        else:
            self.record_success()
        return result
