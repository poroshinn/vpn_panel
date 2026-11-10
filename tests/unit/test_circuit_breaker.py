"""Unit-тесты circuit breaker (MVP-04): переходы состояний."""

from __future__ import annotations

import pytest

from app.ssh.circuit_breaker import (
    BreakerOpenError,
    BreakerState,
    CircuitBreaker,
)


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


def make_breaker(clock: FakeClock, threshold: int = 3, reset: float = 30.0) -> CircuitBreaker:
    return CircuitBreaker(failure_threshold=threshold, reset_timeout=reset, clock=clock)


async def test_starts_closed(clock: FakeClock) -> None:
    breaker = make_breaker(clock)
    assert breaker.state is BreakerState.CLOSED
    await breaker.acquire_slot()  # не бросает


async def test_opens_after_threshold(clock: FakeClock) -> None:
    breaker = make_breaker(clock, threshold=3)
    for _ in range(2):
        breaker.record_failure()
    assert breaker.state is BreakerState.CLOSED
    breaker.record_failure()
    assert breaker.state is BreakerState.OPEN
    with pytest.raises(BreakerOpenError):
        await breaker.acquire_slot()


async def test_open_to_half_open_after_timeout(clock: FakeClock) -> None:
    breaker = make_breaker(clock, threshold=1, reset=30.0)
    breaker.record_failure()
    assert breaker.state is BreakerState.OPEN
    clock.advance(29.9)
    assert breaker.state is BreakerState.OPEN
    clock.advance(0.2)
    assert breaker.state is BreakerState.HALF_OPEN


async def test_half_open_success_closes(clock: FakeClock) -> None:
    breaker = make_breaker(clock, threshold=1, reset=10.0)
    breaker.record_failure()
    clock.advance(10.0)
    assert breaker.state is BreakerState.HALF_OPEN
    await breaker.acquire_slot()
    breaker.record_success()
    assert breaker.state is BreakerState.CLOSED
    assert breaker.consecutive_failures == 0


async def test_half_open_failure_reopens(clock: FakeClock) -> None:
    breaker = make_breaker(clock, threshold=1, reset=10.0)
    breaker.record_failure()
    clock.advance(10.0)
    assert breaker.state is BreakerState.HALF_OPEN
    breaker.record_failure()
    assert breaker.state is BreakerState.OPEN


async def test_half_open_single_probe(clock: FakeClock) -> None:
    breaker = make_breaker(clock, threshold=1, reset=10.0)
    breaker.record_failure()
    clock.advance(10.0)
    await breaker.acquire_slot()
    with pytest.raises(BreakerOpenError):
        await breaker.acquire_slot()


async def test_call_success_resets_counter(clock: FakeClock) -> None:
    breaker = make_breaker(clock, threshold=3)

    async def ok() -> str:
        return "done"

    breaker.record_failure()
    breaker.record_failure()
    assert await breaker.call(ok) == "done"
    assert breaker.consecutive_failures == 0
    assert breaker.state is BreakerState.CLOSED


async def test_call_failure_records_and_propagates(clock: FakeClock) -> None:
    breaker = make_breaker(clock, threshold=2)

    async def fail() -> None:
        raise RuntimeError("boom")

    with pytest.raises(RuntimeError):
        await breaker.call(fail)
    assert breaker.consecutive_failures == 1
    with pytest.raises(RuntimeError):
        await breaker.call(fail)
    assert breaker.state is BreakerState.OPEN


async def test_call_rejected_when_open(clock: FakeClock) -> None:
    breaker = make_breaker(clock, threshold=1)
    breaker.record_failure()

    async def op() -> None:
        raise AssertionError("must not be called")

    with pytest.raises(BreakerOpenError):
        await breaker.call(op)


async def test_manual_reset(clock: FakeClock) -> None:
    breaker = make_breaker(clock, threshold=1)
    breaker.record_failure()
    breaker.reset()
    assert breaker.state is BreakerState.CLOSED
    await breaker.acquire_slot()


async def test_invalid_threshold() -> None:
    with pytest.raises(ValueError):
        CircuitBreaker(failure_threshold=0)
