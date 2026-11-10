"""Unit-тесты app/auth/captcha.py: создание и атомарное потребление."""

from __future__ import annotations

import asyncio

import pytest

from app.auth.captcha import CaptchaExpired, CaptchaStore


async def test_create_returns_question() -> None:
    store = CaptchaStore()
    ch = await store.create()
    assert ch.challenge_id
    assert ch.question.endswith("= ?")


async def test_consume_correct_answer_true() -> None:
    store = CaptchaStore()
    ch = await store.create()
    a, b = ch.question.replace("= ?", "").split("+")
    answer = str(int(a.strip()) + int(b.strip()))
    assert await store.consume(ch.challenge_id, answer) is True


async def test_consume_is_atomic_single_use() -> None:
    """Потребление удаляет challenge: повторная попытка → CaptchaExpired."""
    store = CaptchaStore()
    ch = await store.create()
    a, b = ch.question.replace("= ?", "").split("+")
    answer = str(int(a.strip()) + int(b.strip()))
    assert await store.consume(ch.challenge_id, answer) is True
    with pytest.raises(CaptchaExpired):
        await store.consume(ch.challenge_id, answer)


async def test_consume_wrong_answer_removes_challenge() -> None:
    """Даже неверная попытка «сжигает» challenge (анти-брутфорс)."""
    store = CaptchaStore()
    ch = await store.create()
    assert await store.consume(ch.challenge_id, "999") is False
    with pytest.raises(CaptchaExpired):
        await store.consume(ch.challenge_id, "999")


async def test_expired_challenge_rejected() -> None:
    store = CaptchaStore(ttl_seconds=0)
    ch = await store.create()
    await asyncio.sleep(0.01)
    with pytest.raises(CaptchaExpired):
        await store.consume(ch.challenge_id, "1")


async def test_unknown_challenge_rejected() -> None:
    store = CaptchaStore()
    with pytest.raises(CaptchaExpired):
        await store.consume("no-such-id", "1")
