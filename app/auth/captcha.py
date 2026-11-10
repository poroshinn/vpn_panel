"""CAPTCHA-стор (FR-3.10.3, ТЗ §2.3).

Процессно-локальное хранилище challenge (один воркер — Приложение Б п.5),
атомарное «потребление» ответа: challenge удаляется при первой попытке
подтверждения — успешной или нет (защита от подбора).
"""

from __future__ import annotations

import asyncio
import secrets
import time
from dataclasses import dataclass

# Дефолты; переопределяются настройками панели (settings БД — этап 2)
CHALLENGE_TTL_SECONDS = 10 * 60
MAX_OPEN_CHALLENGES = 10_000


class CaptchaError(Exception):
    """Базовая ошибка CAPTCHA."""


class CaptchaExpired(CaptchaError):
    """Challenge не найден либо просрочен."""


@dataclass(frozen=True, slots=True)
class CaptchaChallenge:
    challenge_id: str
    question: str


@dataclass(frozen=True, slots=True)
class _Entry:
    answer: str
    expires_at: float


class CaptchaStore:
    """Простая арифметическая CAPTCHA с атомарным потреблением ответа."""

    def __init__(self, ttl_seconds: int = CHALLENGE_TTL_SECONDS) -> None:
        self._ttl = ttl_seconds
        self._entries: dict[str, _Entry] = {}
        self._lock = asyncio.Lock()

    async def create(self) -> CaptchaChallenge:
        """Новый challenge вида «a + b = ?»; числа 2–9 (нельзя ответить 0/1 наугад)."""
        async with self._lock:
            self._evict_expired()
            if len(self._entries) >= MAX_OPEN_CHALLENGES:
                # защита от переполнения памяти: сбрасываем самые старые
                for cid in list(self._entries)[: len(self._entries) // 2]:
                    del self._entries[cid]
            a, b = secrets.randbelow(8) + 2, secrets.randbelow(8) + 2
            challenge_id = secrets.token_urlsafe(16)
            self._entries[challenge_id] = _Entry(
                answer=str(a + b), expires_at=time.monotonic() + self._ttl
            )
            return CaptchaChallenge(challenge_id=challenge_id, question=f"{a} + {b} = ?")

    async def consume(self, challenge_id: str, answer: str) -> bool:
        """Атомарная проверка: challenge удаляется в любом исходе попытки.

        :raises CaptchaExpired: challenge отсутствует/просрочен.
        """
        async with self._lock:
            entry = self._entries.pop(challenge_id, None)
            if entry is None or entry.expires_at <= time.monotonic():
                raise CaptchaExpired("captcha challenge not found or expired")
            return secrets.compare_digest(entry.answer, answer.strip())

    def _evict_expired(self) -> None:
        now = time.monotonic()
        expired = [cid for cid, e in self._entries.items() if e.expires_at <= now]
        for cid in expired:
            del self._entries[cid]


# Единственный экземпляр на процесс (инициализируется в app.state при старте)
captcha_store = CaptchaStore()
