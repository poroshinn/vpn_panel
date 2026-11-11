"""Rate-limit (FR-2.3, ТЗ §2.3): скользящее окно, in-process (1 воркер).

- общий лимит на ``/api/*`` на пару (IP, path-группа);
- повышенные (более строгие) лимиты на auth-эндпоинты.
Одинокий процесс панели — хранить окна в памяти безопасно (правило 1).
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass, field

from app.core.config import get_settings


@dataclass(slots=True)
class _Window:
    hits: deque[float] = field(default_factory=deque)


class RateLimiter:
    """Скользящее окно: не более ``limit`` запросов за ``window_seconds``."""

    def __init__(self) -> None:
        self._windows: dict[str, _Window] = defaultdict(_Window)
        self._last_gc = time.monotonic()

    def _gc(self, now: float, window: float) -> None:
        # Раз в минуту выкидываем пустые окна, чтобы память не росла
        if now - self._last_gc < 60.0:
            return
        self._last_gc = now
        alive: dict[str, _Window] = {}
        for key, win in self._windows.items():
            while win.hits and now - win.hits[0] > window:
                win.hits.popleft()
            if win.hits:
                alive[key] = win
        self._windows = alive

    def check(self, key: str, limit: int, window_seconds: float) -> bool:
        """Разрешить ли запрос; фиксирует хит при разрешении."""
        now = time.monotonic()
        self._gc(now, window_seconds)
        win = self._windows[key]
        while win.hits and now - win.hits[0] > window_seconds:
            win.hits.popleft()
        if len(win.hits) >= limit:
            return False
        win.hits.append(now)
        return True


# Единый инстанс на процесс
_limiter: RateLimiter | None = None


def get_limiter() -> RateLimiter:
    global _limiter
    if _limiter is None:
        _limiter = RateLimiter()
    return _limiter


def api_rate_ok(ip: str, path: str) -> bool:
    """Лимит для /api/*: обычные эндпоинты и auth (строже)."""
    settings = get_settings()
    limiter = get_limiter()
    window = float(settings.rate_limit_window_seconds)
    if path.startswith("/api/auth/"):
        return limiter.check(f"auth:{ip}", settings.rate_limit_auth_per_window, window)
    return limiter.check(f"api:{ip}", settings.rate_limit_api_per_window, window)
