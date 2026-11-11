"""Unit-тесты rate-limit (FR-2.3)."""

from __future__ import annotations

import pytest

from app.core import rate_limit
from app.core.rate_limit import RateLimiter


class TestSlidingWindow:
    def test_allows_within_limit(self) -> None:
        rl = RateLimiter()
        for _ in range(5):
            assert rl.check("k", 5, 60.0) is True

    def test_blocks_over_limit(self) -> None:
        rl = RateLimiter()
        for _ in range(5):
            assert rl.check("k", 5, 60.0) is True
        assert rl.check("k", 5, 60.0) is False

    def test_window_slides(self, monkeypatch: pytest.MonkeyPatch) -> None:
        rl = RateLimiter()
        base = 1000.0
        monkeypatch.setattr(rate_limit.time, "monotonic", lambda: base)
        for _ in range(3):
            assert rl.check("k", 3, 10.0) is True
        assert rl.check("k", 3, 10.0) is False
        # прошло окно — хиты вытеснены
        monkeypatch.setattr(rate_limit.time, "monotonic", lambda: base + 11.0)
        assert rl.check("k", 3, 10.0) is True

    def test_keys_isolated(self) -> None:
        rl = RateLimiter()
        assert rl.check("a", 1, 60.0) is True
        assert rl.check("b", 1, 60.0) is True
        assert rl.check("a", 1, 60.0) is False


class TestApiRateOk:
    def test_auth_stricter_than_api(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # настройки по умолчанию: api 300/мин, auth 30/мин
        rate_limit.get_limiter()._windows.clear()
        assert rate_limit.api_rate_ok("1.2.3.4", "/api/v1/users") is True
        # auth-ключ отличается
        assert rate_limit.api_rate_ok("1.2.3.4", "/api/auth/login") is True

    def test_exhausted_auth(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from app.core.config import get_settings

        settings = get_settings()
        limit = settings.rate_limit_auth_per_window
        rate_limit.get_limiter()._windows.clear()
        for _ in range(limit):
            assert rate_limit.api_rate_ok("9.9.9.9", "/api/auth/login") is True
        assert rate_limit.api_rate_ok("9.9.9.9", "/api/auth/login") is False
        # другой IP не затронут
        assert rate_limit.api_rate_ok("8.8.8.8", "/api/auth/login") is True
