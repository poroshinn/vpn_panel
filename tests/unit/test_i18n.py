"""Unit-тесты i18n (FR-3.14.x): fallback, плурализация, детекция локали."""

from __future__ import annotations

import pytest

from app.i18n.catalog import (
    _plural_category,
    detect_locale,
    format_bytes,
    format_datetime_iso,
    get_catalog,
)


class _FakeRequest:
    def __init__(self, cookies: dict | None = None, headers: dict | None = None) -> None:
        self.cookies = cookies or {}
        self.headers = headers or {}


class TestPluralCategories:
    def test_ru_one(self) -> None:
        assert _plural_category("ru", 1) == "one"
        assert _plural_category("ru", 21) == "one"
        assert _plural_category("ru", 101) == "one"

    def test_ru_few(self) -> None:
        assert _plural_category("ru", 2) == "few"
        assert _plural_category("ru", 4) == "few"
        assert _plural_category("ru", 22) == "few"

    def test_ru_many(self) -> None:
        assert _plural_category("ru", 0) == "many"
        assert _plural_category("ru", 5) == "many"
        assert _plural_category("ru", 11) == "many"
        assert _plural_category("ru", 25) == "many"

    def test_en(self) -> None:
        assert _plural_category("en", 1) == "one"
        assert _plural_category("en", 2) == "other"
        assert _plural_category("en", 0) == "other"


class TestCatalog:
    def test_get_known_key(self) -> None:
        assert get_catalog("en").get("dashboard.title") == "Servers"
        assert get_catalog("ru").get("dashboard.title") == "Серверы"

    def test_fallback_to_en(self) -> None:
        # ключ есть в en, отсутствует в ru → берём en
        cat = get_catalog("ru")
        assert cat.get("nonexistent_key") == "nonexistent_key"
        assert cat.get("app.name") == "Amnezia Web Panel"

    def test_unknown_locale_falls_back_to_en(self) -> None:
        assert get_catalog("fr").get("dashboard.title") == "Servers"

    def test_ru_plural_forms(self) -> None:
        cat = get_catalog("ru")
        # synthetic keys через plural() на отсутствующем ключе → сам ключ
        assert cat.plural("my.empty", 1) == "my.empty"

    def test_plural_with_real_forms(self) -> None:
        # подкладываем формы напрямую в строки каталога
        cat = get_catalog("ru")
        cat._strings.update({  # noqa: SLF001 — тестовый доступ
            "test.peer.one": "{n} peer",
            "test.peer.few": "{n} peers (few)",
            "test.peer.many": "{n} peers (many)",
            "test.peer.other": "{n} peers",
        })
        assert cat.plural("test.peer", 1) == "1 peer"
        assert cat.plural("test.peer", 3) == "3 peers (few)"
        assert cat.plural("test.peer", 11) == "11 peers (many)"


class TestDetectLocale:
    def test_cookie_wins(self) -> None:
        req = _FakeRequest(cookies={"awp_lang": "ru"}, headers={"accept-language": "en"})
        assert detect_locale(req) == "ru"

    def test_accept_language(self) -> None:
        req = _FakeRequest(headers={"accept-language": "ru-RU,ru;q=0.9,en;q=0.8"})
        assert detect_locale(req) == "ru"

    def test_default_en(self) -> None:
        assert detect_locale(_FakeRequest()) == "en"

    def test_unsupported_locale_ignored(self) -> None:
        req = _FakeRequest(headers={"accept-language": "fr-FR,fr;q=0.9"})
        assert detect_locale(req) == "en"


class TestFormatting:
    def test_datetime_utc(self) -> None:
        value = "2026-11-11T10:30:00+00:00"
        assert "10:30" in format_datetime_iso(value, "en")
        assert "UTC" in format_datetime_iso(value, "ru")

    def test_datetime_none(self) -> None:
        assert format_datetime_iso(None, "en") == "—"

    def test_datetime_invalid_passthrough(self) -> None:
        assert format_datetime_iso("garbage", "en") == "garbage"

    def test_bytes(self) -> None:
        assert format_bytes(512) == "512 B"
        assert format_bytes(2048) == "2.0 KB"
        assert format_bytes(3 * 1024**3) == "3.0 GB"
        assert format_bytes(None) == "—"


@pytest.mark.parametrize("locale,key,expected", [
    ("en", "nav.logout", "Log out"),
    ("ru", "nav.logout", "Выйти"),
])
def test_translations(locale: str, key: str, expected: str) -> None:
    assert get_catalog(locale).get(key) == expected
