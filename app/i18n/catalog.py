"""Локализация en/ru (FR-3.14.1–3.14.4).

- ключи в ``app/i18n/{en,ru}.json``; отсутствующий ключ → fallback en → сам ключ;
- CLDR-плурализация: ``ru`` — категория one/few/many/other, остальные — one/other;
- язык выбирается из cookie ``awp_lang``, иначе Accept-Language, иначе ``en``;
- форматирование дат/чисел — по локали, время — UTC (правило 2 AGENTS.md).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

LOCALES_DIR = Path(__file__).parent
DEFAULT_LOCALE = "en"
SUPPORTED = ("en", "ru")
LANG_COOKIE = "awp_lang"


class Catalog:
    """Каталог переводов одного языка с fallback на ``en``."""

    def __init__(self, locale: str, strings: dict[str, str], fallback: dict[str, str]) -> None:
        self.locale = locale
        self._strings = strings
        self._fallback = fallback

    def get(self, key: str) -> str:
        return self._strings.get(key) or self._fallback.get(key) or key

    # --------------------------------------------------------------- plural

    def plural(self, key: str, n: int) -> str:
        """Плурализация по CLDR: ключи ``key.one`` / ``key.few`` / ``key.many`` /
        ``key.other`` (ru), ``key.one``/``key.other`` (прочие)."""
        category = _plural_category(self.locale, n)
        # CLDR "many" для числа, попавшего в many, часто совпадает с other —
        # но в ru это отдельная форма; берём её напрямую, а при отсутствии — other
        text = self._strings.get(f"{key}.{category}") or self._strings.get(f"{key}.other")
        text = text or self._fallback.get(f"{key}.{category}") or self._fallback.get(f"{key}.other")
        if text is None:
            return key
        return text.format(n=n)


def _plural_category(locale: str, n: int) -> str:
    abs_n = abs(n)
    if locale == "ru":
        # CLDR ru: one (1,21,31…), few (2–4,22–24…), many (0,5–20,25–30…),
        # other — дробные (не применимо к int)
        mod10, mod100 = abs_n % 10, abs_n % 100
        if mod10 == 1 and mod100 != 11:
            return "one"
        if 2 <= mod10 <= 4 and not 12 <= mod100 <= 14:
            return "few"
        return "many"
    # en / прочие: one — только 1
    return "one" if abs_n == 1 else "other"


_cache: dict[str, dict[str, str]] = {}


def _load_locale(locale: str) -> dict[str, str]:
    if locale not in _cache:
        path = LOCALES_DIR / f"{locale}.json"
        try:
            _cache[locale] = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            _cache[locale] = {}
    return _cache[locale]


_catalogs: dict[str, Catalog] = {}


def get_catalog(locale: str) -> Catalog:
    """Каталог локали с fallback на ``en``; неизвестная локаль → ``en``."""
    if locale not in SUPPORTED:
        locale = DEFAULT_LOCALE
    catalog = _catalogs.get(locale)
    if catalog is None:
        fallback = {} if locale == DEFAULT_LOCALE else _load_locale(DEFAULT_LOCALE)
        catalog = Catalog(locale, _load_locale(locale), fallback)
        _catalogs[locale] = catalog
    return catalog


def detect_locale(request) -> str:  # noqa: ANN001 — Request без циклического импорта
    """Язык запроса: cookie ``awp_lang`` → Accept-Language → ``en``."""
    cookie = request.cookies.get(LANG_COOKIE)
    if cookie in SUPPORTED:
        return cookie
    header = request.headers.get("accept-language", "")
    for part in header.split(","):
        code = part.split(";")[0].strip().split("-")[0].lower()
        if code in SUPPORTED:
            return code
    return DEFAULT_LOCALE


# ------------------------------------------------------------ форматирование


def format_datetime_iso(value: str | None, locale: str) -> str:
    """ISO-8601 (UTC) → человекочитаемая строка по локали; время — UTC."""
    if not value:
        return "—"
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return value
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC).strftime("%d.%m.%Y %H:%M UTC")


def format_bytes(n: int | None, locale: str = "en") -> str:
    """Байты → человекочитаемый объём (МБ/ГБ…), локаль не влияет на единицы SI."""
    if n is None:
        return "—"
    size = float(abs(n))
    for unit in ("B", "KB", "MB", "GB", "TB", "PB"):
        if size < 1024 or unit == "PB":
            if unit == "B":
                return f"{int(size)} {unit}"
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{n} B"
