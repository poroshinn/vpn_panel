"""Telegram-алерты панели (FR-3.10.13).

Тумблеры (каждый включается/выключается в settings БД, ``alert_*``):
- ``server_down``        — сервер недоступен N минут подряд;
- ``quota_exhausted``    — квота пользователя исчерпана (автоотключение);
- ``ssl_expiry``         — SSL-сертификат панели истекает ≤ 14 дней
                           (для MVP проверяется файл, путь — ``alert_ssl_cert_path``);
- ``backup_failed``      — автобэкап не удался;
- ``accounting_gap``     — ``traffic_accounting_gap`` (сводно, ≤ 1 раз/час).

Дедупликация: одинаковый алерт не отправляется чаще, чем раз в
``ALERT_DEDUP_SECONDS`` (по умолчанию 1 час) — in-process стор (1 воркер,
правило 1 AGENTS.md).

Отправка — тем же Telegram-ботом, что и автобэкап (``backup_telegram_*``),
со своими ключами ``alert_telegram_bot_token``/``alert_telegram_chat_id``
(env-фолбэк ``TELEGRAM_BOT_TOKEN``/``TELEGRAM_CHAT_ID``).

Токены/чаты никогда не возвращаются в открытом виде (правило 3 AGENTS.md).
"""

from __future__ import annotations

import asyncio
import logging
import os
import socket
import ssl
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Any

import httpx

from app.backups.telegram import TelegramSendError, _get_setting, _set_setting
from app.db.database import Database

logger = logging.getLogger(__name__)

# Тумблеры (settings-ключи) и их человекочитаемые названия
ALERT_KEYS = {
    "server_down": "alert_server_down_enabled",
    "quota_exhausted": "alert_quota_exhausted_enabled",
    "ssl_expiry": "alert_ssl_expiry_enabled",
    "backup_failed": "alert_backup_failed_enabled",
    "accounting_gap": "alert_accounting_gap_enabled",
}

SETTINGS_BOT_TOKEN = "alert_telegram_bot_token"  # noqa: S105 — имя ключа, не секрет
SETTINGS_CHAT_ID = "alert_telegram_chat_id"
SETTINGS_SSL_CERT_PATH = "alert_ssl_cert_path"
SETTINGS_SERVER_DOWN_MINUTES = "alert_server_down_minutes"

ALERT_DEDUP_SECONDS = 3600  # 1 час (FR-3.10.13: accounting_gap ≤ 1 раз/час)
DEFAULT_SERVER_DOWN_MINUTES = 5
SSL_WARN_DAYS = 14


@dataclass(frozen=True)
class AlertConfig:
    """Резолвнутая конфигурация алертов."""

    bot_token: str | None
    chat_id: str | None
    toggles: dict[str, bool]
    ssl_cert_path: str | None
    server_down_minutes: int

    @property
    def configured(self) -> bool:
        return bool(self.bot_token and self.chat_id)


@dataclass
class AlertState:
    """In-process состояние: дедупликация + трекинг недоступности серверов."""

    last_sent: dict[str, float] = field(default_factory=dict)
    # server_id -> (первый раз недоступен, уже отправлен ли алерт)
    down_since: dict[int, tuple[float, bool]] = field(default_factory=dict)


_state = AlertState()


def reset_state() -> None:
    """Сброс in-process состояния (изоляция тестов)."""
    global _state
    _state = AlertState()


async def get_alert_config(db: Database) -> AlertConfig:
    """Конфигурация алертов: тумблеры + получатель (settings БД → env)."""
    toggles: dict[str, bool] = {}
    for name, key in ALERT_KEYS.items():
        row = await _get_setting(db, key)
        # по умолчанию все тумблеры выключены (осознанное включение админом)
        toggles[name] = (row == "1") if row is not None else False
    minutes_raw = await _get_setting(db, SETTINGS_SERVER_DOWN_MINUTES)
    try:
        minutes = max(1, int(minutes_raw)) if minutes_raw else DEFAULT_SERVER_DOWN_MINUTES
    except ValueError:
        minutes = DEFAULT_SERVER_DOWN_MINUTES
    return AlertConfig(
        bot_token=await _get_setting(db, SETTINGS_BOT_TOKEN)
        or os.environ.get("TELEGRAM_BOT_TOKEN"),
        chat_id=await _get_setting(db, SETTINGS_CHAT_ID)
        or os.environ.get("TELEGRAM_CHAT_ID"),
        toggles=toggles,
        ssl_cert_path=await _get_setting(db, SETTINGS_SSL_CERT_PATH),
        server_down_minutes=minutes,
    )


async def save_alert_config(
    db: Database,
    *,
    toggles: dict[str, bool] | None = None,
    bot_token: str | None = ...,
    chat_id: str | None = ...,
    ssl_cert_path: str | None = ...,
    server_down_minutes: int | None = None,
) -> None:
    """Сохранение настроек алертов (admin). ``...`` — «не менять»."""
    if toggles:
        for name, value in toggles.items():
            key = ALERT_KEYS.get(name)
            if key is None:
                raise ValueError(f"unknown alert toggle: {name}")
            await _set_setting(db, key, "1" if value else "0")
    if bot_token is not ...:
        await _set_setting(db, SETTINGS_BOT_TOKEN, bot_token or None)
    if chat_id is not ...:
        await _set_setting(db, SETTINGS_CHAT_ID, chat_id or None)
    if ssl_cert_path is not ...:
        await _set_setting(db, SETTINGS_SSL_CERT_PATH, ssl_cert_path or None)
    if server_down_minutes is not None:
        await _set_setting(db, SETTINGS_SERVER_DOWN_MINUTES, str(server_down_minutes))


async def send_alert_message(
    bot_token: str,
    chat_id: str,
    text: str,
    *,
    base_url: str = "https://api.telegram.org",
    http: httpx.AsyncClient | None = None,
) -> None:
    """Отправка текста алерта ботом (sendMessage)."""
    url = f"{base_url}/bot{bot_token}/sendMessage"
    own_client = http is None
    client = http or httpx.AsyncClient(timeout=30.0)
    try:
        response = await client.post(url, data={"chat_id": chat_id, "text": text})
        if response.status_code != 200:
            raise TelegramSendError(f"telegram api status {response.status_code}")
    except httpx.HTTPError as exc:
        raise TelegramSendError(f"telegram send failed: {type(exc).__name__}") from exc
    finally:
        if own_client:
            await client.aclose()


async def raise_alert(
    db: Database,
    kind: str,
    text: str,
    *,
    dedup_seconds: float = ALERT_DEDUP_SECONDS,
    http: httpx.AsyncClient | None = None,
    clock: Any = time.monotonic,
) -> bool:
    """Поднять алерт: проверка тумблера + дедупликация + отправка.

    Возвращает ``True``, если алерт отправлен; ``False`` — если заглушён
    тумблером/дедупликацией или бот не настроен. Ошибки сети логируются,
    не бросаются (алерты не должны ронять фоновые циклы).
    """
    config = await get_alert_config(db)
    if not config.toggles.get(kind, False):
        return False
    if not config.configured:
        logger.warning("alert %s suppressed: telegram not configured", kind)
        return False

    now = clock()
    last = _state.last_sent.get(kind, float("-inf"))
    if now - last < dedup_seconds:
        return False
    _state.last_sent[kind] = now

    try:
        await send_alert_message(
            config.bot_token or "", config.chat_id or "", text, http=http
        )
    except TelegramSendError as exc:
        logger.warning("alert %s delivery failed: %s", kind, exc)
        # откатываем метку, чтобы ретрай был возможен на следующем тике
        _state.last_sent[kind] = last
        return False
    return True


# ------------------------------------------------------------ конкретные алерты


async def alert_server_down(
    db: Database,
    server_id: int,
    server_name: str,
    *,
    reachable: bool,
    http: httpx.AsyncClient | None = None,
    clock: Any = time.monotonic,
) -> bool:
    """Сервер недоступен N минут (FR-3.10.13а)."""
    config = await get_alert_config(db)
    threshold = config.server_down_minutes * 60
    now = clock()

    if reachable:
        _state.down_since.pop(server_id, None)
        return False

    first, notified = _state.down_since.get(server_id, (now, False))
    _state.down_since[server_id] = (first, notified)
    if notified or now - first < threshold:
        return False
    sent = await raise_alert(
        db, "server_down",
        f"⚠️ Server '{server_name}' is unreachable for "
        f"{config.server_down_minutes} min.",
        http=http, clock=clock,
    )
    if sent:
        _state.down_since[server_id] = (first, True)
    return sent


async def alert_quota_exhausted(
    db: Database,
    username: str,
    *,
    http: httpx.AsyncClient | None = None,
    clock: Any = time.monotonic,
) -> bool:
    """Квота пользователя исчерпана (автоотключение, FR-3.10.13б)."""
    return await raise_alert(
        db, "quota_exhausted",
        f"⛔ Traffic quota exhausted for user '{username}' — access disabled.",
        http=http, clock=clock,
    )


async def alert_backup_failed(
    db: Database,
    reason: str,
    *,
    http: httpx.AsyncClient | None = None,
    clock: Any = time.monotonic,
) -> bool:
    """Автобэкап не удался (FR-3.10.13)."""
    return await raise_alert(
        db, "backup_failed",
        f"💾 Daily backup failed: {reason}",
        http=http, clock=clock,
    )


async def alert_accounting_gap(
    db: Database,
    count: int,
    *,
    http: httpx.AsyncClient | None = None,
    clock: Any = time.monotonic,
) -> bool:
    """Сводка по gap'ам учёта (≤ 1 раз/час — сама дедупликация raise_alert)."""
    return await raise_alert(
        db, "accounting_gap",
        f"📊 traffic_accounting_gap: {count} unverified counter event(s) "
        "in the last hour.",
        http=http, clock=clock,
    )


def check_ssl_expiry(cert_path: str) -> int | None:
    """Дней до истечения SSL-сертификата файла (PEM); None — прочитать не удалось."""
    try:
        raw = ssl._ssl._test_decode_cert(cert_path)  # type: ignore[attr-defined] # noqa: SLF001
        expiry = parsedate_to_datetime(raw["notAfter"])
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=UTC)
        return (expiry - datetime.now(UTC)).days
    except (OSError, KeyError, ValueError, TypeError):
        return None


async def alert_ssl_expiry(
    db: Database,
    *,
    http: httpx.AsyncClient | None = None,
    clock: Any = time.monotonic,
) -> bool:
    """SSL-сертификат панели истекает ≤ 14 дней (FR-3.10.13)."""
    config = await get_alert_config(db)
    if not config.ssl_cert_path:
        return False
    days = check_ssl_expiry(config.ssl_cert_path)
    if days is None or days > SSL_WARN_DAYS:
        return False
    return await raise_alert(
        db, "ssl_expiry",
        f"🔒 Panel SSL certificate expires in {days} day(s).",
        dedup_seconds=24 * 3600,  # про сертификат — раз в сутки
        http=http, clock=clock,
    )


async def probe_host_tcp(host: str, port: int, probe_timeout: float = 3.0) -> bool:
    """TCP-проба хоста (чистый asyncio, как в probes.py)."""
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=probe_timeout
        )
        writer.close()
        return True
    except (OSError, TimeoutError):
        return False


def socket_probe(host: str, port: int, timeout: float = 3.0) -> bool:
    """Синхронная TCP-проба (для вызова из to_thread)."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False
