"""Автобэкап в Telegram (FR-3.10.10, сценарий §5.5).

Общий клиент отправки файлов ботом (полный бот с командами — Этап 2).
Ежедневная фоновая задача: в заданное время UTC панель делает снапшот,
сжимает gzip и отправляет ботом администратору; результат фиксируется в audit.

Деградации (FR-3.10.10, §5.5.2):
- бот не настроен / Telegram недоступен ⇒ копия ротируется локально
  (``backups/local/``, 7 файлов) + флаг ``last_error`` для алерта
  «автобэкап не удался» (FR-3.10.13, тумблер — MVP-12).
- лимит файла Telegram (50 MiB) превышен ⇒ отправка без вложения
  с текстовой инструкцией скачать снимок из панели.

Настройки хранятся в таблице ``settings`` (ключи ``backup_*``).
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from datetime import time as dt_time
from pathlib import Path
from typing import Any

import httpx

from app.backups.snapshot import Snapshot, make_snapshot
from app.core.audit import log_event
from app.db.database import Database

logger = logging.getLogger(__name__)

TELEGRAM_FILE_LIMIT = 50 * 1024 * 1024  # 50 MiB — лимит Bot API на sendDocument

DEFAULT_TIME_UTC = dt_time(3, 0)  # 03:00 UTC

SETTINGS_ENABLED = "backup_telegram_enabled"
SETTINGS_TIME = "backup_telegram_time_utc"  # "HH:MM"
# nosec: имя settings-ключа, не пароль
SETTINGS_BOT_TOKEN = "backup_telegram_bot_token"  # noqa: S105
SETTINGS_CHAT_ID = "backup_telegram_chat_id"


@dataclass(frozen=True)
class TelegramConfig:
    """Резолвнутая конфигурация бота (из settings БД; env — дефолт)."""

    bot_token: str | None
    chat_id: str | None
    enabled: bool
    send_time: dt_time


async def _get_setting(db: Database, key: str) -> str | None:
    row = await db.fetch_one("SELECT value FROM settings WHERE key = ?", (key,))
    return row["value"] if row else None


async def _set_setting(db: Database, key: str, value: str | None) -> None:
    if value is None:
        await db.execute("DELETE FROM settings WHERE key = ?", (key,))
    else:
        await db.execute(
            "INSERT INTO settings (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )


def _parse_time(raw: str | None) -> dt_time:
    if not raw:
        return DEFAULT_TIME_UTC
    try:
        hh, mm = raw.split(":", 1)
        return dt_time(int(hh), int(mm))
    except (ValueError, TypeError):
        return DEFAULT_TIME_UTC


async def get_config(db: Database) -> TelegramConfig:
    """Конфигурация автобэкапа; бот-токен/чат — settings БД или env."""
    import os

    enabled_raw = await _get_setting(db, SETTINGS_ENABLED)
    enabled = (enabled_raw if enabled_raw is not None else "0") == "1"
    return TelegramConfig(
        bot_token=(
            await _get_setting(db, SETTINGS_BOT_TOKEN)
            or os.environ.get("TELEGRAM_BOT_TOKEN")
        ),
        chat_id=(
            await _get_setting(db, SETTINGS_CHAT_ID)
            or os.environ.get("TELEGRAM_CHAT_ID")
        ),
        enabled=enabled,
        send_time=_parse_time(await _get_setting(db, SETTINGS_TIME)),
    )


async def save_config(
    db: Database,
    *,
    enabled: bool | None = None,
    send_time: str | None = None,
    bot_token: str | None = ...,
    chat_id: str | None = ...,
) -> None:
    """Сохранение настроек автобэкапа (admin). ``...`` — «не менять».

    Секреты не логируются и не возвращаются (правило 3 AGENTS.md): токен
    читается назад только как факт наличия (``telegram_configured``).
    """
    if enabled is not None:
        await _set_setting(db, SETTINGS_ENABLED, "1" if enabled else "0")
    if send_time is not None:
        _parse_time(send_time)  # валидация
        await _set_setting(db, SETTINGS_TIME, send_time)
    if bot_token is not ...:
        await _set_setting(db, SETTINGS_BOT_TOKEN, bot_token or None)
    if chat_id is not ...:
        await _set_setting(db, SETTINGS_CHAT_ID, chat_id or None)


# ------------------------------------------------------------ отправка


class TelegramSendError(RuntimeError):
    """Ошибка отправки в Telegram (без секретов)."""


async def send_backup_document(
    bot_token: str,
    chat_id: str,
    path: Path,
    *,
    base_url: str = "https://api.telegram.org",
    caption: str = "",
    http: httpx.AsyncClient | None = None,
) -> None:
    """Отправка файла ботом (sendDocument). Поднимает :class:`TelegramSendError`."""
    url = f"{base_url}/bot{bot_token}/sendDocument"
    own_client = http is None
    client = http or httpx.AsyncClient(timeout=60.0)
    try:
        # open() на локальном tmpfs-файле снапшота — мгновенный; потоковая
        # отдача файла в httpx требует живого handle на время запроса.
        with open(path, "rb") as fh:  # noqa: ASYNC230
            response = await client.post(
                url,
                data={"chat_id": chat_id, "caption": caption},
                files={"document": (path.name, fh, "application/gzip")},
            )
        if response.status_code != 200:
            # тело ответа Telegram может содержать chat_id — не выходим наружу
            raise TelegramSendError(f"telegram api status {response.status_code}")
    except (OSError, httpx.HTTPError) as exc:
        raise TelegramSendError(f"telegram send failed: {type(exc).__name__}") from exc
    finally:
        if own_client:
            await client.aclose()


async def send_backup_message(
    bot_token: str,
    chat_id: str,
    text: str,
    *,
    base_url: str = "https://api.telegram.org",
    http: httpx.AsyncClient | None = None,
) -> None:
    """Отправка текстового сообщения ботом (sendMessage)."""
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


# ------------------------------------------------------------ daily job


@dataclass(frozen=True)
class DailyResult:
    """Итог одного прогона ежедневного автобэкапа."""

    snapshot: Snapshot | None
    delivered: str  # "telegram" | "local" | "skipped"
    error: str | None = None


async def run_daily_backup(db: Database, *, actor: str = "system") -> DailyResult:
    """Один прогон автобэкапа (FR-3.10.10, §5.5).

    Снапшот всегда делается в локальную ротацию; при настроенном и доступном
    боте — дополнительно отправка в Telegram. Итог — audit-событие.
    """
    config = await get_config(db)
    snapshot = await make_snapshot(db)  # всегда локальная ротация (7 файлов)
    await db.execute(
        "INSERT INTO recovery_snapshots (kind, path, sha256, created_at) "
        "VALUES ('auto', ?, ?, ?)",
        (
            str(snapshot.path),
            snapshot.sha256,
            datetime.now(UTC).isoformat(timespec="seconds"),
        ),
    )

    if not config.enabled:
        return DailyResult(snapshot=snapshot, delivered="skipped")

    if not config.bot_token or not config.chat_id:
        # деградация: бот не настроен → локальная ротация + алерт-флаг (FR-3.10.10)
        await _set_setting(db, "backup_last_error", "telegram_not_configured")
        await log_event(
            db, actor, "backup.auto_failed",
            details={"reason": "telegram_not_configured"},
        )
        return DailyResult(snapshot=snapshot, delivered="local",
                           error="telegram_not_configured")

    try:
        if snapshot.size <= TELEGRAM_FILE_LIMIT:
            await send_backup_document(
                config.bot_token, config.chat_id, snapshot.path,
                caption=f"Panel backup {snapshot.path.name}",
            )
            delivered = "telegram"
        else:
            # превышение лимита: без вложения, с инструкцией (FR-3.10.10)
            await send_backup_message(
                config.bot_token, config.chat_id,
                "Daily backup snapshot is too large to attach "
                f"({snapshot.size} bytes). Download it from the panel: "
                "Settings → Backups.",
            )
            delivered = "telegram_message_only"
        await _set_setting(db, "backup_last_error", None)
    except TelegramSendError as exc:
        await _set_setting(db, "backup_last_error", str(exc))
        await log_event(db, actor, "backup.auto_failed", details={"reason": str(exc)})
        return DailyResult(snapshot=snapshot, delivered="local", error=str(exc))

    await log_event(
        db, actor, "backup.auto_sent",
        details={"delivered": delivered, "sha256": snapshot.sha256},
    )
    return DailyResult(snapshot=snapshot, delivered=delivered)


def _seconds_until(target: dt_time, now: datetime) -> float:
    today_run = datetime.combine(now.date(), target, tzinfo=UTC)
    if today_run <= now:
        today_run += timedelta(days=1)
    return (today_run - now).total_seconds()


class BackupScheduler:
    """Ежедневная фоновая задача автобэкапа (один инстанс на процесс)."""

    def __init__(self, db: Database, *, check_interval: float = 60.0) -> None:
        self._db = db
        self._check_interval = check_interval
        self._task: asyncio.Task | None = None
        self._stopping = asyncio.Event()
        self._last_run_day: str | None = None
        self.last_result: dict[str, Any] | None = None

    def start(self) -> None:
        if self._task is None or self._task.done():
            self._stopping = asyncio.Event()
            self._task = asyncio.create_task(self._run(), name="backup-scheduler")

    async def stop(self) -> None:
        self._stopping.set()
        if self._task is not None:
            try:
                await asyncio.wait_for(self._task, timeout=5.0)
            except (TimeoutError, asyncio.CancelledError):
                self._task.cancel()
            self._task = None

    async def _run(self) -> None:
        while not self._stopping.is_set():
            try:
                await self._tick()
            except Exception:  # noqa: BLE001 — цикл обязан пережить любой сбой
                logger.exception("backup scheduler tick failed")
            try:
                await asyncio.wait_for(self._stopping.wait(), timeout=self._check_interval)
            except TimeoutError:
                pass

    async def _tick(self) -> None:
        config = await get_config(self._db)
        if not config.enabled:
            return
        now = datetime.now(UTC)
        day_key = now.strftime("%Y-%m-%d")
        if self._last_run_day == day_key:
            return
        if now.time() >= config.send_time:
            result = await run_daily_backup(self._db)
            self._last_run_day = day_key
            self.last_result = {
                "delivered": result.delivered,
                "error": result.error,
                "path": str(result.snapshot.path) if result.snapshot else None,
                "at": now.isoformat(timespec="seconds"),
            }
