"""Текстовый логгер с санитайзером и ротацией по дням (FR-3.10.14, FR-3.10.14/NFR-9).

- Файлы: ``logs/panel-YYYY-MM-DD.log`` (UTC-дата), ретеншн 7 дней.
- Санитайзер на уровне логгера: секретоподобные паттерны маскируются.
"""

from __future__ import annotations

import logging
import re
import shutil
from datetime import datetime, timedelta, timezone
from logging.handlers import BaseRotatingHandler
from pathlib import Path

from app.core.config import get_settings

# Паттерны секретов для маскирования (никогда не покидают процесс в открытом виде)
_SECRET_PATTERNS: tuple[re[str], str] = (
    (re.compile(r"(password|passwd|pwd)\s*=\s*\S+", re.IGNORECASE), r"\1=***"),
    (re.compile(r"(authorization)\s*:\s*bearer\s+\S+", re.IGNORECASE), r"\1: Bearer ***"),
    (re.compile(r"(awp_)[A-Za-z0-9_\-]{8,}"), r"\1***"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"), "***"),
    (re.compile(r"(token|secret)\s*[=:]\s*\S+", re.IGNORECASE), r"\1=***"),
)


class _SanitizingFilter(logging.Filter):
    """Фильтр, маскирующий секреты в сообщении и аргументах записи."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            for pattern, replacement in _SECRET_PATTERNS:
                record.msg = pattern.sub(replacement, record.msg)
        if record.args:
            sanitized_args = []
            for arg in record.args:
                text = str(arg)
                for pattern, replacement in _SECRET_PATTERNS:
                    text = pattern.sub(replacement, text)
                sanitized_args.append(text)
            record.args = tuple(sanitized_args)
        return True


class _DailyFileHandler(BaseRotatingHandler):
    """Ротация по UTC-дню; файлы старше N дней удаляются."""

    def __init__(self, directory: Path, retention_days: int) -> None:
        self.directory = directory
        self.retention_days = retention_days
        directory.mkdir(parents=True, exist_ok=True)
        self._current_date = self._utc_today()
        super().__init__(self._filename(self._current_date), encoding="utf-8", mode="a")

    @staticmethod
    def _utc_today() -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%d")

    def _filename(self, date_str: str) -> Path:
        return self.directory / f"panel-{date_str}.log"

    def shouldRollover(self, record: logging.LogRecord) -> bool:
        return self._utc_today() != self._current_date

    def doRollover(self) -> None:
        if self.stream:
            self.stream.close()
            self.stream = None  # type: ignore[assignment]
        self._current_date = self._utc_today()
        self.baseFilename = str(self._filename(self._current_date))
        self.stream = self._open()
        self._cleanup()

    def _cleanup(self) -> None:
        cutoff = datetime.now(timezone.utc) - timedelta(days=self.retention_days)
        for path in self.directory.glob("panel-*.log"):
            try:
                file_date = datetime.strptime(path.stem.removeprefix("panel-"), "%Y-%m-%d").replace(tzinfo=timezone.utc)
            except ValueError:
                continue
            if file_date < cutoff:
                path.unlink(missing_ok=True)


def setup_logging() -> None:
    """Инициализация корневого логгера панели. Вызывать один раз при старте."""
    settings = get_settings()
    handler = _DailyFileHandler(Path(settings.log_dir), settings.log_retention_days)
    handler.setFormatter(
        logging.Formatter("%(asctime)s\t%(levelname)s\t%(name)s\t%(message)s", datefmt="%Y-%m-%dT%H:%M:%S")
    )
    handler.addFilter(_SanitizingFilter())

    console = logging.StreamHandler()
    console.addFilter(_SanitizingFilter())

    root = logging.getLogger()
    root.setLevel(settings.log_level.upper())
    root.addHandler(handler)
    root.addHandler(console)


def cleanup_old_logs() -> None:
    """Ручная очистка (используется тестами и админ-операциями)."""
    settings = get_settings()
    directory = Path(settings.log_dir)
    if not directory.exists():
        return
    cutoff = datetime.now(timezone.utc) - timedelta(days=settings.log_retention_days)
    for path in directory.glob("panel-*.log"):
        try:
            file_date = datetime.strptime(path.stem.removeprefix("panel-"), "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        if file_date < cutoff:
            shutil.rmtree(path, ignore_errors=True) if path.is_dir() else path.unlink(missing_ok=True)
