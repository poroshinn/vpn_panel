"""Конфигурация панели (FR-3.15.3, NFR-2).

Все пути — относительно корня приложения либо абсолютные.
Время — UTC везде (правило 2 AGENTS.md).
"""

from __future__ import annotations

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Переменные окружения панели."""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # Ключ подписи cookie-сессий
    secret_key: str = "change-me"

    # Мастер-ключ шифрования секретов серверов (AES-256-GCM).
    # На MVP-03 станет обязательным (генерация при первом старте в volume).
    panel_master_key: str | None = None

    # Пути
    db_file: Path = Path("data/panel.db")
    log_dir: Path = Path("logs")
    backup_dir: Path = Path("backups")

    # Сервер
    app_port: int = 8000
    log_level: str = "INFO"

    # Ретеншн логов, дней (FR-3.10.14)
    log_retention_days: int = 7

    # CAPTCHA на странице входа (FR-3.10.3) — доп. слой, не замена brute-force
    captcha_enabled: bool = False

    # Сессии (ТЗ §2.3, настраиваются в settings БД — здесь дефолты)
    session_abs_ttl_seconds: int = 7 * 24 * 3600  # 7 дней
    session_idle_ttl_seconds: int = 24 * 3600  # 24 часа

    # SSH (FR-3.1.8, ADR-0002)
    ssh_breaker_reset_seconds: float = 30.0  # время разомкнутого состояния
    ssh_connect_timeout: float = 10.0
    ssh_command_timeout: float = 30.0

    # Учёт трафика (FR-3.5.5): интервал опроса 30–300 с
    accounting_poll_interval: int = 60


_settings: Settings | None = None


def get_settings() -> Settings:
    """Синглтон настроек (инициализация один раз на процесс)."""
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings
