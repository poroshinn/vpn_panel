"""Общие фикстуры тестов: временная БД, изоляция настроек."""

from __future__ import annotations

from pathlib import Path

import pytest

import app.core.config as config_module


@pytest.fixture
def tmp_data_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Изолированные каталоги данных/логов/бэкапов на тест.

    Сбрасывает кэш синглтона настроек, чтобы env-переменные теста применились:
    get_settings() иначе вернёт настройки, закэшированные предыдущим тестом.
    """
    data = tmp_path / "data"
    logs = tmp_path / "logs"
    backups = tmp_path / "backups"
    for d in (data, logs, backups):
        d.mkdir()
    monkeypatch.setenv("DB_FILE", str(data / "panel.db"))
    monkeypatch.setenv("LOG_DIR", str(logs))
    monkeypatch.setenv("BACKUP_DIR", str(backups))
    monkeypatch.setenv("SECRET_KEY", "test-secret-key")
    # rate-limit не должен срабатывать на тестовом traffic (один IP testclient)
    monkeypatch.setenv("RATE_LIMIT_API_PER_WINDOW", "1000000")
    monkeypatch.setenv("RATE_LIMIT_AUTH_PER_WINDOW", "1000000")
    monkeypatch.setattr(config_module, "_settings", None)
    # сброс синглтона лимитера: окна не должны переживать тесты
    import app.core.rate_limit as rate_limit_module

    monkeypatch.setattr(rate_limit_module, "_limiter", None)
    return data
