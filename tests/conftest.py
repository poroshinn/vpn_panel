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
    monkeypatch.setattr(config_module, "_settings", None)
    return data
