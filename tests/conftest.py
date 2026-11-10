"""Общие фикстуры тестов: временная БД, изоляция настроек."""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture
def tmp_data_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Изолированные каталоги данных/логов/бэкапов на тест."""
    data = tmp_path / "data"
    logs = tmp_path / "logs"
    backups = tmp_path / "backups"
    for d in (data, logs, backups):
        d.mkdir()
    monkeypatch.setenv("DB_FILE", str(data / "panel.db"))
    monkeypatch.setenv("LOG_DIR", str(logs))
    monkeypatch.setenv("BACKUP_DIR", str(backups))
    monkeypatch.setenv("SECRET_KEY", "test-secret-key")
    return data
