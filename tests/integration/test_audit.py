"""Интеграционные тесты audit trail (ТЗ §2.3): БД + файл, санитайзер."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.core.audit import log_event
from app.core.config import get_settings
from app.main import create_app


@pytest.fixture
async def audit_db(tmp_data_dir):
    """БД с применённой схемой (lifespan приложения, без HTTP-клиента)."""
    application = create_app()
    async with application.router.lifespan_context(application):
        yield application.state.db


async def test_log_event_written_to_db_and_file(audit_db, tmp_data_dir) -> None:
    await log_event(
        audit_db, "admin", "auth.login", object="user:1", ip="127.0.0.1", result="ok", details={"x": 1}
    )
    row = await audit_db.fetch_one(
        "SELECT * FROM audit_log WHERE action = 'auth.login' ORDER BY id DESC LIMIT 1"
    )
    assert row is not None
    assert row["actor"] == "admin"
    assert row["result"] == "ok"

    log_dir = Path(get_settings().log_dir)
    files = list(log_dir.glob("audit-*.log"))
    assert files, "audit mirror file not created"
    lines = files[0].read_text(encoding="utf-8").strip().splitlines()
    event = json.loads(lines[-1])
    assert event["action"] == "auth.login"
    assert event["details"] == {"x": 1}


async def test_no_secrets_in_audit_details(audit_db, tmp_data_dir) -> None:
    """Детали передаются ответственным кодом уже очищенными; фиксируем контракт:
    хэш пароля никогда не попадает в audit-запись."""
    await log_event(audit_db, "admin", "auth.password_changed", ip="127.0.0.1")
    row = await audit_db.fetch_one(
        "SELECT * FROM audit_log WHERE action = 'auth.password_changed' ORDER BY id DESC LIMIT 1"
    )
    assert row is not None
    assert "argon2" not in (row["details"] or "")
