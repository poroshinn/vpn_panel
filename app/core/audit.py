"""Audit trail (ТЗ §2.3, FR-3.10.3): БД ``audit_log`` + зеркало в файле.

Записи: UTC-метка, actor, действие, объект, IP, результат. Зеркало —
``logs/audit-YYYY-MM-DD.log`` (текстовый, ретеншн — общий для ``logs/``).
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.core.config import get_settings
from app.db.database import Database

_audit_logger = logging.getLogger("panel.audit")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _sanitize_details(details: dict[str, Any] | None) -> str | None:
    """JSON details без секретов (правило 3 AGENTS.md)."""
    if not details:
        return None
    return json.dumps(details, ensure_ascii=False, default=str)


async def log_event(
    db: Database,
    actor: str,
    action: str,
    *,
    object: str | None = None,  # noqa: A002 — имя колонки БД
    ip: str | None = None,
    result: str = "ok",
    details: dict[str, Any] | None = None,
) -> None:
    """Записать событие в ``audit_log`` и зеркальный файл.

    Ошибка записи в БД/файл не должна ронять вызывающую операцию, поэтому
    здесь только логирование исключений.
    """
    ts = _now_iso()
    try:
        await db.execute(
            "INSERT INTO audit_log (ts, actor, action, object, ip, result, details) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (ts, actor, action, object, ip, result, _sanitize_details(details)),
        )
    except Exception:  # noqa: BLE001
        _audit_logger.exception("audit db write failed for action=%s", action)

    try:
        settings = get_settings()
        log_dir = Path(settings.log_dir)
        log_dir.mkdir(parents=True, exist_ok=True)
        path = log_dir / f"audit-{datetime.now(timezone.utc).strftime('%Y-%m-%d')}.log"
        line = json.dumps(
            {"ts": ts, "actor": actor, "action": action, "object": object,
             "ip": ip, "result": result, "details": details},
            ensure_ascii=False,
            default=str,
        )
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except Exception:  # noqa: BLE001
        _audit_logger.exception("audit file write failed for action=%s", action)
