"""Встроенный мигратор схемы (FR-3.15.5).

Только forward; перед применением — pre-migrate снапшот БД в ``backups/pre-migrate/``.
Сбой миграции ⇒ панель не стартует с понятной диагностикой (ТЗ §8.4).
"""

from __future__ import annotations

import logging
import shutil
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from app.core.config import get_settings
from app.db.database import Database

logger = logging.getLogger(__name__)


class MigrationError(RuntimeError):
    """Ошибка применения миграции — панель не стартует."""


def _discover_migrations() -> list[tuple[int, str, str]]:
    """Возвращает [(id, description, sql)] из app/db/migrations/NNNN_*.py, отсортированно."""
    import importlib

    migrations_dir = Path(__file__).parent / "migrations"
    found: list[tuple[int, str, str]] = []
    for path in sorted(migrations_dir.glob("*.py")):
        if path.name.startswith("_"):
            continue
        module = importlib.import_module(f"app.db.migrations.{path.stem}")
        found.append((module.MIGRATION_ID, module.DESCRIPTION, module.SQL))
    found.sort(key=lambda item: item[0])
    return found


def _pre_migrate_snapshot(db_path: Path) -> Path | None:
    """Pre-migrate снапшот (правило 7 AGENTS.md). Возвращает путь или None, если БД нет."""
    if not db_path.exists():
        return None
    backup_dir = Path(get_settings().backup_dir) / "pre-migrate"
    backup_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    target = backup_dir / f"pre-migrate-{stamp}-v{db_path.name}"
    shutil.copy2(db_path, target)
    logger.info("Pre-migrate snapshot created: %s", target)
    return target


async def apply_migrations(db: Database) -> int:
    """Применяет все неоткатываемые (forward) миграции. Возвращает текущую версию схемы."""
    db_path = Path(get_settings().db_file)
    migrations = _discover_migrations()

    current = 0
    try:
        row = await db.fetch_one("SELECT MAX(version) AS v FROM schema_version")
        current = int(row["v"] or 0) if row else 0
    except sqlite3.OperationalError:
        # Таблицы ещё нет — чистая БД
        current = 0

    pending = [m for m in migrations if m[0] > current]
    if not pending:
        return current

    _pre_migrate_snapshot(db_path)

    for migration_id, description, sql in pending:
        logger.info("Applying migration %s: %s", migration_id, description)
        try:
            await db.executescript(sql)
            await db.execute(
                "INSERT INTO schema_version (version, applied_at) VALUES (?, ?)",
                (
                    migration_id,
                    datetime.now(timezone.utc).isoformat(timespec="seconds"),
                ),
            )
        except Exception as exc:  # noqa: BLE001 — fail-fast при старте
            raise MigrationError(f"Migration {migration_id} failed: {exc}") from exc

    return max(m[0] for m in migrations)
