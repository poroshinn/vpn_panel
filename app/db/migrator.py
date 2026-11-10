"""Встроенный мигратор схемы (FR-3.15.5).

Только forward; перед применением — pre-migrate снапшот БД в ``backups/pre-migrate/``.
Сбой миграции ⇒ панель не стартует с понятной диагностикой (ТЗ §8.4).

Каждая миграция — модуль ``app/db/migrations/NNNN_*.py`` с атрибутами
``MIGRATION_ID`` (int), ``DESCRIPTION`` (str) и ``SQL`` (str). DDL в миграциях
должен быть идемпотентным (``CREATE TABLE IF NOT EXISTS``): если панель упала
между применением DDL и записью версии, повторный старт досчитает безопасно.
"""

from __future__ import annotations

import logging
import shutil
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import NamedTuple

from app.core.config import get_settings
from app.db.database import Database

logger = logging.getLogger(__name__)


class MigrationError(RuntimeError):
    """Ошибка применения миграции — панель не стартует."""


class Migration(NamedTuple):
    migration_id: int
    description: str
    sql: str


def _discover_migrations() -> list[Migration]:
    """Возвращает миграции из app/db/migrations/NNNN_*.py, отсортированные по id."""
    import importlib

    migrations_dir = Path(__file__).parent / "migrations"
    found: list[Migration] = []
    for path in sorted(migrations_dir.glob("*.py")):
        if path.name.startswith("_"):
            continue
        module = importlib.import_module(f"app.db.migrations.{path.stem}")
        found.append(Migration(module.MIGRATION_ID, module.DESCRIPTION, module.SQL))

    found.sort(key=lambda m: m.migration_id)

    # Целостность набора: уникальные положительные id (forward-only допускает
    # пропуски номеров, но не дубли — дубли сломают PRIMARY KEY schema_version).
    seen: set[int] = set()
    for m in found:
        if m.migration_id <= 0:
            raise MigrationError(f"Migration id must be positive: {m.migration_id}")
        if m.migration_id in seen:
            raise MigrationError(f"Duplicate migration id: {m.migration_id}")
        seen.add(m.migration_id)
    return found


async def _pre_migrate_snapshot(db: Database, db_path: Path) -> Path | None:
    """Pre-migrate снапшот (правило 7 AGENTS.md).

    Возвращает путь или None, если снапшот не нужен: файла нет либо БД пустая —
    в ней нет ни одной пользовательской таблицы, бэкапить нечего.
    """
    if not db_path.exists():
        return None
    empty = await db.fetch_one(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' LIMIT 1"
    )
    if empty is None:
        return None
    backup_dir = Path(get_settings().backup_dir) / "pre-migrate"
    backup_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    target = backup_dir / f"pre-migrate-{stamp}-v{db_path.name}"
    shutil.copy2(db_path, target)
    logger.info("Pre-migrate snapshot created: %s", target)
    return target


async def get_schema_version(db: Database) -> int:
    """Текущая версия схемы; 0 — если БД пустая."""
    try:
        row = await db.fetch_one("SELECT MAX(version) AS v FROM schema_version")
        return int(row["v"] or 0) if row else 0
    except sqlite3.OperationalError:
        # Таблицы ещё нет — чистая БД
        return 0


async def apply_migrations(db: Database) -> int:
    """Применяет все forward-миграции поверх текущей версии.

    Возвращает версию схемы после применения. Сбой любой миграции поднимает
    :class:`MigrationError` — вызывающий код (lifespan) обязан прервать старт.
    """
    db_path = Path(get_settings().db_file)
    migrations = _discover_migrations()
    current = await get_schema_version(db)

    pending = [m for m in migrations if m.migration_id > current]
    if not pending:
        return current

    snapshot = await _pre_migrate_snapshot(db, db_path)
    if snapshot is None:
        logger.info("Fresh or empty database at %s — snapshot skipped", db_path)

    for migration in pending:
        logger.info(
            "Applying migration %s: %s", migration.migration_id, migration.description
        )
        try:
            # DDL идемпотентен (IF NOT EXISTS), поэтому сбой на шаге записи версии
            # безопасно ретраится при следующем старте.
            await db.executescript(migration.sql)
            await db.execute(
                "INSERT INTO schema_version (version, applied_at) VALUES (?, ?)",
                (
                    migration.migration_id,
                    datetime.now(timezone.utc).isoformat(timespec="seconds"),
                ),
            )
        except Exception as exc:  # noqa: BLE001 — fail-fast при старте
            raise MigrationError(
                f"Migration {migration.migration_id} ({migration.description}) failed: {exc}. "
                f"Snapshot: {snapshot or 'n/a (fresh db)'}"
            ) from exc

    final = await get_schema_version(db)
    logger.info("Schema migrated to version %s", final)
    return final
