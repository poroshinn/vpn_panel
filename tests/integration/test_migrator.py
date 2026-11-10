"""Интеграционные тесты мигратора (MVP-02, FR-3.15.5)."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from app.core.config import get_settings
from app.db.database import Database
from app.db.migrator import MigrationError, apply_migrations, get_schema_version

EXPECTED_TABLES = {
    "schema_version",
    "users",
    "servers",
    "user_connections",
    "settings",
    "api_tokens",
    "audit_log",
    "peer_creations",
    "lifecycle_uncertain",
    "accounting_recoveries",
    "recovery_snapshots",
}


@pytest.fixture
async def db(tmp_data_dir: Path) -> Database:
    database = Database()
    await database.connect()
    yield database
    await database.close()


async def _user_tables(db: Database) -> set[str]:
    rows = await db.fetch_all(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
    )
    return {r["name"] for r in rows}


async def test_apply_from_scratch(db: Database) -> None:
    """Применение с нуля: все таблицы созданы, версия = 1."""
    version = await apply_migrations(db)
    assert version == 1
    assert await get_schema_version(db) == 1
    assert EXPECTED_TABLES <= await _user_tables(db)


async def test_apply_idempotent(db: Database) -> None:
    """Повторное применение — no-op, версия не меняется."""
    assert await apply_migrations(db) == 1
    assert await apply_migrations(db) == 1
    rows = await db.fetch_all("SELECT version FROM schema_version")
    assert [r["version"] for r in rows] == [1]


async def test_pragmas_on_connect(db: Database) -> None:
    """WAL и foreign_keys включены после connect()."""
    assert await db.fetch_one("PRAGMA journal_mode") == {"journal_mode": "wal"}
    assert await db.fetch_one("PRAGMA foreign_keys") == {"foreign_keys": 1}


async def test_pre_migrate_snapshot_created(db: Database, tmp_data_dir: Path) -> None:
    """Перед применением поверх существующей БД создаётся pre-migrate снапшот."""
    # Готовим «существующую» БД без schema_version — мигратор сделает снапшот
    await db.executescript("CREATE TABLE legacy_marker (id INTEGER PRIMARY KEY);")

    assert await apply_migrations(db) == 1

    backup_dir = get_settings().backup_dir / "pre-migrate"
    snapshots = list(backup_dir.glob("pre-migrate-*panel.db"))
    assert snapshots, "pre-migrate snapshot must be created for existing db"


async def test_fresh_db_no_snapshot(db: Database) -> None:
    """На чистой БД снапшот не создаётся (нечего бэкапить)."""
    backup_dir = get_settings().backup_dir / "pre-migrate"
    await apply_migrations(db)
    assert list(backup_dir.glob("pre-migrate-*")) == []


async def test_timestamps_utc_iso(db: Database) -> None:
    """applied_at в schema_version — UTC ISO-8601 (правило 2 AGENTS.md)."""
    await apply_migrations(db)
    row = await db.fetch_one("SELECT applied_at FROM schema_version WHERE version=1")
    assert row["applied_at"].endswith("+00:00")


async def test_unique_migration_ids_rejected(
    db: Database, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Дубли id миграций в наборе — ошибка диагностики, а не тихий сбой."""
    migrations_dir = Path("app/db/migrations")
    dup = migrations_dir / "9999_dup_test.py"
    dup.write_text(
        'MIGRATION_ID = 1\nDESCRIPTION = "dup"\nSQL = ""\n', encoding="utf-8"
    )
    try:
        # сбросить кэш импорта не нужен: модуль новый
        with pytest.raises(MigrationError, match="Duplicate migration id"):
            from app.db import migrator

            migrator._discover_migrations()
    finally:
        dup.unlink(missing_ok=True)


async def test_failed_migration_raises(tmp_data_dir: Path) -> None:
    """Сбой миграции ⇒ MigrationError с диагностикой, БД не переводится дальше."""
    from app.db import migrator

    database = Database()
    await database.connect()
    try:
        original = migrator._discover_migrations

        def broken():
            result = original()
            return [
                migrator.Migration(m.migration_id, m.description, "CREATE BROKEN SQL;")
                for m in result
            ]

        monkey_like = broken
        migrator._discover_migrations = monkey_like  # type: ignore[assignment]
        with pytest.raises(MigrationError, match="failed"):
            await migrator.apply_migrations(database)
        # версия не должна была записаться
        assert await get_schema_version(database) == 0
    finally:
        migrator._discover_migrations = original  # type: ignore[assignment]
        await database.close()


async def test_foreign_keys_enforced(db: Database) -> None:
    """FK-ограничения реально работают (PRAGMA foreign_keys=ON)."""
    await apply_migrations(db)
    with pytest.raises(sqlite3.IntegrityError):
        await db.execute(
            "INSERT INTO user_connections (user_id, server_id, protocol, client_id,"
            " name, created_at) VALUES (999, 1, 'awg', 'c1', 'n', '2026-01-01')"
        )
