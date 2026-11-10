"""Тесты конкурентной записи в БД (MVP-02): без «database is locked»."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from app.db.database import Database


@pytest.fixture
async def db(tmp_data_dir: Path) -> Database:
    database = Database()
    await database.connect()
    await database.execute(
        "CREATE TABLE IF NOT EXISTS lock_probe (id INTEGER PRIMARY KEY, n INTEGER NOT NULL)"
    )
    yield database
    await database.close()


async def test_concurrent_writes_no_lock_error(db: Database) -> None:
    """50 конкурентных вставок через один writer-lock — все успешны, без ошибок блокировки."""

    async def write(i: int) -> int:
        return await db.execute("INSERT INTO lock_probe (n) VALUES (?)", (i,))

    results = await asyncio.gather(*(write(i) for i in range(50)))
    assert all(r > 0 for r in results)

    row = await db.fetch_one("SELECT COUNT(*) AS c FROM lock_probe")
    assert row["c"] == 50


async def test_concurrent_transactions_atomic(db: Database) -> None:
    """Транзакции атомарны: откат при исключении не оставляет частичных данных."""

    async def failing_txn() -> None:
        async with db.transaction() as conn:
            await conn.execute("INSERT INTO lock_probe (n) VALUES (111)")
            raise RuntimeError("rollback me")

    with pytest.raises(RuntimeError):
        await failing_txn()

    row = await db.fetch_one("SELECT COUNT(*) AS c FROM lock_probe WHERE n=111")
    assert row["c"] == 0


async def test_transaction_commits(db: Database) -> None:
    async with db.transaction() as conn:
        await conn.execute("INSERT INTO lock_probe (n) VALUES (222)")
    row = await db.fetch_one("SELECT COUNT(*) AS c FROM lock_probe WHERE n=222")
    assert row["c"] == 1


async def test_mixed_readers_and_writers(db: Database) -> None:
    """Параллельные читатели не мешают писателям (WAL)."""

    async def reader() -> None:
        for _ in range(10):
            await db.fetch_one("SELECT COUNT(*) AS c FROM lock_probe")

    async def writer(i: int) -> None:
        await db.execute("INSERT INTO lock_probe (n) VALUES (?)", (i,))

    tasks = [reader() for _ in range(3)] + [writer(i) for i in range(20)]
    await asyncio.gather(*tasks)

    row = await db.fetch_one("SELECT COUNT(*) AS c FROM lock_probe")
    assert row["c"] == 20


async def test_execute_before_connect(tmp_data_dir: Path) -> None:
    """Использование до connect() даёт понятную ошибку, а не segfault."""
    database = Database()
    with pytest.raises(RuntimeError, match="not connected"):
        await database.execute("SELECT 1")
