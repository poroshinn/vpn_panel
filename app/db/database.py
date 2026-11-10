"""Асинхронный доступ к SQLite (FR-3.15.1).

WAL, один writer через ``asyncio.Lock`` (правило 1 AGENTS.md), транзакционная
целостность. Полная реализация — шаг MVP-02.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import aiosqlite

from app.core.config import get_settings


class Database:
    """Обёртка aiosqlite: одно соединение, WAL, блокировка записи на процесс."""

    def __init__(self, path: Path | None = None) -> None:
        self._path = Path(path) if path else Path(get_settings().db_file)
        self._conn: aiosqlite.Connection | None = None
        self._write_lock = asyncio.Lock()

    async def connect(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = await aiosqlite.connect(self._path)
        self._conn.row_factory = aiosqlite.Row
        await self._conn.execute("PRAGMA journal_mode=WAL")
        await self._conn.execute("PRAGMA foreign_keys=ON")
        await self._conn.execute("PRAGMA synchronous=FULL")
        await self._conn.commit()

    async def close(self) -> None:
        if self._conn is not None:
            await self._conn.close()
            self._conn = None

    @property
    def conn(self) -> aiosqlite.Connection:
        if self._conn is None:
            raise RuntimeError("Database is not connected")
        return self._conn

    async def fetch_one(self, query: str, params: tuple = ()) -> dict | None:
        async with self.conn.execute(query, params) as cur:
            row = await cur.fetchone()
            return dict(row) if row else None

    async def fetch_all(self, query: str, params: tuple = ()) -> list[dict]:
        async with self.conn.execute(query, params) as cur:
            return [dict(row) for row in await cur.fetchall()]

    async def execute(self, query: str, params: tuple = ()) -> int:
        """Мутирующий запрос — под writer-lock, с коммитом. Возвращает lastrowid."""
        async with self._write_lock:
            cur = await self.conn.execute(query, params)
            await self.conn.commit()
            return cur.lastrowid or 0

    async def executescript(self, script: str) -> None:
        async with self._write_lock:
            await self.conn.executescript(script)
            await self.conn.commit()
