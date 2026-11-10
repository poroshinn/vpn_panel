"""Точка входа FastAPI (FR-3.15.2, FR-3.16.1).

Порядок старта: логгер → БД → миграции → маршруты.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI

from app.core.config import get_settings
from app.core.logging import setup_logging
from app.db.database import Database
from app.db.migrator import apply_migrations

logger = logging.getLogger(__name__)


async def _db_healthy(db: Database) -> bool:
    try:
        await db.fetch_one("SELECT 1")
        return True
    except Exception:  # noqa: BLE001
        return False


@asynccontextmanager
async def lifespan(app: FastAPI):
    setup_logging()
    settings = get_settings()
    Path(settings.db_file).parent.mkdir(parents=True, exist_ok=True)

    db = Database()
    await db.connect()
    version = await apply_migrations(db)
    logger.info("Panel started, schema version %s", version)

    app.state.db = db
    yield
    await db.close()


def create_app() -> FastAPI:
    app = FastAPI(title="Amnezia Web Panel", version="0.1.0", lifespan=lifespan)

    @app.get("/health", tags=["system"])
    async def health() -> dict:
        """Health-check (FR-3.16.1): живость + состояние БД."""
        db: Database = app.state.db
        ok = await _db_healthy(db)
        return {"status": "ok" if ok else "degraded", "database": "up" if ok else "down"}

    return app


app = create_app()
