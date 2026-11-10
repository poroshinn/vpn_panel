"""Фикстуры интеграционных тестов auth: приложение с чистой БД + httpx-клиент."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from app.db.database import Database
from app.main import create_app


from app.db.migrator import apply_migrations


@pytest.fixture
def app(tmp_data_dir):
    """Свежее приложение; БД подключается при прогоне lifespan в client."""
    return create_app()


@pytest.fixture
async def client(app):
    """ASGI-клиент с ручным прогоном lifespan (init БД + миграции)."""
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            # app доступен тестам через атрибут клиента
            ac.app = app  # type: ignore[attr-defined]
            yield ac


def make_login(ac: AsyncClient):
    """Фабрика логина с уникальными IP для brute-force тестов."""

    async def _do(username: str, password: str, ip: str = "10.0.0.1"):
        return await ac.post(
            "/api/auth/login",
            json={"username": username, "password": password},
            headers={"X-Test-Client-IP": ip},
        )

    return _do


@pytest.fixture
def db(client) -> Database:
    """БД приложения (lifespan клиента уже выполнен — миграции применены)."""
    return client.app.state.db  # type: ignore[attr-defined]
