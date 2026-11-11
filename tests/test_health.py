"""Integration: /health (FR-3.16.1, ТЗ §8.8)."""

from __future__ import annotations

from fastapi.testclient import TestClient

# IP тест-клиента (TestClient использует "testclient" — не входит в allowlist),
# поэтому allowlist расширяем на его адрес и проверяем статусы явнымEnv-override'ом.


def test_health_ok(tmp_data_dir, monkeypatch) -> None:
    monkeypatch.setenv("HEALTH_ALLOWLIST", "127.0.0.0/8,::1,testclient")
    from app.main import create_app

    app = create_app()
    with TestClient(app) as client:
        resp = client.get("/health")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "ok"
        assert body["database"] == "up"


def test_health_denied_for_foreign_ip(tmp_data_dir, monkeypatch) -> None:
    """IP вне allowlist → 404 (эндпоинт скрыт, §8.8)."""
    from app.main import create_app

    app = create_app()
    with TestClient(app) as client:
        # без env-override "testclient" не входит в дефолтный allowlist
        monkeypatch.delenv("HEALTH_ALLOWLIST", raising=False)
        # пересоздаём приложение в новом env уже не нужно: allowlist читается
        # на каждый запрос
        resp = client.get("/health")
        assert resp.status_code == 404


def test_health_503_when_db_down(tmp_data_dir, monkeypatch) -> None:
    """БД остановлена ⇒ 503 (§8.8)."""
    monkeypatch.setenv("HEALTH_ALLOWLIST", "testclient")
    from app.main import create_app

    app = create_app()
    with TestClient(app) as client:
        # имитируем остановленную БД: закрываем соединение
        import asyncio

        asyncio.get_event_loop_policy()
        app.state._loop = None  # noqa: SLF001 — только для сигнатуры теста
        client.app.state.db._conn = None  # noqa: SLF001 — имитация останова
        resp = client.get("/health")
        assert resp.status_code == 503
        assert resp.json()["database"] == "down"
