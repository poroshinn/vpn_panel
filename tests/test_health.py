"""Integration: /health (FR-3.16.1, MVP-01)."""

from __future__ import annotations

from fastapi.testclient import TestClient


def test_health_ok(tmp_data_dir) -> None:
    from app.main import create_app

    app = create_app()
    with TestClient(app) as client:
        resp = client.get("/health")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "ok"
        assert body["database"] == "up"
