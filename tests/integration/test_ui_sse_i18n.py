"""Integration-тесты MVP-09: SSE-роутер, i18n-страницы, /my, robots/noindex.

- SSE: без сессии 401; поведение хаба — в tests/unit/test_sse_hub.py
  (httpx ASGITransport буферизует ответ, бесконечный поток не читается);
- i18n: ru-страница при cookie, en по умолчанию;
- /my: user видит свои подключения; аноним → redirect на /login;
- noindex/robots (FR-3.13.10).
"""

from __future__ import annotations

from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient

pytestmark = pytest.mark.asyncio


def _new_client(app: Any) -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


async def _login_admin(ac: Any) -> None:
    resp = await ac.post(
        "/api/auth/login",
        json={"username": "admin", "password": "admin"},
        headers={"X-Test-Client-IP": "10.0.0.21"},
    )
    assert resp.status_code == 200, resp.text


async def _create_user(ac: Any, username: str, password: str) -> int:
    resp = await ac.post(
        "/api/v1/users",
        json={"username": username, "role": "user", "password": password},
        headers={"X-Test-Client-IP": "10.0.0.21"},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


# --------------------------------------------------------------------- SSE


async def test_sse_requires_session(client: Any) -> None:
    resp = await client.get("/api/v1/events")
    assert resp.status_code == 401


# --------------------------------------------------------------------- i18n


async def test_dashboard_default_english(client: Any) -> None:
    await _login_admin(client)
    resp = await client.get("/")
    assert resp.status_code == 200
    assert "Servers" in resp.text


async def test_dashboard_ru_via_cookie(client: Any) -> None:
    await _login_admin(client)
    client.cookies.set("awp_lang", "ru")
    resp = await client.get("/")
    assert resp.status_code == 200
    assert "Серверы" in resp.text
    assert "Серверов пока нет" in resp.text


async def test_ru_accept_language(client: Any) -> None:
    await _login_admin(client)
    resp = await client.get("/", headers={"Accept-Language": "ru-RU,ru;q=0.9"})
    assert resp.status_code == 200
    assert "Серверы" in resp.text


# --------------------------------------------------------------------- /my


async def test_my_page_requires_login(client: Any) -> None:
    resp = await client.get("/my", follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["location"] == "/login"


async def test_my_page_shows_only_own_connections(client: Any, db: Any) -> None:
    """user видит свои подключения; admin — свои (пусто)."""
    await _login_admin(client)
    uid = await _create_user(client, "connuser", "conn-pass-1")

    resp = await client.post(
        "/api/v1/servers",
        json={"name": "srv-ui", "host": "203.0.113.50", "ssh_port": 22,
              "username": "root", "password": "secret"},
        headers={"X-Test-Client-IP": "10.0.0.21"},
    )
    assert resp.status_code == 201, resp.text
    server_id = resp.json()["id"]
    # подключение вставляем напрямую (инстанс не установлен — SSH не нужен)
    await db.execute(
        "INSERT INTO user_connections (user_id, server_id, protocol, client_id,"
        " name, created_at, counters_json) VALUES (?, ?, 'awg2', 'c1', 'phone',"
        " '2026-11-11T00:00:00+00:00', '{}')",
        (uid, server_id),
    )

    async with _new_client(client.app) as ac2:
        resp = await ac2.post(
            "/api/auth/login",
            json={"username": "connuser", "password": "conn-pass-1"},
            headers={"X-Test-Client-IP": "10.0.0.22"},
        )
        assert resp.status_code == 200, resp.text
        resp = await ac2.get("/my")
        assert resp.status_code == 200
        assert "phone" in resp.text

    # admin: своих подключений нет → пустая страница
    resp = await client.get("/my")
    assert resp.status_code == 200
    assert "phone" not in resp.text


async def test_config_access_denied_for_other_user(client: Any, db: Any) -> None:
    """Чужой user не может получить конфиг не-своего подключения (403)."""
    await _login_admin(client)
    uid = await _create_user(client, "owner1", "owner-pass-1")
    resp = await client.post(
        "/api/v1/servers",
        json={"name": "srv-cfg", "host": "203.0.113.51", "ssh_port": 22,
              "username": "root", "password": "secret"},
        headers={"X-Test-Client-IP": "10.0.0.21"},
    )
    server_id = resp.json()["id"]
    conn_id = await db.execute(
        "INSERT INTO user_connections (user_id, server_id, protocol, client_id,"
        " name, created_at, counters_json) VALUES (?, ?, 'awg2', 'c1', 'x',"
        " '2026-11-11T00:00:00+00:00', '{}')",
        (uid, server_id),
    )
    await _create_user(client, "other1", "other-pass-1")

    async with _new_client(client.app) as ac2:
        resp = await ac2.post(
            "/api/auth/login",
            json={"username": "other1", "password": "other-pass-1"},
            headers={"X-Test-Client-IP": "10.0.0.23"},
        )
        assert resp.status_code == 200
        resp = await ac2.get(
            f"/api/v1/servers/{server_id}/connections/{conn_id}/config"
        )
        assert resp.status_code == 403


# ------------------------------------------------------- noindex / robots


async def test_robots_disallow_all(client: Any) -> None:
    resp = await client.get("/robots.txt")
    assert resp.status_code == 200
    assert "Disallow: /" in resp.text


async def test_pages_have_noindex_meta(client: Any) -> None:
    await _login_admin(client)
    for path in ("/", "/my", "/settings", "/login"):
        resp = await client.get(path)
        assert resp.status_code == 200, path
        assert "noindex" in resp.text, path


async def test_static_cache_policy(client: Any) -> None:
    resp = await client.get("/static/panel.css")
    assert resp.status_code == 200
    assert "max-age" in resp.headers.get("cache-control", "")


# --------------------------------------------------------------- settings


async def test_settings_page_tabs(client: Any) -> None:
    await _login_admin(client)
    resp = await client.get("/settings")
    assert resp.status_code == 200
    assert "tab-captcha" in resp.text
    assert "tab-backups" in resp.text
    assert "tab-alerts" in resp.text


async def test_settings_redirect_anonymous(client: Any) -> None:
    resp = await client.get("/settings", follow_redirects=False)
    assert resp.status_code == 302
