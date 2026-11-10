"""Интеграционные тесты auth: вход/выход, первый admin, смена пароля, сессии."""

from __future__ import annotations

import pytest

from app.core.security import hash_password


@pytest.fixture
def _clean_bruteforce():
    """Изоляция процессно-локального brute-force стора между тестами."""
    from app.api.routes.auth import _service

    _service._clear()
    yield
    _service._clear()


@pytest.fixture(name="login")
def _login_fixture(client):
    from tests.integration.conftest import make_login

    return make_login(client)


@pytest.mark.usefixtures("_clean_bruteforce")
async def test_first_login_creates_admin(client, db, login) -> None:
    """admin/admin при пустой БД → сессия, флаг обязательной смены пароля."""
    resp = await login("admin", "admin")
    assert resp.status_code == 200
    data = resp.json()
    assert data["username"] == "admin"
    assert data["role"] == "admin"
    assert data["must_change_password"] is True
    assert "awp_session" in resp.cookies


@pytest.mark.usefixtures("_clean_bruteforce")
async def test_login_wrong_password_401(client, db, login) -> None:
    resp = await login("admin", "nope")
    assert resp.status_code == 401
    assert resp.json()["error_code"] == "invalid_username_or_password"


@pytest.mark.usefixtures("_clean_bruteforce")
async def test_me_requires_session(client) -> None:
    resp = await client.get("/api/auth/me")
    assert resp.status_code == 401


@pytest.mark.usefixtures("_clean_bruteforce")
async def test_me_with_session(client, login) -> None:
    resp = await login("admin", "admin")
    me = await client.get("/api/auth/me", headers=_cookie_header(resp, client))
    assert me.status_code == 200
    assert me.json()["role"] == "admin"


@pytest.mark.usefixtures("_clean_bruteforce")
async def test_change_password_and_relogin(client, db, login) -> None:
    resp = await login("admin", "admin")
    headers = _cookie_header(resp, client)
    resp = await client.post(
        "/api/auth/change-password",
        json={"old_password": "admin", "new_password": "new-strong-pass-1"},
        headers=headers,
    )
    assert resp.status_code == 200
    # Старый пароль больше не подходит
    assert (await login("admin", "admin")).status_code == 401
    # Новый — работает
    resp = await login("admin", "new-strong-pass-1")
    assert resp.status_code == 200
    assert resp.json()["must_change_password"] is False


@pytest.mark.usefixtures("_clean_bruteforce")
async def test_logout_invalidates_cookie(client, login) -> None:
    resp = await login("admin", "admin")
    headers = _cookie_header(resp, client)
    logout = await client.post("/api/auth/logout", headers=headers)
    assert logout.status_code == 200
    me = await client.get("/api/auth/me", headers=headers)
    assert me.status_code == 401


@pytest.mark.usefixtures("_clean_bruteforce")
async def test_session_dead_after_disable(client, db, login) -> None:
    """Инвалидация сессии при enabled=false (FR-3.6.4)."""
    resp = await login("admin", "admin")
    headers = _cookie_header(resp, client)
    await db.execute("UPDATE users SET enabled = 0 WHERE username = 'admin'")
    me = await client.get("/api/auth/me", headers=headers)
    assert me.status_code == 403


@pytest.mark.usefixtures("_clean_bruteforce")
async def test_session_dead_after_role_demotion(client, db, login) -> None:
    """Инвалидация сессии при понижении роли (FR-3.6.4, ТЗ §2.3)."""
    resp = await login("admin", "admin")
    headers = _cookie_header(resp, client)
    await db.execute("UPDATE users SET role = 'user' WHERE username = 'admin'")
    me = await client.get("/api/auth/me", headers=headers)
    assert me.status_code == 401  # роль в сессии не совпадает с БД


@pytest.mark.usefixtures("_clean_bruteforce")
async def test_role_none_cannot_login(client, db, login) -> None:
    await db.execute(
        "INSERT INTO users (username, password_hash, role, enabled, disable_reasons, created_at) "
        "VALUES ('ghost', ?, 'none', 1, '[]', '2026-01-01T00:00:00+00:00')",
        (hash_password("pass1234"),),
    )
    resp = await login("ghost", "pass1234")
    assert resp.status_code in (400, 401, 403)
    assert resp.json().get("error_code") in ("role_none", "invalid_username_or_password", "account_disabled")


def _cookie_header(resp, client) -> dict[str, str]:
    """Cookie из Set-Cookie ответа логина → заголовок для последующих запросов."""
    cookie = resp.cookies.get("awp_session")
    assert cookie, f"no session cookie, cookies={resp.cookies}"
    return {"Cookie": f"awp_session={cookie}"}
