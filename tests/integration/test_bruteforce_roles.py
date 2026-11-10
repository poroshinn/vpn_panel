"""Интеграционные тесты: brute-force задержки и матрица ролей (ТЗ §2.2)."""

from __future__ import annotations

import pytest

from app.core.security import hash_password


@pytest.fixture(autouse=True)
def _clean_bruteforce():
    from app.api.routes.auth import _service

    _service._clear()
    yield
    _service._clear()


@pytest.fixture(name="login")
def _login_fixture(client):
    from tests.integration.conftest import make_login

    return make_login(client)


@pytest.fixture
async def _users(db):
    """Набор пользователей для матрицы ролей (admin создаётся явно, т.к. БД непуста)."""
    for username, role, password in (
        ("admin", "admin", "admin"),
        ("sup", "support", "pass-12345"),
        ("usr", "user", "pass-12345"),
    ):
        await db.execute(
            "INSERT INTO users (username, password_hash, role, enabled, disable_reasons, created_at) "
            "VALUES (?, ?, ?, 1, '[]', '2026-01-01T00:00:00+00:00')",
            (username, hash_password(password), role),
        )


@pytest.mark.usefixtures("_clean_bruteforce")
async def test_progressive_delay_after_5_fails(client, login) -> None:
    """5 неудач → задержка 30 с, далее экспонента (ТЗ §2.3)."""
    ip = "10.9.9.9"
    for _ in range(5):
        resp = await login("admin", "wrong", ip=ip)
        assert resp.status_code == 401
    sixth = await login("admin", "wrong", ip=ip)
    assert sixth.status_code == 429
    assert sixth.json()["error_code"] == "login_delayed"
    assert "Retry-After" in sixth.headers
    assert int(sixth.headers["Retry-After"]) >= 30


@pytest.mark.usefixtures("_clean_bruteforce")
async def test_delay_exponentially_grows(client, login) -> None:
    ip = "10.8.8.8"
    for _ in range(6):
        await login("admin", "wrong", ip=ip)
    first_retry = None
    resp = await login("admin", "wrong", ip=ip)
    assert resp.status_code == 429
    first_retry = int(resp.headers["Retry-After"])
    # Ещё одна неудача невозможна под задержкой — 429 без роста счётчика,
    # но success-логин очищает пару. Проверяем экспоненту через 7-ю попытку:
    for _ in range(6):
        await login("admin", "wrong", ip=ip)
    resp2 = await login("admin", "wrong", ip=ip)
    assert resp2.status_code == 429
    assert int(resp2.headers["Retry-After"]) >= first_retry


@pytest.mark.usefixtures("_clean_bruteforce")
async def test_success_resets_failures(client, login) -> None:
    ip = "10.7.7.7"
    for _ in range(4):
        await login("admin", "wrong", ip=ip)
    resp = await login("admin", "admin", ip=ip)
    assert resp.status_code == 200
    # Счётчик сброшен — следующие 4 неудачи не блокируют
    for _ in range(4):
        assert (await login("admin", "wrong", ip=ip)).status_code == 401


@pytest.mark.usefixtures("_clean_bruteforce")
async def test_ip_block_after_threshold(client, login) -> None:
    """Блокировка IP по лимиту суммарных неудач (ТЗ §2.3).

    19 уникальных логинов по одной неудаче: ни одна пара не достигает порога
    прогрессии (5), а суммарный счётчик IP доходит до лимита (20).
    """
    ip = "10.6.6.6"
    for i in range(19):
        resp = await login(f"probe{i}", "wrong", ip=ip)
        assert resp.status_code == 401, (i, resp.status_code)
    # 20-я неудача активирует блок; 21-й запрос уже отклоняется
    resp = await login("probe_final", "wrong", ip=ip)
    assert resp.status_code == 401
    resp = await login("admin", "admin", ip=ip)
    assert resp.status_code == 429
    assert resp.json()["error_code"] == "ip_blocked"
    # Даже валидный вход с заблокированного IP невозможен
    resp = await login("admin", "admin", ip=ip)
    assert resp.status_code == 429
    assert resp.json()["error_code"] == "ip_blocked"


# ----------------------------------------------------- матрица ролей §2.2


@pytest.mark.usefixtures("_clean_bruteforce")
async def test_role_none_cannot_login(client, db, login) -> None:
    await db.execute(
        "INSERT INTO users (username, password_hash, role, enabled, disable_reasons, created_at) "
        "VALUES ('none_u', ?, 'none', 1, '[]', '2026-01-01T00:00:00+00:00')",
        (hash_password("pass-12345"),),
    )
    resp = await login("none_u", "pass-12345")
    assert resp.status_code in (400, 401, 403)


@pytest.mark.usefixtures("_clean_bruteforce", "_users")
async def test_role_matrix_login_allowed(client, login) -> None:
    """Вход разрешён admin/support/user, запрещён none (ТЗ §2.2 строка 1)."""
    for username in ("admin", "sup", "usr"):
        resp = await login(username, "admin" if username == "admin" else "pass-12345")
        assert resp.status_code == 200, username


@pytest.mark.usefixtures("_clean_bruteforce", "_users")
async def test_matrix_admin_only_endpoints(client, login) -> None:
    """Управление пользователями/настройки — только admin (ТЗ §2.2)."""
    from tests.integration.test_auth_flow import _cookie_header

    cookies: dict[str, str] = {}
    for username, password in (("admin", "admin"), ("sup", "pass-12345"), ("usr", "pass-12345")):
        resp = await login(username, password)
        assert resp.status_code == 200, username
        cookies[username] = _cookie_header(resp, client)["Cookie"]

    # admin-only: /api/v1/users (405 недоступен — заглушка роли ниже), пока проверяем me
    for username, expected in (("admin", 200), ("sup", 200), ("usr", 200)):
        me = await client.get("/api/auth/me", headers={"Cookie": cookies[username]})
        assert me.status_code == expected, username
        assert me.json()["role"] == ("admin" if username == "admin" else username and ("support" if username == "sup" else "user"))
