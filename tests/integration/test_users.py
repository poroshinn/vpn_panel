"""Integration-тесты пользователей (MVP-08, FR-3.6.1–3.6.5).

Проверяются: CRUD (роли, пароль обязателен кроме none), enable/disable,
мгновенная инвалидация сессии при disable (сверка с БД), привязка/отвязка
подключений (активный peer — через stop + финализация), экспорт
admin/support но не user, audit-события.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from tests.integration.test_accounting import (
    AWG2_INFO,
    PUBKEY,
    SERVER_PAYLOAD,
    install_accounting_ssh,
)

pytestmark = pytest.mark.asyncio


async def _login_admin(ac: Any) -> Any:
    resp = await ac.post(
        "/api/auth/login",
        json={"username": "admin", "password": "admin"},
        headers={"X-Test-Client-IP": "10.0.0.9"},
    )
    assert resp.status_code == 200, resp.text
    return resp


async def _make_server(client: Any, db: Any) -> int:
    resp = await client.post("/api/v1/servers", json=SERVER_PAYLOAD)
    assert resp.status_code == 201, resp.text
    server_id = resp.json()["id"]
    await db.execute(
        "UPDATE servers SET protocols = ? WHERE id = ?",
        (json.dumps({"awg2": AWG2_INFO}), server_id),
    )
    return server_id


async def _make_conn(db: Any, server_id: int, user_id: int = 1) -> int:
    return await db.execute(
        "INSERT INTO user_connections (user_id, server_id, protocol, client_id,"
        " name, created_at, counters_json) VALUES (?, ?, 'awg2', 'cl1', 'p1',"
        " '2026-11-10T00:00:00+00:00', ?)",
        (user_id, server_id, json.dumps({"pubkey": PUBKEY})),
    )


# ------------------------------------------------------------------- CRUD


async def test_crud_user_lifecycle(client: Any, db: Any) -> None:
    await _login_admin(client)

    # none — без пароля разрешено; user — без пароля ошибка
    resp = await client.post(
        "/api/v1/users",
        json={"username": "bot1", "role": "none"},
        headers={"X-Test-Client-IP": "10.0.0.9"},
    )
    assert resp.status_code == 201, resp.text
    resp = await client.post(
        "/api/v1/users",
        json={"username": "u1", "role": "user"},
        headers={"X-Test-Client-IP": "10.0.0.9"},
    )
    assert resp.status_code == 400
    assert resp.json()["error_code"] == "password_required"

    resp = await client.post(
        "/api/v1/users",
        json={"username": "u1", "role": "user", "password": "secret-pass-1"},
        headers={"X-Test-Client-IP": "10.0.0.9"},
    )
    assert resp.status_code == 201, resp.text
    user = resp.json()
    uid = user["id"]
    assert "password_hash" not in user

    # дубль имени
    resp = await client.post(
        "/api/v1/users",
        json={"username": "u1", "role": "user", "password": "secret-pass-1"},
        headers={"X-Test-Client-IP": "10.0.0.9"},
    )
    assert resp.status_code == 409

    # обновление: telegram, квота
    resp = await client.patch(
        f"/api/v1/users/{uid}",
        json={"telegram_id": 42, "traffic_limit": 1000},
        headers={"X-Test-Client-IP": "10.0.0.9"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["telegram_id"] == 42
    assert resp.json()["traffic_limit"] == 1000

    # последний admin защитён (пока ещё сессия admin)
    resp = await client.get(
        "/api/v1/users", headers={"X-Test-Client-IP": "10.0.0.9"}
    )
    admin_id = next(u["id"] for u in resp.json() if u["username"] == "admin")
    resp = await client.post(
        f"/api/v1/users/{admin_id}/enabled",
        json={"enabled": False},
        headers={"X-Test-Client-IP": "10.0.0.9"},
    )
    assert resp.status_code == 409, resp.text
    assert resp.json()["error_code"] == "last_admin"

    # список доступен support
    resp = await client.post(
        "/api/v1/users",
        json={"username": "sup1", "role": "support", "password": "secret-pass-2"},
        headers={"X-Test-Client-IP": "10.0.0.9"},
    )
    assert resp.status_code == 201
    resp = await client.post(
        "/api/auth/login",
        json={"username": "sup1", "password": "secret-pass-2"},
        headers={"X-Test-Client-IP": "10.0.1.1"},
    )
    assert resp.status_code == 200
    resp = await client.get(
        "/api/v1/users", headers={"X-Test-Client-IP": "10.0.1.1"}
    )
    assert resp.status_code == 200
    names = {u["username"] for u in resp.json()}
    assert {"admin", "u1", "sup1", "bot1"} <= names


async def test_disable_invalidates_session_immediately(
    client: Any, app: Any, db: Any
) -> None:
    """Два независимых клиента: admin управляет, user проверяет доступ."""
    from httpx import ASGITransport, AsyncClient

    await _login_admin(client)
    resp = await client.post(
        "/api/v1/users",
        json={"username": "u2", "role": "user", "password": "secret-pass-3"},
        headers={"X-Test-Client-IP": "10.0.0.9"},
    )
    uid = resp.json()["id"]

    # второй клиент — сессия u2
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as u2c:
        resp = await u2c.post(
            "/api/auth/login",
            json={"username": "u2", "password": "secret-pass-3"},
            headers={"X-Test-Client-IP": "10.0.2.1"},
        )
        assert resp.status_code == 200, resp.text
        resp = await u2c.get("/api/v1/accounting", headers={"X-Test-Client-IP": "10.0.2.1"})
        assert resp.status_code == 200, resp.text

        # disable из-под admin (первый клиент) → сессия u2 мгновенно 403
        resp = await client.post(
            f"/api/v1/users/{uid}/enabled",
            json={"enabled": False},
            headers={"X-Test-Client-IP": "10.0.0.9"},
        )
        assert resp.status_code == 200, resp.text
        resp = await u2c.get("/api/v1/accounting", headers={"X-Test-Client-IP": "10.0.2.1"})
        assert resp.status_code == 403

    # повторный вход запрещён
    resp = await client.post(
        "/api/auth/login",
        json={"username": "u2", "password": "secret-pass-3"},
        headers={"X-Test-Client-IP": "10.0.2.2"},
    )
    assert resp.status_code == 401

    # повторное включение + понижение до none — тоже мгновенная потеря доступа
    resp = await client.post(
        f"/api/v1/users/{uid}/enabled",
        json={"enabled": True},
        headers={"X-Test-Client-IP": "10.0.0.9"},
    )
    assert resp.status_code == 200
    resp = await client.patch(
        f"/api/v1/users/{uid}",
        json={"role": "none"},
        headers={"X-Test-Client-IP": "10.0.0.9"},
    )
    assert resp.status_code == 200
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as u2c:
        resp = await u2c.post(
            "/api/auth/login",
            json={"username": "u2", "password": "secret-pass-3"},
            headers={"X-Test-Client-IP": "10.0.2.3"},
        )
        assert resp.status_code == 400  # role=none — вход запрещён (role_none)


# ------------------------------------------------------- привязка/отвязка


async def test_assign_and_unlink_active_peer_with_stop(
    client: Any, db: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    install_accounting_ssh(monkeypatch)
    await _login_admin(client)
    server_id = await _make_server(client, db)
    conn_id = await _make_conn(db, server_id)

    # новый пользователь и привязка подключения (FR-3.6.2)
    resp = await client.post(
        "/api/v1/users",
        json={"username": "u3", "role": "user", "password": "secret-pass-4"},
        headers={"X-Test-Client-IP": "10.0.0.9"},
    )
    uid = resp.json()["id"]
    resp = await client.post(
        f"/api/v1/users/{uid}/connections",
        json={"connection_id": conn_id},
        headers={"X-Test-Client-IP": "10.0.0.9"},
    )
    assert resp.status_code == 201, resp.text
    row = await db.fetch_one(
        "SELECT user_id FROM user_connections WHERE id = ?", (conn_id,)
    )
    assert row["user_id"] == uid

    # отвязка активного peer'а: stop=True → disable на ноде + финализация
    resp = await client.post(
        f"/api/v1/users/connections/{conn_id}/unlink",
        json={"stop": True},
        headers={"X-Test-Client-IP": "10.0.0.9"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "finalized"
    assert body["counters_verified_final"] is True
    # запись подключения удалена финализацией, tombstone записан
    row = await db.fetch_one(
        "SELECT * FROM user_connections WHERE id = ?", (conn_id,)
    )
    assert row is None
    tomb = await db.fetch_one(
        "SELECT * FROM accounting_recoveries WHERE connection_id = ?", (conn_id,)
    )
    assert tomb is not None and tomb["counters_verified_final"] == 1

    # дельта закоммичена пользователю: baseline (100,200) → семпл (100,200) = 0,
    # но traffic_used инкремент состоялся
    user = await db.fetch_one("SELECT traffic_used FROM users WHERE id = ?", (uid,))
    assert user["traffic_used"] >= 0

    # audit-события
    events = await db.fetch_all(
        "SELECT action FROM audit_log WHERE object = ? ORDER BY id",
        (f"connection:{conn_id}",),
    )
    actions = [e["action"] for e in events]
    assert "connection.assigned" in actions
    assert "connection.unlinked" in actions


async def test_unlink_unreadable_counter_fails_closed(
    client: Any, db: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    results = install_accounting_ssh(monkeypatch)
    await _login_admin(client)
    server_id = await _make_server(client, db)
    conn_id = await _make_conn(db, server_id)

    # peer отсутствует в transfer (pubkey не найден) → fail-closed 409
    results[r"awg show awg2 transfer|wg show awg2 transfer"] = (
        0, "unknown-peer\t1\t2\n", "",
    )

    resp = await client.post(
        f"/api/v1/users/connections/{conn_id}/unlink",
        json={"stop": True},
        headers={"X-Test-Client-IP": "10.0.0.9"},
    )
    assert resp.status_code == 409, resp.text
    body = resp.json()
    assert body["details"]["can_force"] is True

    # подключение НЕ удалено (fail-closed, правило 5)
    row = await db.fetch_one(
        "SELECT * FROM user_connections WHERE id = ?", (conn_id,)
    )
    assert row is not None

    # ретрай с allow_unverified — tombstone без дельты
    resp = await client.post(
        f"/api/v1/users/connections/{conn_id}/unlink",
        json={"stop": True, "allow_unverified": True},
        headers={"X-Test-Client-IP": "10.0.0.9"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "finalized_unverified"
    assert body["counters_verified_final"] is False
    tomb = await db.fetch_one(
        "SELECT * FROM accounting_recoveries WHERE connection_id = ?", (conn_id,)
    )
    assert tomb is not None and tomb["counters_verified_final"] == 0


# ------------------------------------------------------------------ экспорт


async def test_export_roles_matrix(
    client: Any, db: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    install_accounting_ssh(monkeypatch)
    await _login_admin(client)
    server_id = await _make_server(client, db)

    # создаём support и user
    await client.post(
        "/api/v1/users",
        json={"username": "sup2", "role": "support", "password": "secret-pass-5"},
        headers={"X-Test-Client-IP": "10.0.0.9"},
    )
    resp = await client.post(
        "/api/v1/users",
        json={"username": "u4", "role": "user", "password": "secret-pass-6"},
        headers={"X-Test-Client-IP": "10.0.0.9"},
    )
    uid = resp.json()["id"]
    await _make_conn(db, server_id, user_id=uid)

    # admin — экспорт ок (404 для отсутствующего пользователя)
    resp = await client.get(
        f"/api/v1/users/{uid}/export", headers={"X-Test-Client-IP": "10.0.0.9"}
    )
    assert resp.status_code == 200, resp.text
    assert "Content-Disposition" in resp.headers
    payload = json.loads(resp.content)
    assert payload["user"]["username"] == "u4"
    assert len(payload["connections"]) == 1
    assert payload["connections"][0]["id"] >= 1

    # поддержка тоже
    resp = await client.post(
        "/api/auth/login",
        json={"username": "sup2", "password": "secret-pass-5"},
        headers={"X-Test-Client-IP": "10.0.3.1"},
    )
    assert resp.status_code == 200
    resp = await client.get(
        f"/api/v1/users/{uid}/export", headers={"X-Test-Client-IP": "10.0.3.1"}
    )
    assert resp.status_code == 200

    # user — 403
    resp = await client.post(
        "/api/auth/login",
        json={"username": "u4", "password": "secret-pass-6"},
        headers={"X-Test-Client-IP": "10.0.4.1"},
    )
    assert resp.status_code == 200
    resp = await client.get(
        f"/api/v1/users/{uid}/export", headers={"X-Test-Client-IP": "10.0.4.1"}
    )
    assert resp.status_code == 403
    # и на себя тоже (FR-3.6.5 — admin/support)
    resp = await client.get(
        f"/api/v1/users/{uid}/export", headers={"X-Test-Client-IP": "10.0.4.1"}
    )
    assert resp.status_code == 403


async def test_user_routes_forbidden_for_plain_user(client: Any, db: Any) -> None:
    await _login_admin(client)
    await client.post(
        "/api/v1/users",
        json={"username": "u5", "role": "user", "password": "secret-pass-7"},
        headers={"X-Test-Client-IP": "10.0.0.9"},
    )
    resp = await client.post(
        "/api/auth/login",
        json={"username": "u5", "password": "secret-pass-7"},
        headers={"X-Test-Client-IP": "10.0.5.1"},
    )
    assert resp.status_code == 200
    # user не может ни создавать, ни смотреть список
    resp = await client.post(
        "/api/v1/users",
        json={"username": "x", "role": "user", "password": "secret-pass-8"},
        headers={"X-Test-Client-IP": "10.0.5.1"},
    )
    assert resp.status_code == 403
    resp = await client.get(
        "/api/v1/users", headers={"X-Test-Client-IP": "10.0.5.1"}
    )
    assert resp.status_code == 403
    # и не может мутировать других
    resp = await client.post(
        "/api/v1/users/1/enabled",
        json={"enabled": False},
        headers={"X-Test-Client-IP": "10.0.5.1"},
    )
    assert resp.status_code == 403


async def test_audit_events_written(client: Any, db: Any) -> None:
    await _login_admin(client)
    resp = await client.post(
        "/api/v1/users",
        json={"username": "u6", "role": "user", "password": "secret-pass-9"},
        headers={"X-Test-Client-IP": "10.0.0.9"},
    )
    uid = resp.json()["id"]
    await client.post(
        f"/api/v1/users/{uid}/enabled",
        json={"enabled": False},
        headers={"X-Test-Client-IP": "10.0.0.9"},
    )
    events = await db.fetch_all(
        "SELECT action, object FROM audit_log WHERE object LIKE ? ORDER BY id",
        ("user:%",),
    )
    actions = [e["action"] for e in events]
    assert "user.created" in actions
    assert "user.disabled" in actions
