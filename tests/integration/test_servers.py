"""Integration-тесты серверов (MVP-05): CRUD, uid, сортировка, онбординг,
роли, audit — на mock-SSH-ноде (mok-paramiko-транспорт из test_ssh_pool).

Онбординг-детекция выполняется против mock-SSH: таблица результатов команд
перезаписывается фикстурой ``fake_ssh``.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

pytestmark = pytest.mark.asyncio

SERVER_PAYLOAD = {
    "name": "node-1",
    "host": "203.0.113.10",
    "ssh_port": 22,
    "username": "root",
    "password": "s3cret-password",
}


async def _login_admin(ac: Any) -> None:
    resp = await ac.post(
        "/api/auth/login",
        json={"username": "admin", "password": "admin"},
        headers={"X-Test-Client-IP": "10.0.0.9"},
    )
    assert resp.status_code == 200, resp.text


@pytest.fixture
def fake_ssh(monkeypatch: pytest.MonkeyPatch) -> dict[str, tuple[int, str, str]]:
    """Тот же mock-транспорт, что и в test_ssh_pool (импорт общий кода)."""
    from tests.integration.test_ssh_pool import install_fake_paramiko  # type: ignore

    return install_fake_paramiko(monkeypatch)


def onboarding_output(containers: dict[str, str], users: list[str]) -> str:
    lines = "\n".join(f"{n}\t{st}" for n, st in containers.items())
    return f"{lines}\n---\n" + "\n".join(users) + "\n"


# ------------------------------------------------------------------- CRUD


async def test_crud_and_uid_stability(
    client: Any, db: Any, fake_ssh: dict
) -> None:
    await _login_admin(client)

    resp = await client.post("/api/v1/servers", json=SERVER_PAYLOAD)
    assert resp.status_code == 201, resp.text
    server = resp.json()
    uid = server["uid"]
    assert len(uid) >= 8
    assert server["auth_type"] == "password"
    # секрет не возвращается
    assert "password" not in server
    assert "s3cret-password" not in json.dumps(server)

    # перечитывание — uid стабилен
    resp = await client.get(f"/api/v1/servers/{server['id']}")
    assert resp.status_code == 200
    assert resp.json()["uid"] == uid

    # список тоже содержит uid и без секретов
    resp = await client.get("/api/v1/servers")
    items = resp.json()["items"]
    assert [s["uid"] for s in items] == [uid]

    # patch меняет имя, но не uid
    resp = await client.patch(
        f"/api/v1/servers/{server['id']}", json={"name": "renamed"}
    )
    assert resp.status_code == 200
    assert resp.json()["uid"] == uid
    assert resp.json()["name"] == "renamed"

    # delete
    resp = await client.delete(f"/api/v1/servers/{server['id']}")
    assert resp.status_code == 200
    resp = await client.get(f"/api/v1/servers/{server['id']}")
    assert resp.status_code == 404


async def test_delete_guard_on_connections(client: Any, db: Any, fake_ssh: dict) -> None:
    await _login_admin(client)
    resp = await client.post("/api/v1/servers", json=SERVER_PAYLOAD)
    server = resp.json()
    server_id = server["id"]

    await db.execute(
        "INSERT INTO user_connections (user_id, server_id, protocol, client_id,"
        " name, created_at) VALUES (1, ?, 'awg', 'c1', 'conn1',"
        " '2026-01-01T00:00:00Z')",
        (server_id,),
    )
    resp = await client.delete(f"/api/v1/servers/{server_id}")
    assert resp.status_code == 409
    assert resp.json()["error_code"] == "server_has_connections"

    resp = await client.delete(f"/api/v1/servers/{server_id}?force=true")
    assert resp.status_code == 200
    conn = await db.fetch_one("SELECT COUNT(*) AS n FROM user_connections")
    assert conn["n"] == 0


async def test_create_requires_credentials(client: Any, fake_ssh: dict) -> None:
    await _login_admin(client)
    resp = await client.post(
        "/api/v1/servers", json={"name": "x", "host": "h", "username": "root"}
    )
    assert resp.status_code == 400
    assert resp.json()["error_code"] == "credentials_required"


# -------------------------------------------------------------- ordering


async def test_reorder_persists(client: Any, fake_ssh: dict) -> None:
    await _login_admin(client)
    uids = []
    for i in range(3):
        resp = await client.post(
            "/api/v1/servers", json={**SERVER_PAYLOAD, "name": f"node-{i}"}
        )
        assert resp.status_code == 201
        uids.append(resp.json()["uid"])

    # исходный порядок совпадает с порядком добавления
    resp = await client.get("/api/v1/servers")
    assert [s["uid"] for s in resp.json()["items"]] == uids

    # переставляем
    new_order = [uids[2], uids[0], uids[1]]
    resp = await client.post("/api/v1/servers/reorder", json={"uids": new_order})
    assert resp.status_code == 200
    assert [s["uid"] for s in resp.json()["items"]] == new_order

    # порядок переживает перечитывание
    resp = await client.get("/api/v1/servers")
    assert [s["uid"] for s in resp.json()["items"]] == new_order

    # неизвестный uid → 400
    resp = await client.post("/api/v1/servers/reorder", json={"uids": ["nope"]})
    assert resp.status_code == 400


# ------------------------------------------------------------- onboarding


async def test_onboarding_detects_containers(
    client: Any, db: Any, fake_ssh: dict
) -> None:
    await _login_admin(client)
    resp = await client.post("/api/v1/servers", json=SERVER_PAYLOAD)
    server = resp.json()
    server_id = server["id"]

    # mock-SSH-ответ онбординг-скрипта: 2 контейнера + пользователи
    containers = {"awg": "running", "awg2": "exited"}
    users = ["alice", "bob"]
    fake_ssh.clear()
    fake_ssh.update({
        # ключ — сама команда ONBOARDING_SCRIPT
        "docker ps -a --format '{{.Names}}\\t{{.State}}' 2>/dev/null || true; "
        "echo '---'; awk -F: '$3 >= 1000 {print $1}' /etc/passwd 2>/dev/null || true": (
            0, onboarding_output(containers, users), ""
        ),
    })
    resp = await client.post(f"/api/v1/servers/{server_id}/verify")
    assert resp.status_code == 200
    report = resp.json()
    assert report["ssh_ok"] is True
    assert report["containers"] == containers

    # детекция сохранена в БД (protocols JSON)
    row = await db.fetch_one("SELECT protocols FROM servers WHERE id = ?", (server_id,))
    assert json.loads(row["protocols"]) == containers


async def test_onboarding_ssh_failure(client: Any, db: Any, fake_ssh: dict) -> None:
    await _login_admin(client)
    resp = await client.post("/api/v1/servers", json=SERVER_PAYLOAD)
    server_id = resp.json()["id"]

    # SSH-команда не отвечает: mock возвращает не 0 для онбординг-команды
    fake_ssh.clear()
    resp = await client.post(f"/api/v1/servers/{server_id}/verify")
    assert resp.status_code == 200
    report = resp.json()
    assert report["ssh_ok"] is False
    assert report["error"]
    # protocols не изменены
    row = await db.fetch_one("SELECT protocols FROM servers WHERE id = ?", (server_id,))
    assert json.loads(row["protocols"]) == {}


# ------------------------------------------------------------------ roles


@pytest.mark.parametrize(
    ("role", "status_create", "status_list"),
    [
        ("support", 403, 200),
        ("user", 403, 403),
    ],
)
async def test_role_matrix(
    client: Any, fake_ssh: dict, role: str, status_create: int, status_list: int
) -> None:
    await _login_admin(client)
    # создаём пользователя с ролью прямым INSERT
    db = client.app.state.db  # type: ignore[attr-defined]
    from app.core.security import hash_password

    await db.execute(
        "INSERT INTO users (username, password_hash, role, enabled, created_at)"
        " VALUES (?, ?, ?, 1, '2026-01-01T00:00:00Z')",
        (f"{role}_u", hash_password("StrongPass1!"), role),
    )
    client.cookies.clear()
    resp = await client.post(
        "/api/auth/login",
        json={"username": f"{role}_u", "password": "StrongPass1!"},
        headers={"X-Test-Client-IP": "10.0.0.8"},
    )
    assert resp.status_code == 200

    resp = await client.post("/api/v1/servers", json=SERVER_PAYLOAD)
    assert resp.status_code == status_create

    resp = await client.get("/api/v1/servers")
    assert resp.status_code == status_list


async def test_anonymous_cannot_delete(client: Any, db: Any, fake_ssh: dict) -> None:
    await _login_admin(client)
    resp = await client.post("/api/v1/servers", json=SERVER_PAYLOAD)
    server_id = resp.json()["id"]
    client.cookies.clear()
    # неаутентифицированный — 401
    resp = await client.delete(f"/api/v1/servers/{server_id}")
    assert resp.status_code == 401


# ------------------------------------------------------------------ audit


async def test_audit_events_created_and_deleted(client: Any, db: Any, fake_ssh: dict) -> None:
    await _login_admin(client)
    resp = await client.post("/api/v1/servers", json=SERVER_PAYLOAD)
    uid = resp.json()["uid"]
    resp = await client.delete(f"/api/v1/servers/{resp.json()['id']}")
    assert resp.status_code == 200

    rows = await db.fetch_all(
        "SELECT action, object FROM audit_log WHERE action LIKE 'server.%' ORDER BY id"
    )
    actions = [r["action"] for r in rows]
    assert "server.create" in actions
    assert "server.delete" in actions
    created = next(r for r in rows if r["action"] == "server.create")
    assert created["object"] == uid
