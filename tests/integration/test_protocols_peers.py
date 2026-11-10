"""Integration-тесты протоколов и peers (MVP-06) на mock-SSH-ноде.

Проверяются: установка/удаление инстансов, идемпотентность peer-операций
(повтор ``operation_id`` не создаёт дубликат), неопределённый SSH-исход →
``lifecycle_uncertain`` + ретрай, rename без гонок (параллельные запросы),
audit-события, матрица ролей.

Mock-SSH здесь — wildcard-вариант (ключи-регулярки): команды installer/peers
содержат сгенерированные части (compose, client_id), точное совпадение неудобно.
"""

from __future__ import annotations

import asyncio
import json
import re
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

AWG2_INFO = {
    "preset_id": "awg-2x",
    "protocol": "awg",
    "port": 32898,
    "junk": {"Jc": "4", "S1": "86"},
    "bbr": False,
}


def install_fake_paramiko_wild(
    monkeypatch: pytest.MonkeyPatch,
) -> dict[str, tuple[int, str, str]]:
    """Wildcard-mock paramiko: ключи результатов — regex-паттерны команд."""
    results: dict[str, tuple[int, str, str]] = {}

    import paramiko

    from tests.integration.test_ssh_pool import FakeChannel

    orig_exec = FakeChannel.exec_command

    def exec_command_wild(self: FakeChannel, command: str) -> None:
        for pattern, outcome in results.items():
            if re.search(pattern, command):
                code, out, err = outcome
                self._cmd = command
                self._code = code
                self._stdout = out.encode()
                self._stderr = err.encode()
                return
        orig_exec(self, command)

    monkeypatch.setattr(FakeChannel, "exec_command", exec_command_wild)

    monkeypatch.setattr(paramiko, "SSHClient", *[_client_factory(results)])
    return results


def _client_factory(results: dict[str, tuple[int, str, str]]):
    from tests.integration.test_ssh_pool import FakeTransport

    class FakeClient:
        def __init__(self) -> None:
            self._transport = FakeTransport(results)

        def set_missing_host_key_policy(self, policy: Any) -> None:
            pass

        def connect(self, **kwargs: Any) -> None:
            pass

        def get_transport(self) -> FakeTransport:
            return self._transport

        def close(self) -> None:
            self._transport.active = False

    return FakeClient


@pytest.fixture
def fake_ssh(monkeypatch: pytest.MonkeyPatch) -> dict[str, tuple[int, str, str]]:
    return install_fake_paramiko_wild(monkeypatch)


@pytest.fixture
def success_ssh(fake_ssh: dict[str, tuple[int, str, str]]) -> dict:
    """Mock, где все команды ноды успешны."""
    fake_ssh[r"docker compose up -d"] = (0, "installed\n", "")
    fake_ssh[r"docker-compose up -d"] = (0, "installed\n", "")
    fake_ssh[r"docker compose down -v"] = (0, "removed\n", "")
    fake_ssh[r"awg-pc add"] = (0, "added\n", "")
    fake_ssh[r"awg-pc remove"] = (0, "removed\n", "")
    fake_ssh[r"awg-pc rename"] = (0, "renamed\n", "")
    fake_ssh[r"awg-pc enable"] = (0, "enabled\n", "")
    fake_ssh[r"awg-pc disable"] = (0, "disabled\n", "")
    return fake_ssh


async def _login_admin(ac: Any) -> None:
    resp = await ac.post(
        "/api/auth/login",
        json={"username": "admin", "password": "admin"},
        headers={"X-Test-Client-IP": "10.0.0.9"},
    )
    assert resp.status_code == 200, resp.text


async def _make_server(client: Any, db: Any) -> int:
    """Сервер с предустановленным инстансом awg2."""
    resp = await client.post("/api/v1/servers", json=SERVER_PAYLOAD)
    assert resp.status_code == 201, resp.text
    server_id = resp.json()["id"]
    await db.execute(
        "UPDATE servers SET protocols = ? WHERE id = ?",
        (json.dumps({"awg2": AWG2_INFO}), server_id),
    )
    return server_id


# -------------------------------------------------------------- install


async def test_install_and_uninstall_instance(
    client: Any, db: Any, success_ssh: dict
) -> None:
    await _login_admin(client)
    resp = await client.post("/api/v1/servers", json=SERVER_PAYLOAD)
    server_id = resp.json()["id"]

    resp = await client.post(
        f"/api/v1/servers/{server_id}/protocols",
        json={"preset_id": "awg-2x", "port": 40000},
    )
    assert resp.status_code == 201, resp.text
    data = resp.json()
    assert data["instance"] == "awg2"
    assert data["port"] == 40000

    row = await db.fetch_one("SELECT protocols FROM servers WHERE id = ?", (server_id,))
    protocols = json.loads(row["protocols"])
    assert "awg2" in protocols
    assert protocols["awg2"]["preset_id"] == "awg-2x"

    # мульти-инстанс: второй awg-2x → awg2__2
    resp = await client.post(
        f"/api/v1/servers/{server_id}/protocols", json={"preset_id": "awg-2x"}
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["instance"] == "awg2__2"

    resp = await client.get(f"/api/v1/servers/{server_id}/protocols")
    assert resp.status_code == 200
    names = [i["instance"] for i in resp.json()["items"]]
    assert names == ["awg2", "awg2__2"]

    # удаление
    resp = await client.delete(f"/api/v1/servers/{server_id}/protocols/awg2")
    assert resp.status_code == 200, resp.text
    row = await db.fetch_one("SELECT protocols FROM servers WHERE id = ?", (server_id,))
    assert "awg2" not in json.loads(row["protocols"])

    # удаление несуществующего → 404
    resp = await client.delete(f"/api/v1/servers/{server_id}/protocols/awg2")
    assert resp.status_code == 404


async def test_install_single_instance_guard(
    client: Any, db: Any, success_ssh: dict
) -> None:
    await _login_admin(client)
    server_id = await _make_server(client, db)
    resp = await client.post(
        f"/api/v1/servers/{server_id}/protocols", json={"preset_id": "wg"}
    )
    assert resp.status_code == 201, resp.text
    # повторная установка одиночного протокола → 400
    resp = await client.post(
        f"/api/v1/servers/{server_id}/protocols", json={"preset_id": "wg"}
    )
    assert resp.status_code == 400
    assert resp.json()["error_code"] == "instance_exists"


async def test_install_ssh_failure_records_uncertain(
    client: Any, db: Any, fake_ssh: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SSH-сбой (не exit-код) → неопределённый исход, protocols не тронуты."""
    from app.ssh.pool import SSHError

    await _login_admin(client)
    server_id = await _make_server(client, db)

    pool = client.app.state.ssh_pool

    async def failing_call(*args: Any, **kwargs: Any) -> Any:
        raise SSHError("ssh connect failed")

    monkeypatch.setattr(pool, "call", failing_call)

    resp = await client.post(
        f"/api/v1/servers/{server_id}/protocols", json={"preset_id": "awg-2x"}
    )
    assert resp.status_code == 502, resp.text
    assert resp.json()["error_code"] == "install_uncertain"

    row = await db.fetch_one(
        "SELECT COUNT(*) AS n FROM lifecycle_uncertain WHERE server_id = ?",
        (server_id,),
    )
    assert row["n"] >= 1
    row = await db.fetch_one("SELECT protocols FROM servers WHERE id = ?", (server_id,))
    assert json.loads(row["protocols"]).get("awg2") == AWG2_INFO


# ---------------------------------------------------------------- peers


async def test_create_peer_idempotent_operation_id(
    client: Any, db: Any, success_ssh: dict
) -> None:
    await _login_admin(client)
    server_id = await _make_server(client, db)

    body = {
        "instance": "awg2",
        "user_id": 1,
        "name": "phone",
        "operation_id": "op-fixed-1",
    }
    resp = await client.post(f"/api/v1/servers/{server_id}/connections", json=body)
    assert resp.status_code == 201, resp.text
    peer = resp.json()
    client_id = peer["client_id"]
    assert peer["protocol"] == "awg2"

    # повтор того же operation_id → тот же peer, без дубликата
    resp = await client.post(f"/api/v1/servers/{server_id}/connections", json=body)
    assert resp.status_code == 201, resp.text
    assert resp.json()["client_id"] == client_id

    row = await db.fetch_one(
        "SELECT COUNT(*) AS n FROM user_connections WHERE server_id = ?", (server_id,)
    )
    assert row["n"] == 1
    op = await db.fetch_one(
        "SELECT status FROM peer_creations WHERE operation_id = 'op-fixed-1'"
    )
    assert op["status"] == "done"


async def test_create_peer_ssh_uncertain_then_retry(
    client: Any, db: Any, success_ssh: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SSH-сбой → 502 + lifecycle_uncertain; ретрай завершает операцию."""
    from app.ssh.pool import SSHError

    await _login_admin(client)
    server_id = await _make_server(client, db)
    body = {
        "instance": "awg2", "user_id": 1, "name": "laptop",
        "operation_id": "op-retry-1",
    }

    pool = client.app.state.ssh_pool
    real_call = pool.call

    async def failing_call(*args: Any, **kwargs: Any) -> Any:
        raise SSHError("command failed on node 1")

    monkeypatch.setattr(pool, "call", failing_call)
    resp = await client.post(f"/api/v1/servers/{server_id}/connections", json=body)
    assert resp.status_code == 502, resp.text
    assert resp.json()["error_code"] == "lifecycle_uncertain"

    # «восстанавливаем» SSH: снимаем патч, mock снова отвечает успехом
    monkeypatch.setattr(pool, "call", real_call)

    op = await db.fetch_one(
        "SELECT status FROM peer_creations WHERE operation_id = 'op-retry-1'"
    )
    assert op["status"] == "uncertain"
    row = await db.fetch_one(
        "SELECT COUNT(*) AS n FROM lifecycle_uncertain WHERE operation_id = 'op-retry-1'"
    )
    assert row["n"] == 1

    # ретрай после восстановления SSH (mock снова работает) — дубликатов нет
    resp = await client.post(f"/api/v1/servers/{server_id}/connections", json=body)
    assert resp.status_code == 201, resp.text
    op = await db.fetch_one(
        "SELECT status FROM peer_creations WHERE operation_id = 'op-retry-1'"
    )
    assert op["status"] == "done"


async def test_rename_no_races(client: Any, db: Any, success_ssh: dict) -> None:
    await _login_admin(client)
    server_id = await _make_server(client, db)
    resp = await client.post(
        f"/api/v1/servers/{server_id}/connections",
        json={"instance": "awg2", "user_id": 1, "name": "p0"},
    )
    conn_id = resp.json()["id"]

    results = await asyncio.gather(
        client.patch(
            f"/api/v1/servers/{server_id}/connections/{conn_id}", json={"name": "n1"}
        ),
        client.patch(
            f"/api/v1/servers/{server_id}/connections/{conn_id}", json={"name": "n2"}
        ),
    )
    assert all(r.status_code == 200 for r in results), [r.text for r in results]
    row = await db.fetch_one("SELECT name FROM user_connections WHERE id = ?", (conn_id,))
    assert row["name"] in ("n1", "n2")


async def test_delete_peer_idempotent_and_tombstone(
    client: Any, db: Any, success_ssh: dict
) -> None:
    await _login_admin(client)
    server_id = await _make_server(client, db)
    resp = await client.post(
        f"/api/v1/servers/{server_id}/connections",
        json={"instance": "awg2", "user_id": 1, "name": "del"},
    )
    conn_id = resp.json()["id"]

    resp = await client.delete(
        f"/api/v1/servers/{server_id}/connections/{conn_id}?operation_id=del-op-1"
    )
    assert resp.status_code == 200, resp.text
    row = await db.fetch_one(
        "SELECT COUNT(*) AS n FROM user_connections WHERE id = ?", (conn_id,)
    )
    assert row["n"] == 0
    # tombstone для fail-closed учёта (подхватывается в MVP-07)
    row = await db.fetch_one(
        "SELECT COUNT(*) AS n FROM accounting_recoveries WHERE reason = 'peer_deleted'"
    )
    assert row["n"] == 1
    op = await db.fetch_one(
        "SELECT status FROM peer_creations WHERE operation_id = 'del-op-1'"
    )
    assert op["status"] == "done"


async def test_peer_audit_events(client: Any, db: Any, success_ssh: dict) -> None:
    await _login_admin(client)
    server_id = await _make_server(client, db)
    resp = await client.post(
        f"/api/v1/servers/{server_id}/connections",
        json={"instance": "awg2", "user_id": 1, "name": "a1"},
    )
    conn_id = resp.json()["id"]
    await client.delete(f"/api/v1/servers/{server_id}/connections/{conn_id}")

    rows = await db.fetch_all(
        "SELECT action FROM audit_log WHERE action LIKE 'peer.%' ORDER BY id"
    )
    actions = [r["action"] for r in rows]
    assert "peer.create" in actions
    assert "peer.delete" in actions


async def test_role_matrix_peers(client: Any, db: Any, success_ssh: dict) -> None:
    """user — 403; support — может создавать подключения (матрица §2.2)."""
    from app.core.security import hash_password

    await _login_admin(client)
    await db.execute(
        "INSERT INTO users (username, password_hash, role, enabled, created_at)"
        " VALUES ('plain', ?, 'user', 1, '2026-01-01T00:00:00Z')",
        (hash_password("StrongPass1!"),),
    )
    server_id = await _make_server(client, db)

    client.cookies.clear()
    resp = await client.post(
        "/api/auth/login", json={"username": "plain", "password": "StrongPass1!"},
        headers={"X-Test-Client-IP": "10.0.0.7"},
    )
    assert resp.status_code == 200
    resp = await client.post(
        f"/api/v1/servers/{server_id}/connections",
        json={"instance": "awg2", "user_id": 1, "name": "x"},
    )
    assert resp.status_code == 403

    # support — разрешено
    client.cookies.clear()
    await db.execute(
        "INSERT INTO users (username, password_hash, role, enabled, created_at)"
        " VALUES ('supp', ?, 'support', 1, '2026-01-01T00:00:00Z')",
        (hash_password("StrongPass1!"),),
    )
    resp = await client.post(
        "/api/auth/login", json={"username": "supp", "password": "StrongPass1!"},
        headers={"X-Test-Client-IP": "10.0.0.6"},
    )
    assert resp.status_code == 200
    resp = await client.post(
        f"/api/v1/servers/{server_id}/connections",
        json={"instance": "awg2", "user_id": 1, "name": "sup"},
    )
    assert resp.status_code == 201, resp.text


# -------------------------------------------------------------- configs


async def test_peer_config_endpoint(client: Any, db: Any, success_ssh: dict) -> None:
    await _login_admin(client)
    server_id = await _make_server(client, db)
    resp = await client.post(
        f"/api/v1/servers/{server_id}/connections",
        json={"instance": "awg2", "user_id": 1, "name": "cfg"},
    )
    conn_id = resp.json()["id"]
    cid = resp.json()["client_id"]

    raw_conf = (
        "[Interface]\nPrivateKey = aaaa=\nAddress = 10.8.1.2/32\n\n"
        "[Peer]\nPublicKey = bbbb=\nEndpoint = 203.0.113.10:32898\n"
    )
    success_ssh[f"awg-pc config {cid}"] = (0, raw_conf, "")

    resp = await client.get(
        f"/api/v1/servers/{server_id}/connections/{conn_id}/config"
    )
    assert resp.status_code == 200, resp.text
    bundle = resp.json()
    assert bundle["conf"].startswith("# Amnezia Web Panel")
    assert bundle["vpn_key"].startswith("vpn://")
    import base64 as _b64

    assert _b64.b64decode(bundle["qr_png_base64"]).startswith(b"\x89PNG")

    # format=conf → файл
    resp = await client.get(
        f"/api/v1/servers/{server_id}/connections/{conn_id}/config?format=conf"
    )
    assert resp.status_code == 200
    assert "text/plain" in resp.headers["content-type"]
    assert "PrivateKey" in resp.text
