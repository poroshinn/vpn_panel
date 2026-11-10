"""Integration-тесты учёта трафика (MVP-07) на mock-SSH-ноде.

Проверяются: цикл опроса (transfer по инстансам), смена эпохи →
``traffic_accounting_gap`` без обнуления итогов, исчерпание квоты →
автоотключение с причиной ``quota``, финализация happy-path и fail-closed 409,
перезапуск панели — базлайны целы.

Mock-SSH — wildcard-вариант; выход transfer меняется мутацией ``results``
(значение захватывается в момент установки паттерна).
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from app.accounting.service import AccountingService

pytestmark = pytest.mark.asyncio

SERVER_PAYLOAD = {
    "name": "node-1",
    "host": "203.0.113.10",
    "ssh_port": 22,
    "username": "root",
    "password": "s3cret-password",
}

AWG2_INFO = {"preset_id": "awg-2x", "protocol": "awg", "port": 32898, "junk": {}}

PUBKEY = "5Ks3tJ9qZ0hXk2mVq7wLbN8pRcT1uYdAeFgHiJkLmNo="
PUBKEY2 = "zzz8y7x6w5v4u3t2s1r0q9p8o7n6m5l4k3j2i1h0g="

# стабильная эпоха (эпоха не меняется между семплами)
EPOCH_META_OK = "cont123 777 2026-11-10T00:00:00Z|boot-1|3|1000:ctime\n"
# другая эпоха (сменённый PID процесса)
EPOCH_META_NEW = "cont123 888 2026-11-10T00:00:00Z|boot-1|3|1000:ctime\n"

TRANSFER_PAT = r"awg show awg2 transfer|wg show awg2 transfer"
META_PAT = r"docker inspect -f"


def install_accounting_ssh(
    monkeypatch: pytest.MonkeyPatch, transfer_raw: str = f"{PUBKEY}\t100\t200\n"
) -> dict[str, tuple[int, str, str]]:
    """Mock SSH: epoch-мета стабильна, transfer — фиксированный вывод."""
    from tests.integration.test_protocols_peers import install_fake_paramiko_wild

    results = install_fake_paramiko_wild(monkeypatch)
    set_transfer(results, raw=transfer_raw)
    results[META_PAT] = (0, EPOCH_META_OK, "")
    results[r"awg-pc (enable|disable)"] = (0, "ok\n", "")
    return results


def set_transfer(
    results: dict[str, tuple[int, str, str]],
    rx: int | None = None,
    tx: int | None = None,
    raw: str | None = None,
    pubkey: str = PUBKEY,
) -> None:
    """Обновить transfer-исход мока (значение захватывается tuple'ом)."""
    if raw is None:
        prev = results.get(TRANSFER_PAT, (0, f"{PUBKEY}\t0\t0\n", ""))[1]
        # если вывод уже для другого ключа — заменим целиком по rx/tx
        if pubkey in prev:
            lines = [ln for ln in prev.splitlines() if ln.startswith(pubkey)]
            if lines:
                _, old_rx, old_tx = lines[0].split("\t")
                rx = old_rx if rx is None else rx
                tx = old_tx if tx is None else tx
                raw = f"{pubkey}\t{rx}\t{tx}\n"
            else:
                raw = f"{pubkey}\t{rx or 0}\t{tx or 0}\n"
        else:
            raw = f"{pubkey}\t{rx or 0}\t{tx or 0}\n"
    results[TRANSFER_PAT] = (0, raw, "")


async def _login_admin(ac: Any) -> None:
    resp = await ac.post(
        "/api/auth/login",
        json={"username": "admin", "password": "admin"},
        headers={"X-Test-Client-IP": "10.0.0.9"},
    )
    assert resp.status_code == 200, resp.text


async def _make_setup(client: Any, db: Any) -> tuple[int, int]:
    """Сервер с awg2 + подключение с известным pubkey в counters_json."""
    resp = await client.post("/api/v1/servers", json=SERVER_PAYLOAD)
    assert resp.status_code == 201, resp.text
    server_id = resp.json()["id"]
    await db.execute(
        "UPDATE servers SET protocols = ? WHERE id = ?",
        (json.dumps({"awg2": AWG2_INFO}), server_id),
    )
    conn_id = await db.execute(
        "INSERT INTO user_connections (user_id, server_id, protocol, client_id,"
        " name, created_at, counters_json) VALUES (1, ?, 'awg2', 'cl1', 'p1',"
        " '2026-11-10T00:00:00+00:00', ?)",
        (server_id, json.dumps({"pubkey": PUBKEY})),
    )
    return server_id, conn_id


def _service(client: Any) -> AccountingService:
    return client.app.state.accounting_service  # type: ignore[attr-defined]


# ---------------------------------------------------------- цикл опроса


async def test_poll_cycle_commits_baseline_and_delta(
    client: Any, db: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    results = install_accounting_ssh(monkeypatch)
    await _login_admin(client)
    server_id, conn_id = await _make_setup(client, db)
    svc = _service(client)

    # первый цикл: устанавливает базлайн, дельта не считается
    await svc.tick()
    row = await db.fetch_one("SELECT * FROM user_connections WHERE id = ?", (conn_id,))
    assert row["rx_base"] == 100 and row["tx_base"] == 200
    assert row["lifetime_rx"] == 0 and row["lifetime_tx"] == 0
    assert row["counters_verified_final"] == 1
    assert row["last_sample_at"] is not None

    # второй цикл: счётчики выросли → дельта коммитится
    set_transfer(results, rx=600, tx=900)
    await svc.tick()
    row = await db.fetch_one("SELECT * FROM user_connections WHERE id = ?", (conn_id,))
    assert row["rx_base"] == 600 and row["tx_base"] == 900
    assert row["lifetime_rx"] == 500 and row["lifetime_tx"] == 700
    user = await db.fetch_one("SELECT traffic_used FROM users WHERE id = 1")
    assert user["traffic_used"] == 1200


async def test_epoch_change_records_gap_without_reset(
    client: Any, db: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    results = install_accounting_ssh(monkeypatch)
    await _login_admin(client)
    server_id, conn_id = await _make_setup(client, db)
    svc = _service(client)

    await svc.tick()
    before = await db.fetch_one(
        "SELECT * FROM user_connections WHERE id = ?", (conn_id,)
    )
    assert before["lifetime_rx"] == 0

    # счётчик сброшен И эпоха сменилась (перезапуск контейнера)
    results[META_PAT] = (0, EPOCH_META_NEW, "")
    set_transfer(results, rx=5, tx=10)
    await svc.tick()
    row = await db.fetch_one("SELECT * FROM user_connections WHERE id = ?", (conn_id,))
    # gap: итоги НЕ обнулены и НЕ увеличены, verified=false (fail-closed)
    assert row["lifetime_rx"] == before["lifetime_rx"]
    assert row["counters_verified_final"] == 0
    assert row["epoch_hash"] != before["epoch_hash"]
    counters = json.loads(row["counters_json"])
    assert counters["last_gap"]["reason"] == "epoch_changed"
    # запись gap в accounting_recoveries
    rec = await db.fetch_one(
        "SELECT * FROM accounting_recoveries WHERE reason = 'traffic_accounting_gap'"
        " ORDER BY id DESC LIMIT 1"
    )
    assert rec is not None


async def test_counter_reset_on_same_epoch_is_gap(
    client: Any, db: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    results = install_accounting_ssh(monkeypatch)
    await _login_admin(client)
    server_id, conn_id = await _make_setup(client, db)
    svc = _service(client)

    await svc.tick()
    before = await db.fetch_one(
        "SELECT * FROM user_connections WHERE id = ?", (conn_id,)
    )

    # счётчик упал, эпоха прежняя → gap (counter_reset)
    set_transfer(results, rx=10, tx=20)
    await svc.tick()
    row = await db.fetch_one("SELECT * FROM user_connections WHERE id = ?", (conn_id,))
    assert row["counters_verified_final"] == 0
    counters = json.loads(row["counters_json"])
    assert counters["last_gap"]["reason"] == "counter_reset"
    # базлайн обновлён на новые сырые значения (без обнуления итогов)
    assert row["rx_base"] == 10 and row["tx_base"] == 20
    assert row["lifetime_rx"] == before["lifetime_rx"]


# ------------------------------------------------------------- квоты


async def test_quota_exhaustion_disables_user(
    client: Any, db: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    results = install_accounting_ssh(monkeypatch)
    await _login_admin(client)
    await _make_setup(client, db)
    svc = _service(client)

    # лимит 1500, used 1200 после двух циклов — не исчерпан
    await db.execute("UPDATE users SET traffic_limit = 1500 WHERE id = 1")
    await svc.tick()
    set_transfer(results, rx=600, tx=900)
    await svc.tick()
    user = await db.fetch_one("SELECT * FROM users WHERE id = 1")
    assert user["traffic_used"] == 1200
    assert user["enabled"] == 1

    # исчерпание: дельта 200+300=500 → 1200+500=1700 ≥ 1500 → отключение
    set_transfer(results, rx=800, tx=1200)
    await svc.tick()
    user = await db.fetch_one("SELECT * FROM users WHERE id = 1")
    assert user["traffic_used"] == 1700
    assert user["enabled"] == 0
    assert "quota" in json.loads(user["disable_reasons"])


async def test_monthly_reset_idempotent_keeps_baselines(
    client: Any, db: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    results = install_accounting_ssh(monkeypatch)
    await _login_admin(client)
    server_id, conn_id = await _make_setup(client, db)
    svc = _service(client)
    await svc.tick()
    set_transfer(results, rx=600, tx=900)
    await svc.tick()

    row = await db.fetch_one(
        "SELECT rx_base FROM user_connections WHERE id = ?", (conn_id,)
    )
    assert row["rx_base"] == 600

    reset = await svc.monthly_reset()
    assert reset == 1
    user = await db.fetch_one("SELECT traffic_used FROM users WHERE id = 1")
    assert user["traffic_used"] == 0
    # сырые базлайны не тронуты (FR-3.5.4)
    row = await db.fetch_one(
        "SELECT rx_base FROM user_connections WHERE id = ?", (conn_id,)
    )
    assert row["rx_base"] == 600
    # повторный сброс в том же месяце — no-op
    assert await svc.monthly_reset() == 0


# --------------------------------------------------------- финализация


async def test_finalize_happy_path(
    client: Any, db: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    install_accounting_ssh(monkeypatch)
    await _login_admin(client)
    server_id, conn_id = await _make_setup(client, db)
    svc = _service(client)
    await svc.tick()

    resp = await client.post(
        f"/api/v1/servers/{server_id}/connections/{conn_id}/finalize", json={}
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["status"] == "finalized"
    assert data["counters_verified_final"] is True

    # подключение удалено, tombstone верифицирован
    assert (
        await db.fetch_one("SELECT 1 FROM user_connections WHERE id = ?", (conn_id,))
        is None
    )
    rec = await db.fetch_one(
        "SELECT * FROM accounting_recoveries WHERE reason = 'finalized'"
        " ORDER BY id DESC LIMIT 1"
    )
    assert rec is not None and rec["counters_verified_final"] == 1
    tombstone = json.loads(rec["tombstone_json"])
    assert tombstone["final_rx"] == 100


async def test_finalize_unreadable_counter_fails_closed(
    client: Any, db: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    results = install_accounting_ssh(monkeypatch)
    await _login_admin(client)
    server_id, conn_id = await _make_setup(client, db)
    svc = _service(client)
    await svc.tick()

    # peer исчез из transfer (нечитаемый счётчик)
    set_transfer(results, raw="")
    resp = await client.post(
        f"/api/v1/servers/{server_id}/connections/{conn_id}/finalize", json={}
    )
    assert resp.status_code == 409, resp.text
    data = resp.json()
    assert data["error_code"] == "counter_unreadable"
    assert data["details"]["can_force"] is True
    # fail-closed: запись не удалена
    assert (
        await db.fetch_one("SELECT 1 FROM user_connections WHERE id = ?", (conn_id,))
        is not None
    )

    # ретрай с allow_unverified: tombstone без дельты
    resp = await client.post(
        f"/api/v1/servers/{server_id}/connections/{conn_id}/finalize",
        json={"allow_unverified": True},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["counters_verified_final"] is False
    assert (
        await db.fetch_one("SELECT 1 FROM user_connections WHERE id = ?", (conn_id,))
        is None
    )
    rec = await db.fetch_one(
        "SELECT * FROM accounting_recoveries WHERE reason = 'finalized_unverified'"
        " ORDER BY id DESC LIMIT 1"
    )
    assert rec is not None and rec["counters_verified_final"] == 0


# ------------------------------------------------------- базлайны/рестарт


async def test_baselines_survive_restart(
    client: Any, db: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    results = install_accounting_ssh(monkeypatch)
    await _login_admin(client)
    server_id, conn_id = await _make_setup(client, db)
    svc = _service(client)
    await svc.tick()
    set_transfer(results, rx=600, tx=900)
    await svc.tick()

    # «перезапуск»: базлайны/эпоха живут в БД, а не в памяти сервиса
    row = await db.fetch_one("SELECT * FROM user_connections WHERE id = ?", (conn_id,))
    assert row["rx_base"] == 600 and row["lifetime_rx"] == 500
    assert row["epoch_hash"] is not None

    # новый сервис на той же БД продолжает с тех же базлайнов
    svc2 = AccountingService(
        db, client.app.state.ssh_pool, client.app.state.server_service,
        client.app.state.peer_service,
    )
    await svc2.tick()
    row = await db.fetch_one("SELECT * FROM user_connections WHERE id = ?", (conn_id,))
    # базлайн сохранился: дельта не задвоилась
    assert row["lifetime_rx"] == 500


# ---------------------------------------------------------- матрица ролей


async def test_accounting_endpoints_roles(
    client: Any, db: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    install_accounting_ssh(monkeypatch)
    await _login_admin(client)
    server_id, conn_id = await _make_setup(client, db)

    # аноним — 401
    anon_app = client.app
    from httpx import ASGITransport, AsyncClient

    async with AsyncClient(
        transport=ASGITransport(app=anon_app), base_url="http://t"
    ) as ac:
        resp = await ac.get("/api/v1/accounting")
        assert resp.status_code == 401
        resp = await ac.put("/api/v1/users/1/quota", json={"traffic_limit": 100})
        assert resp.status_code == 401

    # сводка себя доступна залогиненному
    resp = await client.get("/api/v1/accounting")
    assert resp.status_code == 200
    assert "traffic_used" in resp.json()

    # admin может менять квоту
    resp = await client.put("/api/v1/users/1/quota", json={"traffic_limit": 1000})
    assert resp.status_code == 200
    user = await db.fetch_one("SELECT traffic_limit FROM users WHERE id = 1")
    assert user["traffic_limit"] == 1000
