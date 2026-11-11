"""Интеграционные тесты MVP-13: system/status, алерты, настройки, audit, диск."""

from __future__ import annotations

import json

import pytest

from app.alerts.service import (
    alert_accounting_gap,
    alert_quota_exhausted,
    alert_server_down,
    get_alert_config,
    reset_state,
    save_alert_config,
)
from app.core.security import hash_password


@pytest.fixture(autouse=True)
def _reset_alerts():
    reset_state()
    yield
    reset_state()


@pytest.fixture(name="users")
async def _users(db):
    await db.execute(
        "INSERT INTO users (username, password_hash, role, enabled, disable_reasons, created_at) "
        "VALUES ('admin', ?, 'admin', 1, '[]', '2026-01-01T00:00:00+00:00')",
        (hash_password("admin"),),
    )
    await db.execute(
        "INSERT INTO users (username, password_hash, role, enabled, disable_reasons, created_at) "
        "VALUES ('sup', ?, 'support', 1, '[]', '2026-01-01T00:00:00+00:00')",
        (hash_password("pass-12345"),),
    )
    await db.execute(
        "INSERT INTO users (username, password_hash, role, enabled, disable_reasons, created_at) "
        "VALUES ('usr', ?, 'user', 1, '[]', '2026-01-01T00:00:00+00:00')",
        (hash_password("pass-12345"),),
    )


@pytest.fixture(name="login")
async def _login(client, users):
    async def _do(username: str, password: str):
        return await client.post(
            "/api/auth/login", json={"username": username, "password": password}
        )

    return _do


# ------------------------------------------------------------ health §8.8


async def test_health_allowlist_denies_foreign(client, monkeypatch) -> None:
    """IP вне allowlist → 404; allowlist env применяется на каждый запрос.

    ASGI-транспорт httpx представляет клиента как 127.0.0.1, поэтому
    «чужим» адресом задаём 10.99.99.99.
    """
    monkeypatch.setenv("HEALTH_ALLOWLIST", "10.99.99.99")
    resp = await client.get("/health")
    assert resp.status_code == 404
    monkeypatch.setenv("HEALTH_ALLOWLIST", "127.0.0.0/8")
    resp = await client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok", "database": "up"}


async def test_health_503_db_down(client) -> None:
    """БД остановлена ⇒ 503 (§8.8)."""
    client.app.state.db._conn = None  # noqa: SLF001 — имитация останова
    resp = await client.get("/health")
    assert resp.status_code == 503
    body = resp.json()
    assert body["database"] == "down"


# ------------------------------------------------------- system/status


async def test_system_status_admin_only(client, login) -> None:
    assert (await client.get("/api/v1/system/status")).status_code == 401
    await login("usr", "pass-12345")
    assert (await client.get("/api/v1/system/status")).status_code == 403
    await login("admin", "admin")
    resp = await client.get("/api/v1/system/status")
    assert resp.status_code == 200
    body = resp.json()
    assert body["schema_version"] >= 2
    assert "uptime_seconds" in body
    assert body["database"]["size_bytes"] >= 0
    assert "accounting" in body["background_tasks"]
    assert "backup_scheduler" in body["background_tasks"]


# ------------------------------------------------------------- алерты


async def test_alerts_toggles_off_by_default(db) -> None:
    config = await get_alert_config(db)
    assert config.configured is False
    assert all(v is False for v in config.toggles.values())


async def test_alert_send_and_dedup(db, monkeypatch) -> None:
    """Алерт уходит в mock-Telegram и дедуплицируется (повтор — молча)."""
    await save_alert_config(
        db, toggles={"quota_exhausted": True}, bot_token="T", chat_id="C"  # noqa: S106 — фейковый токен
    )
    sent: list[dict] = []

    class _Resp:
        status_code = 200

        def json(self):  # pragma: no cover
            return {}

    class _Client:
        def __init__(self, *a, **kw):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def aclose(self):
            return None

        async def post(self, url, **kw):
            sent.append({"url": url, **kw})
            return _Resp()

    monkeypatch.setattr("httpx.AsyncClient", _Client)
    clock = {"t": 0.0}

    def fake_clock():
        return clock["t"]

    first = await alert_quota_exhausted(db, "usr", clock=fake_clock)
    assert first is True
    assert len(sent) == 1
    # тот же момент — дедупликация
    again = await alert_quota_exhausted(db, "usr", clock=fake_clock)
    assert again is False
    assert len(sent) == 1
    # час спустя — снова уходит
    clock["t"] = 3700.0
    later = await alert_quota_exhausted(db, "usr", clock=fake_clock)
    assert later is True
    assert len(sent) == 2
    assert "C" in sent[0]["url"] or "C" in str(sent[0].get("data", {}))


async def test_alert_suppressed_when_toggle_off(db) -> None:
    sent = await alert_quota_exhausted(db, "usr")
    assert sent is False  # тумблер по умолчанию выключен


async def test_server_down_alert_after_threshold(db, monkeypatch) -> None:
    """Алерт недоступности только после N минут (по часам)."""
    await save_alert_config(
        db, toggles={"server_down": True}, bot_token="T", chat_id="C",  # noqa: S106 — фейковый токен
        server_down_minutes=5,
    )
    posts: list[int] = []

    class _Resp:
        status_code = 200

    class _Client:
        def __init__(self, *a, **kw):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def aclose(self):
            return None

        async def post(self, url, **kw):
            posts.append(1)
            return _Resp()

    import app.alerts.service as svc

    monkeypatch.setattr(svc.httpx, "AsyncClient", _Client)
    clock = {"t": 0.0}

    # 1 минута недоступен — рано
    clock["t"] = 60.0
    assert await alert_server_down(db, 1, "srv", reachable=False,
                                   clock=lambda: clock["t"]) is False
    # 3 минуты — всё ещё рано
    clock["t"] = 180.0
    assert await alert_server_down(db, 1, "srv", reachable=False,
                                   clock=lambda: clock["t"]) is False
    # 6 минут — алерт
    clock["t"] = 360.0
    assert await alert_server_down(db, 1, "srv", reachable=False,
                                   clock=lambda: clock["t"]) is True
    assert len(posts) == 1
    # повтор — не дублируется (noted)
    clock["t"] = 400.0
    assert await alert_server_down(db, 1, "srv", reachable=False,
                                   clock=lambda: clock["t"]) is False
    # сервер восстановился — трекинг сброшен
    assert await alert_server_down(db, 1, "srv", reachable=True) is False
    # снова недоступен — отсчёт заново
    clock["t"] = 500.0
    assert await alert_server_down(db, 1, "srv", reachable=False,
                                   clock=lambda: clock["t"]) is False


async def test_accounting_gap_alert_dedup_hourly(db, monkeypatch) -> None:
    """gap-алерт ≤ 1 раз/час (FR-3.10.13)."""
    await save_alert_config(
        db, toggles={"accounting_gap": True}, bot_token="T", chat_id="C"  # noqa: S106 — фейковый токен
    )
    posts: list[int] = []

    class _Resp:
        status_code = 200

    class _Client:
        def __init__(self, *a, **kw):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def aclose(self):
            return None

        async def post(self, url, **kw):
            posts.append(1)
            return _Resp()

    import app.alerts.service as svc

    monkeypatch.setattr(svc.httpx, "AsyncClient", _Client)
    clock = {"t": 0.0}

    assert await alert_accounting_gap(db, 3, clock=lambda: clock["t"]) is True
    assert await alert_accounting_gap(db, 5, clock=lambda: clock["t"]) is False
    assert len(posts) == 1
    clock["t"] = 3601.0
    assert await alert_accounting_gap(db, 7, clock=lambda: clock["t"]) is True
    assert len(posts) == 2


# ------------------------------------------------------ настройки панели


async def test_settings_appearance_roundtrip(client, login) -> None:
    await login("admin", "admin")
    resp = await client.put(
        "/api/v1/settings/appearance",
        json={"title": "My VPN", "subtitle": "corp"},
    )
    assert resp.status_code == 200
    resp = await client.get("/api/v1/settings/appearance")
    assert resp.status_code == 200
    body = resp.json()
    assert body["title"] == "My VPN"
    assert body["subtitle"] == "corp"


async def test_settings_appearance_roles(client, login) -> None:
    """Чтение — admin/support; мутация — admin (§2.2)."""
    await login("sup", "pass-12345")
    assert (await client.get("/api/v1/settings/appearance")).status_code == 200
    assert (
        await client.put("/api/v1/settings/appearance", json={"title": "x"})
    ).status_code == 403
    await login("usr", "pass-12345")
    assert (await client.get("/api/v1/settings/appearance")).status_code == 403


async def test_settings_captcha_toggle(client, login) -> None:
    await login("admin", "admin")
    resp = await client.put("/api/v1/settings/captcha", json={"enabled": True})
    assert resp.status_code == 200
    assert resp.json()["enabled"] is True
    resp = await client.get("/api/v1/settings/captcha")
    assert resp.json()["enabled"] is True
    # выключаем обратно, чтобы не влиять на другие тесты
    await client.put("/api/v1/settings/captcha", json={"enabled": False})


async def test_settings_alerts_never_echo_token(client, login, db) -> None:
    """Токен бота только на запись; GET никогда его не возвращает (правило 3)."""
    await login("admin", "admin")
    resp = await client.put(
        "/api/v1/settings/alerts",
        json={"bot_token": "SECRET123", "chat_id": "42",
              "toggles": {"backup_failed": True}},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["telegram_configured"] is True
    resp = await client.get("/api/v1/settings/alerts")
    text = json.dumps(resp.json())
    assert "SECRET123" not in text
    assert resp.json()["toggles"]["backup_failed"] is True


async def test_settings_alerts_support_readonly(client, login) -> None:
    await login("sup", "pass-12345")
    assert (await client.get("/api/v1/settings/alerts")).status_code == 200
    resp = await client.put(
        "/api/v1/settings/alerts", json={"toggles": {"backup_failed": True}}
    )
    assert resp.status_code == 403


# ---------------------------------------------------------------- audit


async def test_audit_api_roles_and_filters(client, login, db) -> None:
    from app.core.audit import log_event

    await log_event(db, "admin", "server.created", object="server:1", ip="1.2.3.4")
    await log_event(db, "sup", "server.created", object="server:2", ip="1.2.3.4",
                    result="denied")

    await login("usr", "pass-12345")
    assert (await client.get("/api/v1/audit")).status_code == 403

    await login("sup", "pass-12345")
    resp = await client.get("/api/v1/audit")
    assert resp.status_code == 200  # support — read-only просмотр
    total = resp.json()["total"]
    assert total >= 2

    await login("admin", "admin")
    resp = await client.get("/api/v1/audit", params={"actor": "sup"})
    items = resp.json()["items"]
    assert items and all(i["actor"] == "sup" for i in items)
    resp = await client.get("/api/v1/audit", params={"result": "denied"})
    items = resp.json()["items"]
    assert items and all(i["result"] == "denied" for i in items)
    resp = await client.get("/api/v1/audit", params={"action": "server."})
    items = resp.json()["items"]
    assert items and all(i["action"].startswith("server.") for i in items)


# -------------------------------------------------- дисковая деградация


async def test_disk_guard_read_only(monkeypatch, tmp_path) -> None:
    """Аварийный порог ⇒ read-only (FR-3.15.7, симуляция)."""
    from app.core import disk_guard

    disk_guard.reset_state()
    # мокаем disk_usage: «свободно 10 MiB» < emergency 50
    import shutil

    class _Usage(NamedTuple := __import__("collections").namedtuple("_U", "total used free")):
        pass

    usage = _Usage(total=10**9, used=0, free=10 * 1024 * 1024)
    monkeypatch.setattr(shutil, "disk_usage", lambda _: usage)
    state = await disk_guard.check_disk(tmp_path)
    assert state.read_only is True
    assert state.emergency is True

    import pytest as _pytest

    with _pytest.raises(RuntimeError, match=disk_guard.READ_ONLY_ERROR):
        await disk_guard.ensure_writable()
    disk_guard.reset_state()


async def test_disk_status_endpoint(client, login) -> None:
    from app.core import disk_guard

    disk_guard.reset_state()
    await login("admin", "admin")
    resp = await client.get("/api/v1/settings/disk")
    assert resp.status_code == 200
    body = resp.json()
    assert "free_mb" in body and "read_only" in body
    disk_guard.reset_state()


async def test_monitor_tick_smoke(app, client, db) -> None:
    """Один тик монитора не падает и возвращает статус серверов/диска."""
    from app.alerts.monitor import ObservabilityMonitor
    from app.servers.service import ServerService
    from app.ssh.pool import SSHPool

    monitor = ObservabilityMonitor(db, ServerService(SSHPool()), interval=3600)
    result = await monitor.tick()
    assert "servers" in result
    assert "disk_read_only" in result
