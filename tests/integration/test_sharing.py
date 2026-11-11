"""Integration-тесты шеринга (MVP-10, FR-3.8.1–3.8.4).

Сценарий ТЗ §8.2: share-ссылка отдаёт конфиги без входа в панель;
пароль — обязательный барьер; перегенерация мгновенно инвалидирует старую
ссылку; ревокация закрывает доступ; роли setup — admin; rate-limit на
перебор; audit-события; noindex/no-store.
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

CONFIG_PAT = r"awg-pc config"


def _raw_config() -> str:
    return (
        "[Interface]\nPrivateKey = AAAA\nAddress = 10.8.0.2/32\n\n"
        "[Peer]\nPublicKey = BBBB\nEndpoint = 203.0.113.10:32898\n"
        "AllowedIPs = 0.0.0.0/0\n"
    )


async def _login_admin(ac: Any) -> None:
    resp = await ac.post(
        "/api/auth/login",
        json={"username": "admin", "password": "admin"},
        headers={"X-Test-Client-IP": "10.0.0.9"},
    )
    assert resp.status_code == 200, resp.text


async def _make_setup(client: Any, db: Any) -> tuple[int, int]:
    """Сервер с awg2 + подключение владельца admin (user_id=1)."""
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


# --------------------------------------------------------------- setup/roles


async def test_setup_roles_and_token_stable(client: Any, db: Any) -> None:
    """FR-3.8.1: setup — admin; support/user — 403; токен стабилен."""
    await _login_admin(client)
    await _make_setup(client, db)

    # admin создаёт support-пользователя
    resp = await client.post(
        "/api/v1/users",
        json={"username": "sup1", "role": "support", "password": "support-pass"},
        headers={"X-Test-Client-IP": "10.0.0.9"},
    )
    assert resp.status_code == 201, resp.text

    # setup от admin — 201, токен выдан один раз
    resp = await client.post(
        "/api/v1/users/1/share/setup",
        json={},
        headers={"X-Test-Client-IP": "10.0.0.9"},
    )
    assert resp.status_code == 201, resp.text
    token1 = resp.json()["share_token"]
    assert token1.startswith("sh_")

    # повторный setup — тот же токен (стабильная ссылка)
    resp = await client.post(
        "/api/v1/users/1/share/setup",
        json={},
        headers={"X-Test-Client-IP": "10.0.0.9"},
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["share_token"] == token1

    # статус не раскрывает токен
    resp = await client.get(
        "/api/v1/users/1/share", headers={"X-Test-Client-IP": "10.0.0.9"}
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["share_enabled"] is True
    assert "share_token" not in body

    # support видит статус, но не может setup/rotate/revoke
    resp2 = await client.post(
        "/api/auth/login",
        json={"username": "sup1", "password": "support-pass"},
        headers={"X-Test-Client-IP": "10.0.0.10"},
    )
    assert resp2.status_code == 200, resp2.text
    for method, url in (
        ("post", "/api/v1/users/1/share/setup"),
        ("post", "/api/v1/users/1/share/rotate"),
        ("post", "/api/v1/users/1/share/revoke"),
    ):
        resp = await client.request(
            method, url, json={},
            headers={"X-Test-Client-IP": "10.0.0.10"},
        )
        assert resp.status_code == 403, (method, url, resp.text)
    resp = await client.get(
        "/api/v1/users/1/share", headers={"X-Test-Client-IP": "10.0.0.10"}
    )
    assert resp.status_code == 200


async def test_share_page_serves_configs_without_login(
    client: Any, db: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Сценарий ТЗ §8.2: валидный токен отдаёт конфиги без входа в панель."""
    install_accounting_ssh(monkeypatch)
    results = install_accounting_ssh(monkeypatch)
    results[CONFIG_PAT] = (0, _raw_config(), "")
    await _login_admin(client)
    await _make_setup(client, db)

    resp = await client.post(
        "/api/v1/users/1/share/setup",
        json={},
        headers={"X-Test-Client-IP": "10.0.0.9"},
    )
    token = resp.json()["share_token"]

    # анонимный клиент без cookie панели — страница отдаёт список
    resp = await client.get(f"/share/{token}")
    assert resp.status_code == 200, resp.text
    assert "noindex" in resp.text
    assert resp.headers["cache-control"] == "no-store"

    # выгрузка .conf без сессии
    conn_id = await db.fetch_one("SELECT id FROM user_connections LIMIT 1")
    resp = await client.get(f"/share/{token}/download/{conn_id['id']}")
    assert resp.status_code == 200
    assert "Endpoint = 203.0.113.10:32898" in resp.text

    # QR
    resp = await client.get(f"/share/{token}/download/{conn_id['id']}?format=qr")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "image/png"


async def test_invalid_tokens_404(client: Any, db: Any) -> None:
    """Отозванный/перегенерированный/чужой токен — 404 (без деталей)."""
    await _login_admin(client)
    await _make_setup(client, db)

    resp = await client.get("/share/sh_nonexistent000000000000")
    assert resp.status_code == 404

    # выдать и отозвать
    resp = await client.post(
        "/api/v1/users/1/share/setup",
        json={},
        headers={"X-Test-Client-IP": "10.0.0.9"},
    )
    token = resp.json()["share_token"]
    resp = await client.post(
        "/api/v1/users/1/share/revoke",
        headers={"X-Test-Client-IP": "10.0.0.9"},
    )
    assert resp.status_code == 200
    resp = await client.get(f"/share/{token}")
    assert resp.status_code == 404


async def test_rotate_invalidates_old_token_and_audits(
    client: Any, db: Any
) -> None:
    """FR-3.8.4: перегенерация — старая ссылка мгновенно недействительна."""
    await _login_admin(client)
    await _make_setup(client, db)

    resp = await client.post(
        "/api/v1/users/1/share/setup",
        json={},
        headers={"X-Test-Client-IP": "10.0.0.9"},
    )
    old_token = resp.json()["share_token"]

    resp = await client.post(
        "/api/v1/users/1/share/rotate",
        headers={"X-Test-Client-IP": "10.0.0.9"},
    )
    assert resp.status_code == 201, resp.text
    new_token = resp.json()["share_token"]
    assert new_token != old_token

    resp = await client.get(f"/share/{old_token}")
    assert resp.status_code == 404
    resp = await client.get(f"/share/{new_token}")
    assert resp.status_code == 200

    # rotate при выключенном шеринге — 409
    await client.post(
        "/api/v1/users/1/share/revoke",
        headers={"X-Test-Client-IP": "10.0.0.9"},
    )
    resp = await client.post(
        "/api/v1/users/1/share/rotate",
        headers={"X-Test-Client-IP": "10.0.0.9"},
    )
    assert resp.status_code == 409

    # audit-события
    row = await db.fetch_one(
        "SELECT COUNT(*) AS n FROM audit_log WHERE action = 'share.token_rotated'"
    )
    assert row["n"] >= 1


async def test_password_barrier_and_share_session(
    client: Any, db: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """FR-3.8.3: пароль обязателен, неверный — 403, верный — cookie-сессия."""
    results = install_accounting_ssh(monkeypatch)
    results[CONFIG_PAT] = (0, _raw_config(), "")
    await _login_admin(client)
    await _make_setup(client, db)

    resp = await client.post(
        "/api/v1/users/1/share/setup",
        json={"password": "share-pass-123"},
        headers={"X-Test-Client-IP": "10.0.0.9"},
    )
    assert resp.status_code == 201, resp.text
    token = resp.json()["share_token"]

    # страница без сессии — форма пароля
    resp = await client.get(f"/share/{token}")
    assert resp.status_code == 200
    assert 'type="password"' in resp.text

    # содержимое недоступно без ввода пароля
    conn_id_row = await db.fetch_one("SELECT id FROM user_connections LIMIT 1")
    resp = await client.get(f"/share/{token}/download/{conn_id_row['id']}")
    assert resp.status_code == 302

    # неверный пароль — 403
    resp = await client.post(
        f"/share/{token}", data={"password": "wrong-password"},
    )
    assert resp.status_code == 403

    # верный пароль — 303 + cookie share-сессии
    resp = await client.post(
        f"/share/{token}", data={"password": "share-pass-123"},
    )
    assert resp.status_code == 303, resp.text
    assert "awp_share" in resp.cookies

    # с cookie — страница и выгрузка доступны
    resp = await client.get(f"/share/{token}")
    assert resp.status_code == 200
    assert 'type="password"' not in resp.text
    resp = await client.get(f"/share/{token}/download/{conn_id_row['id']}")
    assert resp.status_code == 200


async def test_share_password_rate_limit(client: Any, db: Any) -> None:
    """Rate-limit на перебор пароля share-страницы (задача MVP-10)."""
    await _login_admin(client)
    await _make_setup(client, db)

    resp = await client.post(
        "/api/v1/users/1/share/setup",
        json={"password": "share-pass-123"},
        headers={"X-Test-Client-IP": "10.0.0.9"},
    )
    token = resp.json()["share_token"]

    svc = client.app.state.share_service  # type: ignore[attr-defined]
    svc._RATE_MAX = 5  # noqa: SLF001 — ускоряем тест

    statuses = []
    for _ in range(8):
        resp = await client.post(
            f"/share/{token}", data={"password": "totally-wrong"},
        )
        statuses.append(resp.status_code)
    assert 429 in statuses

    # rate-limit по одному и тому же токену
    svc._attempts.clear()  # noqa: SLF001
    resp = await client.post(
        f"/share/{token}", data={"password": "share-pass-123"},
    )
    assert resp.status_code == 303


async def test_disabled_user_share_token_invalid(client: Any, db: Any) -> None:
    """Disable владельца мгновенно закрывает share-страницу (FR-3.6.4+3.8)."""
    await _login_admin(client)
    await _make_setup(client, db)

    resp = await client.post(
        "/api/v1/users/1/share/setup",
        json={},
        headers={"X-Test-Client-IP": "10.0.0.9"},
    )
    token = resp.json()["share_token"]

    admin_id = None
    users = (await client.get(
        "/api/v1/users", headers={"X-Test-Client-IP": "10.0.0.9"}
    )).json()
    admin_id = next(u["id"] for u in users if u["username"] == "admin")
    # disable самого себя нельзя (last_admin guard только для последнего admin
    # — но enable-флаг можно снимать? нет: last_admin). Проверяем через прямой
    # UPDATE: суть — resolve_token не пускает disabled/role=none.
    await db.execute("UPDATE users SET enabled = 0 WHERE share_token = ?", (token,))
    resp = await client.get(f"/share/{token}")
    assert resp.status_code == 404

    await db.execute("UPDATE users SET enabled = 1 WHERE share_token = ?", (token,))
    resp = await client.get(f"/share/{token}")
    assert resp.status_code == 200
    assert admin_id  # noqa: B018 — используется для читаемости сценария
