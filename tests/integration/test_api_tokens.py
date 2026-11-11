"""Integration-тесты Bearer-токенов и rate-limit (FR-3.12.1–3.12.5, FR-2.3)."""

from __future__ import annotations

import pytest
from httpx import AsyncClient

from tests.integration.conftest import make_login

pytest.importorskip("httpx")


@pytest.fixture
async def admin_client(client: AsyncClient) -> AsyncClient:
    login = make_login(client)
    await login("admin", "admin")
    return client


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


class TestTokenLifecycle:
    async def test_create_returns_raw_once(
        self, admin_client: AsyncClient
    ) -> None:
        resp = await admin_client.post(
            "/api/v1/tokens", json={"name": "ci", "ttl_seconds": 3600}
        )
        assert resp.status_code == 201
        body = resp.json()
        assert body["token"].startswith("awp_")
        assert body["expires_at"] is not None
        # в списке raw уже не виден
        listing = await admin_client.get("/api/v1/tokens")
        items = listing.json()
        assert len(items) == 1
        assert "token" not in items[0]

    async def test_token_works_on_session_endpoints(
        self, client: AsyncClient, admin_client: AsyncClient
    ) -> None:
        resp = await admin_client.post("/api/v1/tokens", json={"name": "api"})
        raw = resp.json()["token"]
        # эндпоинт, требующий сессию, работает с Bearer без cookie
        me = await client.get("/api/auth/me", headers=_bearer(raw))
        assert me.status_code == 200
        assert me.json()["username"] == "admin"
        servers = await client.get("/api/v1/servers", headers=_bearer(raw))
        assert servers.status_code == 200

    async def test_revoke_instant(self, client: AsyncClient, admin_client: AsyncClient) -> None:
        resp = await admin_client.post("/api/v1/tokens", json={"name": "tmp"})
        body = resp.json()
        me = await client.get("/api/auth/me", headers=_bearer(body["token"]))
        assert me.status_code == 200
        rev = await admin_client.delete(f"/api/v1/tokens/{body['id']}")
        assert rev.status_code == 200
        me2 = await client.get("/api/auth/me", headers=_bearer(body["token"]))
        assert me2.status_code == 401

    async def test_rotate_old_invalidated(
        self, client: AsyncClient, admin_client: AsyncClient
    ) -> None:
        resp = await admin_client.post("/api/v1/tokens", json={"name": "r1"})
        old = resp.json()
        rot = await admin_client.post(f"/api/v1/tokens/{old['id']}/rotate")
        assert rot.status_code == 200
        new = rot.json()
        assert new["token"] != old["token"]
        assert (await client.get("/api/auth/me", headers=_bearer(old["token"]))).status_code == 401
        assert (await client.get("/api/auth/me", headers=_bearer(new["token"]))).status_code == 200

    async def test_support_token_no_admin_ops(
        self, client: AsyncClient, admin_client: AsyncClient
    ) -> None:
        # создаём support-пользователя отдельным клиентом
        await admin_client.post(
            "/api/v1/users",
            json={"username": "sup2", "password": "sup2pass123", "role": "support"},
        )
        sup_client = AsyncClient(transport=client._transport, base_url="http://test")
        try:
            login = make_login(sup_client)
            await login("sup2", "sup2pass123")
            resp = await sup_client.post("/api/v1/tokens", json={"name": "sup"})
            raw = resp.json()["token"]
            headers = _bearer(raw)
            assert (await sup_client.get("/api/v1/users", headers=headers)).status_code == 200
            # admin-only операция с support-токеном запрещена (§2.2)
            del_req = await sup_client.delete("/api/v1/users/1", headers=headers)
            assert del_req.status_code == 403
        finally:
            await sup_client.aclose()

    async def test_role_demotion_invalidates_token(
        self, client: AsyncClient, admin_client: AsyncClient
    ) -> None:
        await admin_client.post(
            "/api/v1/users",
            json={"username": "sup3", "password": "sup3pass123", "role": "support"},
        )
        sup_client = AsyncClient(transport=client._transport, base_url="http://test")
        try:
            login = await sup_client.post(
                "/api/auth/login", json={"username": "sup3", "password": "sup3pass123"}
            )
            assert login.status_code == 200
            resp = await sup_client.post("/api/v1/tokens", json={"name": "dem"})
            raw = resp.json()["token"]
            # понижение роли до user — hook отзывает все токены владельца
            users = await admin_client.get("/api/v1/users")
            uid = next(u["id"] for u in users.json() if u["username"] == "sup3")
            demote = await admin_client.patch(
                f"/api/v1/users/{uid}", json={"role": "user"}
            )
            assert demote.status_code == 200
            me = await client.get("/api/auth/me", headers=_bearer(raw))
            assert me.status_code in (401, 403)
        finally:
            await sup_client.aclose()

    async def test_disable_owner_invalidates_token(
        self, client: AsyncClient, admin_client: AsyncClient
    ) -> None:
        await admin_client.post(
            "/api/v1/users",
            json={"username": "sup4", "password": "sup4pass123", "role": "support"},
        )
        sup_client = AsyncClient(transport=client._transport, base_url="http://test")
        try:
            await sup_client.post(
                "/api/auth/login", json={"username": "sup4", "password": "sup4pass123"}
            )
            resp = await sup_client.post("/api/v1/tokens", json={"name": "dis"})
            raw = resp.json()["token"]
            users = await admin_client.get("/api/v1/users")
            uid = next(u["id"] for u in users.json() if u["username"] == "sup4")
            disable = await admin_client.post(
                f"/api/v1/users/{uid}/enabled", json={"enabled": False}
            )
            assert disable.status_code == 200
            me = await client.get("/api/auth/me", headers=_bearer(raw))
            assert me.status_code in (401, 403)
        finally:
            await sup_client.aclose()


class TestErrorsAndDocs:
    async def test_error_format_uniform(self, client: AsyncClient) -> None:
        resp = await client.get("/api/v1/users")
        assert resp.status_code == 401
        body = resp.json()
        assert set(body) >= {"error_code", "message", "details"}

    async def test_openapi_docs_redoc(self, client: AsyncClient) -> None:
        assert (await client.get("/openapi.json")).status_code == 200
        assert (await client.get("/docs")).status_code == 200
        assert (await client.get("/redoc")).status_code == 200

    async def test_api_alias_v1(self, client: AsyncClient) -> None:
        # /api — алиас на /api/v1 через 307 (FR-3.12.3)
        resp = await client.get("/api/tokens", follow_redirects=True)
        assert resp.status_code == 401
        body = resp.json()
        assert set(body) >= {"error_code", "message", "details"}
