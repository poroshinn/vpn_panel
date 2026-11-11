"""Unit-тесты app/auth/tokens.py (FR-3.12.4)."""

from __future__ import annotations

import pytest

from app.auth.tokens import (
    TOKEN_PREFIX,
    TokenError,
    TokenService,
    _hash_token,
)
from app.db.database import Database
from app.db.migrator import apply_migrations


@pytest.fixture
async def db(tmp_path):
    database = Database(path=tmp_path / "t.db")
    await database.connect()
    await apply_migrations(database)
    await database.execute(
        "INSERT INTO users (id, username, role, enabled, created_at)"
        " VALUES (1, 'admin', 'admin', 1, '2026-01-01T00:00:00+00:00')"
    )
    await database.execute(
        "INSERT INTO users (id, username, role, enabled, created_at)"
        " VALUES (2, 'sup', 'support', 1, '2026-01-01T00:00:00+00:00')"
    )
    await database.execute(
        "INSERT INTO users (id, username, role, enabled, created_at)"
        " VALUES (3, 'plain', 'user', 1, '2026-01-01T00:00:00+00:00')"
    )
    yield database
    await database.close()


class TestCreate:
    async def test_creates_raw_with_prefix(self, db: Database) -> None:
        raw, record = await TokenService().create(
            db, owner_id=1, owner_role="admin", name="ci"
        )
        assert raw.startswith(TOKEN_PREFIX)
        assert record["name"] == "ci"
        assert record["revoked_at"] is None

    async def test_hash_not_reversible(self, db: Database) -> None:
        raw, _ = await TokenService().create(
            db, owner_id=1, owner_role="admin", name="x"
        )
        row = await db.fetch_one("SELECT token_hash FROM api_tokens")
        assert row["token_hash"] == _hash_token(raw)
        assert raw not in row["token_hash"]

    async def test_user_role_cannot_own(self, db: Database) -> None:
        with pytest.raises(TokenError) as exc:
            await TokenService().create(db, owner_id=3, owner_role="user", name="x")
        assert exc.value.error_code == "insufficient_role"

    async def test_ttl_sets_expires_at(self, db: Database) -> None:
        _, record = await TokenService().create(
            db, owner_id=1, owner_role="admin", name="t", ttl_seconds=3600
        )
        assert record["expires_at"] is not None

    async def test_limit_active_tokens(self, db: Database) -> None:
        svc = TokenService()
        for i in range(20):
            await svc.create(db, owner_id=1, owner_role="admin", name=f"t{i}")
        with pytest.raises(TokenError) as exc:
            await svc.create(db, owner_id=1, owner_role="admin", name="over")
        assert exc.value.error_code == "too_many_tokens"


class TestRotateRevoke:
    async def test_rotate_invalidates_old(self, db: Database) -> None:
        svc = TokenService()
        old_raw, old_rec = await svc.create(
            db, owner_id=1, owner_role="admin", name="a"
        )
        new_raw, _ = await svc.rotate(
            db, owner_id=1, owner_role="admin", token_id=old_rec["id"]
        )
        assert new_raw != old_raw
        row = await db.fetch_one(
            "SELECT * FROM api_tokens WHERE id = ?", (old_rec["id"],)
        )
        assert row["revoked_at"] is not None
        # старый больше не аутентифицирует, новый — да
        with pytest.raises(TokenError):
            await svc.authenticate(db, old_raw)
        session = await svc.authenticate(db, new_raw)
        assert session.user_id == 1

    async def test_revoke_instant(self, db: Database) -> None:
        svc = TokenService()
        raw, rec = await svc.create(db, owner_id=2, owner_role="support", name="s")
        assert await svc.revoke(db, owner_id=2, token_id=rec["id"]) is True
        with pytest.raises(TokenError) as exc:
            await svc.authenticate(db, raw)
        assert exc.value.error_code == "token_revoked"

    async def test_revoke_other_owner_404(self, db: Database) -> None:
        svc = TokenService()
        _, rec = await svc.create(db, owner_id=1, owner_role="admin", name="a")
        with pytest.raises(TokenError) as exc:
            await svc.revoke(db, owner_id=2, token_id=rec["id"])
        assert exc.value.error_code == "token_not_found"


class TestAuthenticate:
    async def test_role_inherited_dynamically(self, db: Database) -> None:
        svc = TokenService()
        raw, _ = await svc.create(db, owner_id=2, owner_role="support", name="s")
        session = await svc.authenticate(db, raw)
        assert session.role == "support"
        # понизили роль — токен мгновенно недействителен
        await db.execute("UPDATE users SET role = 'user' WHERE id = 2")
        with pytest.raises(TokenError):
            await svc.authenticate(db, raw)

    async def test_disabled_owner_rejected(self, db: Database) -> None:
        svc = TokenService()
        raw, _ = await svc.create(db, owner_id=1, owner_role="admin", name="a")
        await db.execute("UPDATE users SET enabled = 0 WHERE id = 1")
        with pytest.raises(TokenError):
            await svc.authenticate(db, raw)

    async def test_expired_rejected(self, db: Database) -> None:
        svc = TokenService()
        raw, rec = await svc.create(
            db, owner_id=1, owner_role="admin", name="e", ttl_seconds=3600
        )
        await db.execute(
            "UPDATE api_tokens SET expires_at = '2000-01-01T00:00:00+00:00'"
            " WHERE id = ?",
            (rec["id"],),
        )
        with pytest.raises(TokenError) as exc:
            await svc.authenticate(db, raw)
        assert exc.value.error_code == "token_expired"

    async def test_unknown_token_rejected(self, db: Database) -> None:
        with pytest.raises(TokenError):
            await TokenService().authenticate(db, TOKEN_PREFIX + "unknown")


class TestHook:
    async def test_revoke_user_tokens(self, db: Database) -> None:
        svc = TokenService()
        raw1, _ = await svc.create(db, owner_id=1, owner_role="admin", name="a1")
        raw2, _ = await svc.create(db, owner_id=1, owner_role="admin", name="a2")
        raw3, _ = await svc.create(db, owner_id=2, owner_role="support", name="s1")
        count = await svc.revoke_user_tokens(db, 1)
        assert count == 2
        for raw in (raw1, raw2):
            with pytest.raises(TokenError):
                await svc.authenticate(db, raw)
        await svc.authenticate(db, raw3)  # чужой не отозван
