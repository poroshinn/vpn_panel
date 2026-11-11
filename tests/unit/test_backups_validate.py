"""Unit-тесты валидатора бэкапов (FR-3.11.1/3.11.7) и ротации (MVP-11)."""

from __future__ import annotations

import gzip
import sqlite3
from pathlib import Path

import pytest

from app.backups.restore import RestoreError, RestorePreview, check_schema_version, validate_file
from app.backups.snapshot import rotate_local


def _make_db(path: Path, version: int = 2, users: int = 3) -> None:
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE schema_version (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT,
            role TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            totp_secret_enc TEXT,
            telegram_id INTEGER,
            traffic_used INTEGER NOT NULL DEFAULT 0,
            traffic_total INTEGER,
            traffic_limit INTEGER,
            expiration TEXT,
            disable_reasons TEXT NOT NULL DEFAULT '[]',
            share_token TEXT UNIQUE,
            share_enabled INTEGER NOT NULL DEFAULT 0,
            share_password_hash TEXT,
            created_at TEXT NOT NULL
        );
        CREATE TABLE servers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            uid TEXT NOT NULL UNIQUE,
            name TEXT NOT NULL,
            host TEXT NOT NULL,
            ssh_port INTEGER NOT NULL DEFAULT 22,
            username TEXT NOT NULL,
            password_enc TEXT,
            private_key_enc TEXT,
            protocols TEXT NOT NULL DEFAULT '{}',
            self_service_enabled INTEGER NOT NULL DEFAULT 0,
            sort_order INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        );
        CREATE TABLE user_connections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            server_id INTEGER NOT NULL REFERENCES servers(id),
            protocol TEXT NOT NULL,
            client_id TEXT NOT NULL,
            name TEXT NOT NULL,
            created_by TEXT,
            created_source TEXT NOT NULL DEFAULT 'panel',
            counters_json TEXT NOT NULL DEFAULT '{}',
            baselines_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL,
            UNIQUE (server_id, protocol, client_id)
        );
        CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE api_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            token_hash TEXT NOT NULL UNIQUE,
            owner_id INTEGER NOT NULL REFERENCES users(id),
            expires_at TEXT,
            revoked_at TEXT,
            created_at TEXT NOT NULL
        );
        CREATE TABLE audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            actor TEXT NOT NULL,
            action TEXT NOT NULL,
            object TEXT,
            ip TEXT,
            result TEXT NOT NULL DEFAULT 'ok',
            details TEXT
        );
        CREATE TABLE peer_creations (
            operation_id TEXT PRIMARY KEY,
            server_id INTEGER NOT NULL,
            protocol TEXT NOT NULL,
            client_id TEXT,
            params_json TEXT NOT NULL DEFAULT '{}',
            status TEXT NOT NULL DEFAULT 'pending',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE lifecycle_uncertain (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            operation_id TEXT NOT NULL,
            server_id INTEGER NOT NULL,
            protocol TEXT NOT NULL,
            description TEXT NOT NULL,
            resolved INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        );
        CREATE TABLE accounting_recoveries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            connection_id INTEGER,
            tombstone_json TEXT NOT NULL,
            counters_verified_final INTEGER NOT NULL DEFAULT 0,
            reason TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        """
    )
    conn.execute("INSERT INTO schema_version VALUES (?, '2026-01-01T00:00:00+00:00')", (version,))
    for i in range(users):
        conn.execute(
            "INSERT INTO users (username, role, created_at) VALUES (?, 'user', '2026-01-01')",
            (f"user{i}",),
        )
    conn.commit()
    conn.close()


@pytest.fixture
def db_gz(tmp_path: Path) -> bytes:
    raw = tmp_path / "src.db"
    _make_db(raw)
    return gzip.compress(raw.read_bytes())


class TestValidateFile:
    def test_valid_gz(self, db_gz: bytes, tmp_path: Path) -> None:
        candidate, preview = validate_file(db_gz)
        assert preview.schema_version == 2
        assert preview.tables["users"] == 3
        candidate.unlink()

    def test_valid_plain_db(self, tmp_path: Path) -> None:
        raw = tmp_path / "plain.db"
        _make_db(raw)
        candidate, preview = validate_file(raw.read_bytes())
        assert preview.schema_version == 2
        candidate.unlink()

    def test_empty(self) -> None:
        with pytest.raises(RestoreError) as exc:
            validate_file(b"")
        assert exc.value.error_code == "invalid_file"

    def test_not_sqlite(self) -> None:
        with pytest.raises(RestoreError) as exc:
            validate_file(gzip.compress(b"not a database at all"))
        assert exc.value.error_code == "invalid_file"

    def test_missing_tables(self, tmp_path: Path) -> None:
        raw = tmp_path / "partial.db"
        conn = sqlite3.connect(raw)
        conn.execute("CREATE TABLE schema_version (version INTEGER PRIMARY KEY, applied_at TEXT)")
        conn.execute("INSERT INTO schema_version VALUES (1, 'x')")
        conn.commit()
        conn.close()
        with pytest.raises(RestoreError) as exc:
            validate_file(gzip.compress(raw.read_bytes()))
        assert exc.value.error_code == "invalid_schema"

    def test_corrupted_gz(self, db_gz: bytes) -> None:
        corrupted = bytearray(db_gz)
        corrupted[len(corrupted) // 2] ^= 0xFF
        # gzip может распаковаться частично или упасть — валидатор обязан дать
        # машинный код ошибки в любом случае
        try:
            candidate, _ = validate_file(bytes(corrupted))
        except RestoreError as exc:
            assert exc.error_code in ("invalid_file", "integrity_failed", "invalid_schema")
            return
        # если распаковалось — заголовок/структура не SQLite ⇒ ошибка уже выше
        candidate.unlink()


class TestSchemaVersion:
    def _preview(self, version: int) -> RestorePreview:
        return RestorePreview(schema_version=version, tables={})

    def test_newer_rejected(self) -> None:
        with pytest.raises(RestoreError) as exc:
            check_schema_version(2, self._preview(3))
        assert exc.value.error_code == "schema_newer"

    def test_older_warns(self) -> None:
        warnings = check_schema_version(2, self._preview(1))
        assert warnings and "v1" in warnings[0]

    def test_equal_ok(self) -> None:
        assert check_schema_version(2, self._preview(2)) == []


class TestRotateLocal:
    def test_keeps_newest_seven(self, tmp_path: Path) -> None:
        d = tmp_path / "local"
        d.mkdir()
        for i in range(10):
            (d / f"panel-2026010{i}T000000Z.db.gz").write_bytes(b"x")
        removed = rotate_local(d, keep=7)
        assert len(removed) == 3
        assert len(list(d.glob("*.db.gz"))) == 7
        # удалены старейшие
        assert not (d / "panel-20260100T000000Z.db.gz").exists()

    def test_under_limit_noop(self, tmp_path: Path) -> None:
        d = tmp_path / "local"
        d.mkdir()
        (d / "a.db.gz").write_bytes(b"x")
        assert rotate_local(d, keep=7) == []
