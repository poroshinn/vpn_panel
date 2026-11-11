"""Integration-тесты бэкапов/восстановления (FR-3.10.10, FR-3.11.1/3.3/3.7)."""

from __future__ import annotations

import gzip
import sqlite3
from pathlib import Path

import pytest
from httpx import AsyncClient

from app.backups.snapshot import make_snapshot
from tests.integration.conftest import make_login


@pytest.fixture
async def admin_client(client: AsyncClient) -> AsyncClient:
    login = make_login(client)
    response = await login("admin", "admin")
    assert response.status_code == 200
    return client


def _make_backup_bytes(
    db_path: Path, *, mutate: bool = False
) -> bytes:
    """Снимок текущей БД приложения в bytes (.db.gz) — как Telegram-бэкап.

    ``mutate=True`` — мутация ТОЛЬКО экспортированного файла (учётные значения
    меньше текущих ⇒ попытка отмотки), живая БД не трогается.
    """
    target = db_path.parent / f"export-{abs(hash(mutate))}.db"
    target.unlink(missing_ok=True)
    src = sqlite3.connect(str(db_path))
    src.execute("VACUUM INTO ?", (str(target),))
    src.close()
    if mutate:
        conn = sqlite3.connect(target)
        conn.execute("UPDATE user_connections SET lifetime_rx = 0, lifetime_tx = 0")
        conn.commit()
        conn.close()
    data = target.read_bytes()
    target.unlink(missing_ok=True)
    return gzip.compress(data)


async def _seed_connection(client: AsyncClient) -> int:
    """Сервер + протокол + подключение, чтобы были учётные записи."""
    db = client.app.state.db
    await db.execute(
        "INSERT INTO servers (uid, name, host, username, created_at) "
        "VALUES ('srv-x', 'X', '10.0.0.9', 'root', '2026-01-01T00:00:00+00:00')"
    )
    server = await db.fetch_one("SELECT id FROM servers WHERE uid='srv-x'")
    await db.execute(
        "INSERT INTO user_connections (user_id, server_id, protocol, client_id, name, "
        "created_at, lifetime_rx, lifetime_tx) VALUES (1, ?, 'awg2', 'cl1', 'c1', "
        "'2026-01-01T00:00:00+00:00', 1000, 2000)",
        (server["id"],),
    )
    return server["id"]


class TestSnapshotApi:
    async def test_create_requires_admin(self, client: AsyncClient) -> None:
        response = await client.post("/api/v1/backups/snapshot")
        assert response.status_code == 401

    async def test_support_forbidden(self, client: AsyncClient, admin_client: AsyncClient) -> None:
        # создаём support отдельным клиентом (иначе cookie перезатрётся)
        await admin_client.post(
            "/api/v1/users",
            json={"username": "sup1", "role": "support", "password": "secret-pass-1"},
            headers={"X-Test-Client-IP": "10.0.0.9"},
        )
        login = make_login(client)
        await login("sup1", "secret-pass-1", ip="10.0.0.10")
        response = await client.post("/api/v1/backups/snapshot")
        assert response.status_code == 403

    async def test_create_and_download(self, admin_client: AsyncClient) -> None:
        response = await admin_client.post("/api/v1/backups/snapshot")
        assert response.status_code == 200
        body = response.json()
        assert body["sha256"] and body["size"] > 0

        listing = await admin_client.get("/api/v1/backups/snapshots")
        assert listing.status_code == 200
        manual = listing.json()["manual"]
        assert any(item["name"] == body["name"] for item in manual)

        download = await admin_client.get(
            f"/api/v1/backups/snapshots/manual/{body['name']}"
        )
        assert download.status_code == 200
        assert download.content[:2] == b"\x1f\x8b"


class TestRestoreFlow:
    async def test_snapshot_roundtrip(
        self, admin_client: AsyncClient, tmp_path: Path
    ) -> None:
        """Снапшот → «скачал» → restore из него (§5.6 end-to-end, happy-path)."""
        db_path: Path = admin_client.app.state.db.path
        snap = await make_snapshot(
            admin_client.app.state.db, tmp_path, prefix="t", rotate=False
        )
        data = snap.path.read_bytes()

        preview = await admin_client.post(
            "/api/v1/backups/restore/preview",
            files={"file": ("b.db.gz", data, "application/gzip")},
        )
        assert preview.status_code == 200
        assert preview.json()["schema_version"] >= 1

        # мутация в живой БД, чтобы restore был содержательным
        admin_db = admin_client.app.state.db
        await _seed_connection(admin_client)
        backup_bytes = _make_backup_bytes(db_path)

        # удаляем подключение из живой БД (в бэкапе оно есть)
        await admin_db.execute("DELETE FROM user_connections")
        await admin_db.execute("DELETE FROM servers WHERE uid='srv-x'")

        result = await admin_client.post(
            "/api/v1/backups/restore?keep_protected=false&confirm_text=restore",
            files={"file": ("b.db.gz", backup_bytes, "application/gzip")},
        )
        assert result.status_code == 200, result.text
        body = result.json()
        assert body["restored"] is True

        # данные восстановлены
        row = await admin_db.fetch_one("SELECT COUNT(*) AS n FROM user_connections")
        assert row["n"] == 1

    async def test_full_restore_without_confirm_409(
        self, admin_client: AsyncClient
    ) -> None:
        """Отмотка защищённых записей без текст-подтверждения ⇒ 409 (FR-3.11.3)."""
        db_path: Path = admin_client.app.state.db.path
        await _seed_connection(admin_client)
        backup_bytes = _make_backup_bytes(db_path, mutate=True)

        result = await admin_client.post(
            "/api/v1/backups/restore?keep_protected=false",
            files={"file": ("b.db.gz", backup_bytes, "application/gzip")},
        )
        assert result.status_code == 409
        assert result.json()["error_code"] == "protected_records"

    async def test_merge_profile_keeps_counters(
        self, admin_client: AsyncClient
    ) -> None:
        """Merge-профиль: восстановление, счётчики соединения не отмотаны."""
        db_path: Path = admin_client.app.state.db.path
        server_id = await _seed_connection(admin_client)
        backup_bytes = _make_backup_bytes(db_path)

        result = await admin_client.post(
            "/api/v1/backups/restore",
            files={"file": ("b.db.gz", backup_bytes, "application/gzip")},
        )
        assert result.status_code == 200, result.text
        assert result.json()["protected_kept"] is True

        row = await admin_client.app.state.db.fetch_one(
            "SELECT lifetime_rx FROM user_connections WHERE server_id=?", (server_id,)
        )
        assert row["lifetime_rx"] == 1000

    async def test_schema_newer_rejected(self, admin_client: AsyncClient) -> None:
        """Версия схемы бэкапа новее текущей ⇒ отказ (FR-3.11.1).

        Полная валидная схема (иначе invalid_schema раньше schema_newer),
        но версия 999 > текущей 2.
        """
        db_path: Path = admin_client.app.state.db.path
        backup_bytes = _make_backup_bytes(db_path)

        # правим версию в распакованном дампе и пакуем обратно
        import tempfile as _tmp

        raw = gzip.decompress(backup_bytes)
        candidate = Path(_tmp.mkdtemp()) / "future.db"
        candidate.write_bytes(raw)
        conn = sqlite3.connect(candidate)
        conn.execute("DELETE FROM schema_version")
        conn.execute("INSERT INTO schema_version VALUES (999, 'x')")
        conn.commit()
        conn.close()
        future_bytes = gzip.compress(candidate.read_bytes())
        candidate.unlink()

        result = await admin_client.post(
            "/api/v1/backups/restore",
            files={"file": ("f.db.gz", future_bytes, "application/gzip")},
        )
        assert result.status_code == 409
        assert result.json()["error_code"] == "schema_newer"

    async def test_invalid_file_rejected(self, admin_client: AsyncClient) -> None:
        result = await admin_client.post(
            "/api/v1/backups/restore",
            files={"file": ("x.db.gz", gzip.compress(b"junk"), "application/gzip")},
        )
        assert result.status_code == 400
        assert result.json()["error_code"] == "invalid_file"

    async def test_telegram_format_same_validator(
        self, admin_client: AsyncClient
    ) -> None:
        """Файл «из Telegram» (тот же .db.gz) восстанавливается тем же валидатором (FR-3.11.7)."""
        db_path: Path = admin_client.app.state.db.path
        backup_bytes = _make_backup_bytes(db_path)
        preview = await admin_client.post(
            "/api/v1/backups/restore/preview",
            files={"file": ("tg-backup.db.gz", backup_bytes, "application/gzip")},
        )
        assert preview.status_code == 200

    async def test_pre_restore_snapshot_created(
        self, admin_client: AsyncClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Обязательный пред-restore снапшот создаётся (FR-3.11.1)."""
        db_path: Path = admin_client.app.state.db.path
        backup_bytes = _make_backup_bytes(db_path)
        result = await admin_client.post(
            "/api/v1/backups/restore",
            files={"file": ("b.db.gz", backup_bytes, "application/gzip")},
        )
        assert result.status_code == 200
        assert result.json()["pre_restore_snapshot"]


class TestTelegramDaily:
    async def test_daily_backup_without_bot_degrades_locally(
        self, admin_client: AsyncClient
    ) -> None:
        """Бот не настроен ⇒ локальная ротация + алерт-флаг (FR-3.10.10)."""
        from app.backups.telegram import run_daily_backup

        db = admin_client.app.state.db
        await db.execute(
            "INSERT OR REPLACE INTO settings (key, value) VALUES "
            "('backup_telegram_enabled', '1')"
        )
        result = await run_daily_backup(db)
        assert result.delivered == "local"
        assert result.error == "telegram_not_configured"
        assert result.snapshot is not None and result.snapshot.path.exists()

        audit = await db.fetch_one(
            "SELECT * FROM audit_log WHERE action='backup.auto_failed' "
            "ORDER BY id DESC LIMIT 1"
        )
        assert audit is not None

    async def test_daily_backup_disabled_skips(self, admin_client: AsyncClient) -> None:
        from app.backups.telegram import run_daily_backup

        db = admin_client.app.state.db
        result = await run_daily_backup(db)
        assert result.delivered == "skipped"

    async def test_config_endpoint_never_echoes_token(
        self, admin_client: AsyncClient
    ) -> None:
        response = await admin_client.get("/api/v1/backups/telegram/config")
        assert response.status_code == 200
        body = response.json()
        assert "bot_token" not in body
        assert body["telegram_configured"] is False

    async def test_save_config_and_run_now(self, admin_client: AsyncClient) -> None:
        response = await admin_client.put(
            "/api/v1/backups/telegram/config",
            json={"enabled": True, "send_time_utc": "04:30"},
        )
        assert response.status_code == 200
        assert response.json()["enabled"] is True
        assert response.json()["send_time_utc"] == "04:30"

        run = await admin_client.post("/api/v1/backups/telegram/run")
        assert run.status_code == 200
        assert run.json()["delivered"] == "local"  # бот не настроен

        audit = await admin_client.app.state.db.fetch_one(
            "SELECT * FROM audit_log WHERE action='backup.manual_run'"
        )
        assert audit is not None
