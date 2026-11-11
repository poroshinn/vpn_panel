"""In-panel restore (FR-3.11.1, FR-3.11.3, FR-3.11.7, сценарий §5.6).

Поток: загрузка файла (``.db``/``.db.gz`` — один валидатор для панели и
Telegram-бэкапа) → валидация (gzip, SQLite integrity check, версия схемы) →
превью → обязательный пред-restore снапшот → атомарная замена файла БД +
переоткрытие соединения процесса (без остановки процесса) → protected-профиль.

Protected-профиль (FR-3.11.3):
- **merge-безопасный** (по умолчанию): после замены файла восстанавливаются
  текущие учётные записи — счётчики/базлайны/lifetime/флаг верифицированности
  ``user_connections`` и колонки квот/учёта ``users`` (ownership сохраняется
  автоматически: замена БД меняет учётные строки, но привязки переписываются
  назад из снапшота-предка);
- **полное восстановление**: только с подтверждением текстом
  (``confirm_text`` = "restore"); попытка отмотать защищённые записи без
  подтверждения ⇒ 409 (``protected_records``).

Ошибка применения ⇒ автооткат к пред-restore снапшоту + понятная ошибка.
"""

from __future__ import annotations

import gzip
import logging
import sqlite3
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.backups.snapshot import pre_restore_snapshot
from app.core.audit import log_event
from app.db.database import Database

logger = logging.getLogger(__name__)

CONFIRM_FULL_RESTORE = "restore"

# Защищённые учётные данные (FR-3.11.3): счётчики/базлайны/ownership-квоты
PROTECTED_CONN_COLUMNS = (
    "rx_base", "tx_base", "lifetime_rx", "lifetime_tx",
    "last_sample_at", "counters_verified_final",
)
PROTECTED_USER_COLUMNS = (
    "traffic_used", "traffic_limit", "expiration", "traffic_reset_month",
)

_EXPECTED_TABLES = {
    "schema_version", "users", "servers", "user_connections", "settings",
    "audit_log", "peer_creations", "accounting_recoveries",
}


class RestoreError(RuntimeError):
    """Ошибка restore с машинным кодом (правило 9 AGENTS.md)."""

    def __init__(
        self, error_code: str, message: str, *, details: dict[str, Any] | None = None
    ) -> None:
        super().__init__(message)
        self.error_code = error_code
        self.message = message
        self.details = details or {}


@dataclass
class RestorePreview:
    """Превью файла бэкапа до применения."""

    schema_version: int
    tables: dict[str, int] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)


def gunzip_to_tmp(data: bytes, workdir: Path) -> Path:
    """Распаковка ``.db.gz`` (или проход ``.db`` насквозь) во временный файл."""
    target = workdir / "candidate.db"
    if data[:2] == b"\x1f\x8b":
        try:
            raw = gzip.decompress(data)
        except (OSError, EOFError) as exc:
            raise RestoreError("invalid_file", "Corrupted gzip archive") from exc
    else:
        raw = data
    target.write_bytes(raw)
    return target


def validate_file(data: bytes) -> tuple[Path, RestorePreview]:
    """Валидация файла бэкапа (один валидатор: панель и Telegram — FR-3.11.7).

    Возвращает (путь к распакованному файлу, превью). Поднимает
    :class:`RestoreError` с машинным кодом при любой проблеме.
    """
    if not data:
        raise RestoreError("invalid_file", "Backup file is empty")
    max_size = 512 * 1024 * 1024
    if len(data) > max_size:
        raise RestoreError("invalid_file", "Backup file too large",
                           details={"size": len(data)})

    import tempfile as _tempfile
    workdir = Path(_tempfile.mkdtemp(prefix="restore-"))
    candidate = gunzip_to_tmp(data, workdir)

    # SQLite header
    header = candidate.read_bytes()[:16]
    if not header.startswith(b"SQLite format 3\x00"):
        raise RestoreError("invalid_file", "Not a SQLite database file")

    # integrity check + чтение метаданных — отдельным синхронным соединением
    try:
        conn = sqlite3.connect(f"file:{candidate}?mode=ro", uri=True)
        try:
            (result,) = conn.execute("PRAGMA integrity_check").fetchone()
            if result != "ok":
                raise RestoreError("integrity_failed", f"SQLite integrity check failed: {result}")
            tables = {
                row[0] for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
            missing = _EXPECTED_TABLES - tables
            if missing:
                raise RestoreError(
                    "invalid_schema", "Backup is missing panel tables",
                    details={"missing": sorted(missing)},
                )
            row = conn.execute("SELECT MAX(version) FROM schema_version").fetchone()
            schema_version = int(row[0] or 0)

            counts: dict[str, int] = {}
            for table in sorted(tables - {"sqlite_sequence"}):
                # имя таблицы из sqlite_master, а не пользовательский ввод
                quoted = '"' + table.replace('"', '""') + '"'
                # ruff флагует строку f-строки, noqa — на ней
                sql = f"SELECT COUNT(*) FROM {quoted}"  # noqa: S608
                row = conn.execute(sql).fetchone()
                counts[table] = int(row[0])
        finally:
            conn.close()
    except sqlite3.DatabaseError as exc:
        raise RestoreError(
            "integrity_failed", f"Cannot read database file: {type(exc).__name__}"
        ) from exc

    return candidate, RestorePreview(schema_version=schema_version, tables=counts)


def check_schema_version(current_version: int, preview: RestorePreview) -> list[str]:
    """Проверка версии схемы бэкапа против текущей; возвращает предупреждения.

    Версия бэкапа **новее** текущей ⇒ отказ (downgrade панели недопустим).
    Версия бэкапа старше ⇒ предупреждение: при старте применятся миграции.
    """
    warnings: list[str] = []
    if preview.schema_version > current_version:
        raise RestoreError(
            "schema_newer",
            f"Backup schema version {preview.schema_version} is newer than "
            f"panel schema {current_version}; upgrade the panel first",
            details={"backup_version": preview.schema_version, "current_version": current_version},
        )
    if preview.schema_version < current_version:
        warnings.append(
            f"backup schema v{preview.schema_version} < current v{current_version}; "
            "migrations will run after restore"
        )
    return warnings


def _capture_protected(conn: sqlite3.Connection) -> dict[str, Any]:
    """Слепок защищённых записей текущей БД (merge-профиль)."""
    protected: dict[str, Any] = {"connections": {}, "users": {}}
    cols = ", ".join(PROTECTED_CONN_COLUMNS)
    # nosec: имена колонок — константы модуля, не пользовательский ввод
    for row in conn.execute(
        f"SELECT id, {cols} FROM user_connections"  # noqa: S608 — колонки-константы
    ).fetchall():
        protected["connections"][row[0]] = row[1:]
    cols_u = ", ".join(PROTECTED_USER_COLUMNS)
    for row in conn.execute(f"SELECT id, {cols_u} FROM users").fetchall():  # noqa: S608
        protected["users"][row[0]] = row[1:]
    return protected


def _restore_protected(conn: sqlite3.Connection, protected: dict[str, Any]) -> int:
    """Запись защищённых значений поверх восстановленных. Возвращает число строк."""
    updated = 0
    cols = PROTECTED_CONN_COLUMNS
    assignments = ", ".join(f"{c} = ?" for c in cols)
    for conn_id, values in protected["connections"].items():
        cur = conn.execute(
            f"UPDATE user_connections SET {assignments} WHERE id = ?",  # noqa: S608 — константы
            (*values, conn_id),
        )
        updated += cur.rowcount if cur.rowcount > 0 else 0
    cols_u = PROTECTED_USER_COLUMNS
    assignments_u = ", ".join(f"{c} = ?" for c in cols_u)
    for user_id, values in protected["users"].items():
        cur = conn.execute(
            f"UPDATE users SET {assignments_u} WHERE id = ?",  # noqa: S608 — константы
            (*values, user_id),
        )
        updated += cur.rowcount if cur.rowcount > 0 else 0
    return updated


def _detect_rollback_attempt(
    current: sqlite3.Connection, candidate: sqlite3.Connection
) -> bool:
    """Детекция попытки отмотать защищённые записи (FR-3.11.3 → 409).

    Сравниваются lifetime-итоги соединений и квоты пользователей: в бэкапе
    значения строго меньше текущих ⇒ отмотка.
    """
    try:
        cur_max = current.execute(
            "SELECT COALESCE(SUM(lifetime_rx + lifetime_tx), 0) FROM user_connections"
        ).fetchone()[0]
        cand_max = candidate.execute(
            "SELECT COALESCE(SUM(lifetime_rx + lifetime_tx), 0) FROM user_connections"
        ).fetchone()[0]
        if cand_max < cur_max:
            return True
        cur_users = current.execute(
            "SELECT COALESCE(SUM(traffic_used), 0) FROM users"
        ).fetchone()[0]
        cand_users = candidate.execute(
            "SELECT COALESCE(SUM(traffic_used), 0) FROM users"
        ).fetchone()[0]
        return cand_users < cur_users
    except sqlite3.DatabaseError:
        return False


class RestoreService:
    """In-panel restore: валидация, превью, применение, откат (FR-3.11.1)."""

    def __init__(self, db: Database, backup_root: Path) -> None:
        self._db = db
        self._backup_root = Path(backup_root)
        self.last_preview: RestorePreview | None = None

    # ------------------------------------------------------------ preview

    async def preview(self, data: bytes) -> tuple[RestorePreview, list[str]]:
        """Валидация + превью (версия, число записей, предупреждения)."""
        candidate, preview = await _to_thread(validate_file, data)
        from app.db.migrator import get_schema_version

        current = await get_schema_version(self._db)
        warnings = check_schema_version(current, preview)
        candidate.unlink(missing_ok=True)
        self.last_preview = preview
        return preview, warnings

    # ------------------------------------------------------------- apply

    async def apply(
        self,
        data: bytes,
        *,
        confirm_text: str | None = None,
        keep_protected: bool = True,
    ) -> dict[str, Any]:
        """Применение файла бэкапа к живой БД (§5.6).

        Шаги: валидация → детекция отмотки → пред-restore снапшот →
        атомарная замена + переоткрытие → merge-профиль (protected) →
        при сбое — автооткат.
        """
        if keep_protected and confirm_text == CONFIRM_FULL_RESTORE:
            raise RestoreError(
                "invalid_request",
                "confirm_text='restore' means full restore; pass keep_protected=false",
            )

        candidate, preview = await _to_thread(validate_file, data)
        from app.db.migrator import get_schema_version

        current_version = await get_schema_version(self._db)
        warnings = check_schema_version(current_version, preview)

        # детекция отмотки защищённых записей (409 без подтверждения — FR-3.11.3)
        rollback_attempt = await _to_thread(
            self._rollback_attempt, candidate, keep_protected
        )
        if rollback_attempt and (
            keep_protected is False and confirm_text != CONFIRM_FULL_RESTORE
        ):
            candidate.unlink(missing_ok=True)
            raise RestoreError(
                "protected_records",
                "Backup would roll back protected accounting/ownership records; "
                f"confirm with text '{CONFIRM_FULL_RESTORE}' for full restore",
            )

        # обязательный пред-restore снапшот (FR-3.11.1)
        pre = await pre_restore_snapshot(self._db, self._backup_root / "pre-restore")

        try:
            await self._swap(candidate, keep_protected)
        except Exception as exc:  # noqa: BLE001 — автооткат к пред-restore снапшоту
            logger.exception("restore failed, rolling back to %s", pre.path)
            import gzip as _gzip

            raw = await _to_thread(lambda: _gzip.open(pre.path, "rb").read())
            rollback_candidate, _ = validate_file(raw)
            await self._swap(rollback_candidate, keep_protected=False)
            raise RestoreError(
                "restore_failed",
                f"Restore failed and was rolled back to pre-restore snapshot: "
                f"{type(exc).__name__}",
            ) from exc

        candidate.unlink(missing_ok=True)
        await log_restore(self._db, preview, keep_protected, warnings)
        return {
            "restored": True,
            "schema_version": preview.schema_version,
            "tables": preview.tables,
            "warnings": warnings,
            "pre_restore_snapshot": pre.path.name,
            "pre_restore_sha256": pre.sha256,
            "protected_kept": keep_protected,
        }

    def _rollback_attempt(
        self, candidate: Path, keep_protected: bool
    ) -> bool:
        if keep_protected:
            return False  # merge-профиль не отматывает защищённые записи
        cur = sqlite3.connect(f"file:{self._db.path}?mode=ro", uri=True)
        cand = sqlite3.connect(f"file:{candidate}?mode=ro", uri=True)
        try:
            return _detect_rollback_attempt(cur, cand)
        finally:
            cur.close()
            cand.close()

    async def _swap(self, candidate: Path, keep_protected: bool) -> None:
        """Атомарная замена файла БД + переоткрытие соединения процесса.

        ВАЖНО: writer-lock панели не реентерабельный — внутри него нельзя
        вызывать ``db.transaction()``/``db.execute``. Мерж защищённых записей
        выполняется через собственное sqlite3-соединение к файлу до переоткрытия.
        """
        db_path = self._db.path
        protected: dict[str, Any] | None = None

        async with self._db._write_lock:  # noqa: SLF001 — единственный writer

            def _capture() -> None:
                nonlocal protected
                if not keep_protected:
                    return
                src = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
                try:
                    protected = _capture_protected(src)
                finally:
                    src.close()

            def _atomic_replace_and_merge() -> None:
                if protected is not None:
                    conn = sqlite3.connect(str(candidate))
                    try:
                        updated = _restore_protected(conn, protected)
                        logger.info("protected records restored: %d rows", updated)
                        conn.commit()
                    finally:
                        conn.close()
                # WAL/SHM старой БД больше не актуальны — удаляем рядом
                for suffix in ("-wal", "-shm"):
                    Path(str(db_path) + suffix).unlink(missing_ok=True)
                import shutil

                target = db_path.with_suffix(".db.restore-new")
                shutil.copy2(candidate, target)
                target.replace(db_path)

            await _to_thread(_capture)
            await _to_thread(_atomic_replace_and_merge)
            await self._db.close()
            await self._db.connect()

        logger.info("Database file replaced; connection reopened")


async def _to_thread(func, /, *args):
    import asyncio

    return await asyncio.to_thread(func, *args)


async def log_restore(
    db: Database, preview: RestorePreview, keep_protected: bool, warnings: list[str]
) -> None:
    """Audit-событие восстановления (FR-3.16.2: бэкапы/восстановления)."""
    await log_event(
        db, "system", "backup.restored",
        details={
            "schema_version": preview.schema_version,
            "protected_kept": keep_protected,
            "warnings": warnings,
            "at": datetime.now(UTC).isoformat(timespec="seconds"),
        },
    )
