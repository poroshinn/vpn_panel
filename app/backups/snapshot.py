"""Безопасный SQLite-снапшот (FR-3.10.10, FR-3.11.1).

Снапшот делается в безопасный момент записи: под writer-lock панели (правило 1
AGENTS.md — один writer), с ``VACUUM INTO`` — это атомарный, consistent-снимок
БД средствами SQLite (не копия живого WAL-файла), затем gzip.

Формат снимка: ``.db.gz`` (gzip от чистого SQLite-файла) — один и тот же формат
для скачиваемого снимка, локальной ротации и Telegram-бэкапа (FR-3.11.7 —
один валидатор).

Локальная ротация: ``backups/local/`` — последние 7 файлов (FR-3.10.10).
"""

from __future__ import annotations

import asyncio
import gzip
import hashlib
import logging
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from app.core.config import get_settings
from app.db.database import Database

logger = logging.getLogger(__name__)

LOCAL_RETENTION = 7  # файлов (FR-3.10.10)

_SAFE_STAMP = re.compile(r"[^A-Za-z0-9._-]")


@dataclass(frozen=True)
class Snapshot:
    """Результат снапшота."""

    path: Path
    sha256: str
    size: int


def sha256_file(path: Path) -> str:
    """SHA-256 файла (стримово, без чтения в память целиком)."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _safe_name(stamp: str, prefix: str) -> str:
    clean = _SAFE_STAMP.sub("-", stamp)
    return f"{prefix}-{clean}.db.gz"


def _write_gzipped(src: Path, dst: Path) -> None:
    """gzip(src) → dst, атомарно (tmp + rename)."""
    tmp = dst.with_suffix(".db.gz.tmp")
    try:
        with open(src, "rb") as fin, gzip.open(tmp, "wb", compresslevel=6) as fout:
            for chunk in iter(lambda: fin.read(1 << 20), b""):
                fout.write(chunk)
        tmp.replace(dst)
    finally:
        tmp.unlink(missing_ok=True)


def rotate_local(directory: Path, keep: int = LOCAL_RETENTION) -> list[Path]:
    """Локальная ротация: оставить ``keep`` новейших ``*.db.gz``, удалить остальные."""
    files = sorted(directory.glob("*.db.gz"))
    removed: list[Path] = []
    for stale in files[:-keep] if len(files) > keep else []:
        stale.unlink(missing_ok=True)
        removed.append(stale)
    return removed


async def make_snapshot(
    db: Database,
    directory: Path | None = None,
    *,
    prefix: str = "panel",
    rotate: bool = True,
) -> Snapshot:
    """Безопасный снапшот текущей БД (FR-3.10.10, FR-3.11.1).

    ``VACUUM INTO`` выполняется под writer-lock — в безопасный момент записи;
    результат — консистентный файл БД, затем gzip. Ротация локальных копий
    (7 файлов) — только в каталоге локальной ротации.
    """
    if directory is None:
        target_dir = Path(get_settings().backup_dir) / "local"
    else:
        target_dir = Path(directory)
    target_dir.mkdir(parents=True, exist_ok=True)

    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    raw_path = target_dir / _safe_name(stamp, prefix).removesuffix(".db.gz")
    raw_path = raw_path.with_suffix(".db")
    gz_path = raw_path.with_suffix(".db.gz")

    async with db._write_lock:  # noqa: SLF001 — единый writer, безопасный момент
        def _vacuum() -> None:
            import sqlite3

            src = sqlite3.connect(str(db.path))
            try:
                src.execute("VACUUM INTO ?", (str(raw_path),))
            finally:
                src.close()

        await asyncio.to_thread(_vacuum)

    await asyncio.to_thread(_write_gzipped, raw_path, gz_path)
    raw_path.unlink(missing_ok=True)

    digest = await asyncio.to_thread(sha256_file, gz_path)
    size = gz_path.stat().st_size

    if rotate:
        removed = await asyncio.to_thread(rotate_local, target_dir)
        for r in removed:
            logger.info("Backup rotation: removed %s", r.name)

    logger.info("Snapshot created: %s (sha256=%s, %d bytes)", gz_path.name, digest[:12], size)
    return Snapshot(path=gz_path, sha256=digest, size=size)


async def pre_restore_snapshot(db: Database, directory: Path | None = None) -> Snapshot:
    """Обязательный пред-restore снапшот (FR-3.11.1) — скачиваемый."""
    if directory is None:
        target_dir = Path(get_settings().backup_dir) / "pre-restore"
    else:
        target_dir = Path(directory)
    target_dir.mkdir(parents=True, exist_ok=True)
    return await make_snapshot(db, target_dir, prefix="pre-restore", rotate=False)
