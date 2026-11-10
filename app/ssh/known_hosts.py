"""TOFU-хранилище отпечатков SSH-хостов (FR-3.1.5).

Trust-On-First-Use: отпечаток host key при первом подключении сохраняется в
файл доверия панели ``ssh_known_hosts`` (в volume-каталоге); последующие
подключения сверяются. Смена отпечатка — :class:`HostKeyMismatch` (ошибка +
audit-событие на уровне вызывающего кода, правило 3 AGENTS.md — секреты не
логируются, только отпечатки).

Формат файла (по строке на запись)::

    <host> <port> <key_type> <sha256_fingerprint> <first_seen_iso_utc>
"""

from __future__ import annotations

import hashlib
import logging
from datetime import UTC, datetime
from pathlib import Path

from app.core.config import get_settings

logger = logging.getLogger(__name__)

HOST_KEY_TYPES = (
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ssh-rsa",
)


class HostKeyMismatchError(Exception):
    """Отпечаток хоста не совпал с сохранённым (возможен MITM)."""


# Обратная совместимость имени (использовалось до переименования)
HostKeyMismatch = HostKeyMismatchError


class KnownHostsStore:
    """Файловое TOFU-хранилище отпечатков: ``{host}:{port} -> sha256``."""

    def __init__(self, path: Path | None = None) -> None:
        if path is None:
            settings = get_settings()
            path = Path(settings.db_file).parent / "ssh_known_hosts"
        self._path = path

    @property
    def path(self) -> Path:
        return self._path

    # ------------------------------------------------------------- helpers

    @staticmethod
    def entry_id(host: str, port: int) -> str:
        """Ключ записи: ``host:port`` (порт нестандартный важен для уникальности)."""
        return f"{host}:{port}"

    @staticmethod
    def fingerprint(public_key_bytes: bytes) -> str:
        """SHA-256 отпечаток публичного ключа в формате OpenSSH ``SHA256:...``."""
        digest = hashlib.sha256(public_key_bytes).digest()
        # base64 без паддинга, как в ssh-keygen -lf
        import base64

        return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")

    def _load(self) -> dict[str, tuple[str, str, str]]:
        """Загрузить хранилище: entry_id -> (key_type, fingerprint, first_seen)."""
        entries: dict[str, tuple[str, str, str]] = {}
        if not self._path.exists():
            return entries
        try:
            for line in self._path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if len(parts) != 5:
                    logger.warning("skipping malformed known-hosts line")
                    continue
                entry_id = f"{parts[0]}:{parts[1]}"
                entries[entry_id] = (parts[2], parts[3], parts[4])
        except OSError:
            logger.exception("failed to read known-hosts file %s", self._path)
        return entries

    def _save(self, entries: dict[str, tuple[str, str, str]]) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        lines = []
        for entry_id, (key_type, fingerprint, first_seen) in sorted(entries.items()):
            host, _, port = entry_id.rpartition(":")
            lines.append(f"{host} {port} {key_type} {fingerprint} {first_seen}")
        content = "\n".join(lines) + ("\n" if lines else "")
        tmp = self._path.with_suffix(".tmp")
        tmp.write_text(content, encoding="utf-8")
        tmp.replace(self._path)
        self._path.chmod(0o600)

    # -------------------------------------------------------------- public

    def get(self, host: str, port: int) -> tuple[str, str] | None:
        """Сохранённый отпечаток: ``(key_type, fingerprint)`` либо None (TOFU)."""
        entry = self._load().get(self.entry_id(host, port))
        return (entry[0], entry[1]) if entry else None

    def verify(
        self, host: str, port: int, key_type: str, fingerprint: str
    ) -> bool:
        """Проверить отпечаток. None в хранилище → TOFU-закрепление и True.

        Совпадение → True. Несовпадение → :class:`HostKeyMismatch`.
        """
        entries = self._load()
        entry_id = self.entry_id(host, port)
        saved = entries.get(entry_id)
        if saved is None:
            self.pin(host, port, key_type, fingerprint)
            return True
        if saved[1] != fingerprint:
            raise HostKeyMismatch(
                f"host key fingerprint mismatch for {host}:{port} "
                f"(saved {saved[1]}, got {fingerprint})"
            )
        return True

    def pin(self, host: str, port: int, key_type: str, fingerprint: str) -> None:
        """Сохранить/заменить отпечаток (замена — только явным вызовом admin'ом)."""
        entries = self._load()
        entry_id = self.entry_id(host, port)
        first_seen = entries[entry_id][2] if entry_id in entries else (
            datetime.now(UTC).isoformat(timespec="seconds")
        )
        entries[entry_id] = (key_type, fingerprint, first_seen)
        self._save(entries)

    def remove(self, host: str, port: int) -> bool:
        """Удалить запись (например, перед повторным TOFU по решению admin'а)."""
        entries = self._load()
        entry_id = self.entry_id(host, port)
        if entry_id not in entries:
            return False
        del entries[entry_id]
        self._save(entries)
        return True
