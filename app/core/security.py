"""Криптопримитивы панели (FR-3.10, NFR-2): argon2id-хэши, AES-256-GCM.

Правило 3 AGENTS.md: секреты никогда не покидают процесс в открытом виде.
``PANEL_MASTER_KEY`` — обязателен; при отсутствии генерируется при первом
старте и сохраняется в файл ``data/master.key`` (volume-каталог).
"""

from __future__ import annotations

import base64
import binascii
import os
import secrets
from pathlib import Path

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.core.config import get_settings

# argon2id, параметры по умолчанию OWASP-профиля библиотеки argon2-cffi
_password_hasher = PasswordHasher()

_NONCE_LEN = 12  # байт nonce для AES-GCM


class SecurityError(Exception):
    """Ошибка криптографических операций (ключ, формат, целостность)."""


# ---------------------------------------------------------------- argon2id


def hash_password(password: str) -> str:
    """argon2id-хэш пароля (в БД хранится только хэш)."""
    return _password_hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    """Проверка пароля по argon2id-хэшу; неверный пароль / битый хэш → False."""
    if not password_hash:
        return False
    try:
        return _password_hasher.verify(password_hash, password)
    except VerifyMismatchError:
        return False
    except Exception:  # noqa: BLE001 — битый/чужой формат хэша
        return False


def needs_rehash(password_hash: str) -> bool:
    """True, если хэш устарел по параметрам (требуется перехэширование)."""
    try:
        return _password_hasher.check_needs_rehash(password_hash)
    except Exception:  # noqa: BLE001
        return False


# ------------------------------------------------------- AES-256-GCM


def _b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii")


def _b64decode(text: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(text.encode("ascii"))
    except (binascii.Error, ValueError, UnicodeEncodeError) as exc:
        raise SecurityError("invalid encrypted payload encoding") from exc


def _load_master_key() -> bytes:
    """Мастер-ключ AES-256 (32 байта): из settings либо из файла, иначе генерация.

    Ключ в файле хранится hex-строкой; файл создаётся с правами 0600 в каталоге
    рядом с БД (volume-каталог ``data/``).
    """
    settings = get_settings()
    if settings.panel_master_key:
        try:
            return bytes.fromhex(settings.panel_master_key)
        except ValueError as exc:
            raise SecurityError("PANEL_MASTER_KEY must be 64 hex chars") from exc

    key_file = Path(settings.db_file).parent / "master.key"
    if key_file.exists():
        try:
            key = bytes.fromhex(key_file.read_text(encoding="utf-8").strip())
        except ValueError as exc:
            raise SecurityError(f"corrupted master key file: {key_file}") from exc
        if len(key) != 32:
            raise SecurityError("master key file must contain 32-byte hex key")
        return key

    key = AESGCM.generate_key(256)
    key_file.parent.mkdir(parents=True, exist_ok=True)
    key_file.write_text(key.hex() + "\n", encoding="utf-8")
    key_file.chmod(0o600)
    return key


def _aesgcm() -> AESGCM:
    return AESGCM(_load_master_key())


def encrypt_secret(plaintext: str) -> str:
    """AES-256-GCM шифрование строки → ``v1:<b64(nonce|ciphertext)>``."""
    nonce = os.urandom(_NONCE_LEN)
    blob = nonce + _aesgcm().encrypt(nonce, plaintext.encode("utf-8"), None)
    return "v1:" + _b64encode(blob)


def decrypt_secret(token: str) -> str:
    """Расшифровка AES-256-GCM; неверный ключ/данные → :class:`SecurityError`."""
    if not token or not token.startswith("v1:"):
        raise SecurityError("unknown encrypted payload format")
    blob = _b64decode(token.removeprefix("v1:"))
    if len(blob) <= _NONCE_LEN:
        raise SecurityError("encrypted payload too short")
    nonce, ciphertext = blob[:_NONCE_LEN], blob[_NONCE_LEN:]
    try:
        return _aesgcm().decrypt(nonce, ciphertext, None).decode("utf-8")
    except Exception as exc:  # noqa: BLE001 — InvalidTag и др.
        raise SecurityError("decryption failed (wrong key or tampered data)") from exc


# ------------------------------------------------------- генераторы


def generate_token(prefix: str, length: int = 32) -> str:
    """Криптостойкий токен вида ``{prefix}_<secrets>`` (Bearer/share)."""
    return f"{prefix}_{secrets.token_urlsafe(length)}"
