"""Unit-тесты app/core/security.py: argon2id, AES-256-GCM, мастер-ключ."""

from __future__ import annotations

import pytest

from app.core import security
from app.core.security import SecurityError, decrypt_secret, encrypt_secret, hash_password, verify_password


def test_password_hash_roundtrip() -> None:
    h = hash_password("s3cret-пароль")
    assert h.startswith("$argon2id$")
    assert verify_password(h, "s3cret-пароль")
    assert not verify_password(h, "wrong")


def test_verify_empty_hash() -> None:
    assert not verify_password("", "anything")


def test_encrypt_decrypt_roundtrip() -> None:
    token = encrypt_secret("ssh-password-123")
    assert token.startswith("v1:")
    assert "ssh-password-123" not in token
    assert decrypt_secret(token) == "ssh-password-123"


def test_decrypt_wrong_payload_format() -> None:
    with pytest.raises(SecurityError):
        decrypt_secret("deadbeef")
    with pytest.raises(SecurityError):
        decrypt_secret("v1:!!!!")


def test_decrypt_tampered_data() -> None:
    token = encrypt_secret("data")
    blob = bytearray(security._b64decode(token.removeprefix("v1:")))
    blob[-1] ^= 0xFF  # порча последнего байта шифротекста
    tampered = "v1:" + security._b64encode(bytes(blob))
    with pytest.raises(SecurityError):
        decrypt_secret(tampered)


def test_master_key_generated_and_reused(tmp_data_dir) -> None:
    key1 = security._load_master_key()
    assert len(key1) == 32
    key2 = security._load_master_key()
    assert key1 == key2
    key_file = tmp_data_dir / "master.key"
    assert key_file.exists()
    assert key_file.stat().st_mode & 0o777 == 0o600


def test_generated_token_prefix() -> None:
    tok = security.generate_token("awp")
    assert tok.startswith("awp_")
    assert len(tok) > 40
