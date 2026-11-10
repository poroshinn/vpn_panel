"""Unit-тесты TOFU-хранилища отпечатков (MVP-04, mock-level)."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.ssh.known_hosts import HostKeyMismatch, KnownHostsStore

FP_A = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
FP_B = "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"


@pytest.fixture
def store(tmp_path: Path) -> KnownHostsStore:
    return KnownHostsStore(tmp_path / "ssh_known_hosts")


def test_tofu_first_use_pins(store: KnownHostsStore) -> None:
    assert store.get("node1", 22) is None
    assert store.verify("node1", 22, "ssh-ed25519", FP_A) is True
    saved = store.get("node1", 22)
    assert saved == ("ssh-ed25519", FP_A)


def test_same_fingerprint_passes(store: KnownHostsStore) -> None:
    store.pin("node1", 22, "ssh-ed25519", FP_A)
    assert store.verify("node1", 22, "ssh-ed25519", FP_A) is True


def test_mismatch_raises(store: KnownHostsStore) -> None:
    store.pin("node1", 22, "ssh-ed25519", FP_A)
    with pytest.raises(HostKeyMismatch):
        store.verify("node1", 22, "ssh-ed25519", FP_B)


def test_port_in_entry(store: KnownHostsStore) -> None:
    store.pin("node1", 2222, "ssh-ed25519", FP_A)
    # порт 22 — отдельная запись, TOFU заново
    assert store.get("node1", 22) is None
    assert store.get("node1", 2222) == ("ssh-ed25519", FP_A)


def test_remove(store: KnownHostsStore) -> None:
    store.pin("node1", 22, "ssh-ed25519", FP_A)
    assert store.remove("node1", 22) is True
    assert store.get("node1", 22) is None
    assert store.remove("node1", 22) is False


def test_file_persists_and_permissions(store: KnownHostsStore, tmp_path: Path) -> None:
    store.pin("node1", 22, "ssh-ed25519", FP_A)
    path = tmp_path / "ssh_known_hosts"
    assert path.exists()
    # POSIX-права: маска 0o777
    assert (path.stat().st_mode & 0o777) == 0o600
    # новый экземпляр магазина читает тот же файл
    assert KnownHostsStore(path).get("node1", 22) == ("ssh-ed25519", FP_A)


def test_first_seen_preserved_on_repin(store: KnownHostsStore) -> None:
    store.pin("node1", 22, "ssh-ed25519", FP_A)
    _, _, first_seen = store._load()["node1:22"]
    store.pin("node1", 22, "ssh-ed25519", FP_B)
    assert store.get("node1", 22) == ("ssh-ed25519", FP_B)
    assert store._load()["node1:22"][2] == first_seen


def test_fingerprint_format() -> None:
    fp = KnownHostsStore.fingerprint(b"public-key-bytes")
    assert fp.startswith("SHA256:")
    assert "=" not in fp  # без паддинга, как ssh-keygen
