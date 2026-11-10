"""Unit-тесты эпох и парсера transfer (MVP-07, FR-3.5.1, FR-3.5.3)."""

from __future__ import annotations

from app.accounting.epochs import (
    EpochMeta,
    epoch_hash,
    epochs_differ,
    parse_epoch_meta,
    parse_transfer,
)

# ------------------------------------------------------------ transfer


def test_parse_transfer_basic() -> None:
    raw = (
        "5Ks3tJ9qZ0hXk2mVq7wLbN8pRcT1uYdAeFgHiJkLmNo=	1024	2048\n"
        "zzz8y7x6w5v4u3t2s1r0q9p8o7n6m5l4k3j2i1h0g=	100	200\n"
        "garbage line without tabs\n"
        "\n"
    )
    samples = parse_transfer(raw)
    assert len(samples) == 2
    first = samples["5Ks3tJ9qZ0hXk2mVq7wLbN8pRcT1uYdAeFgHiJkLmNo="]
    assert (first.rx, first.tx) == (1024, 2048)
    assert samples["zzz8y7x6w5v4u3t2s1r0q9p8o7n6m5l4k3j2i1h0g="].rx == 100


def test_parse_transfer_exact_integers() -> None:
    raw = "5Ks3tJ9qZ0hXk2mVq7wLbN8pRcT1uYdAeFgHiJkLmNo=	999999999999	1\n"
    samples = parse_transfer(raw)
    assert samples["5Ks3tJ9qZ0hXk2mVq7wLbN8pRcT1uYdAeFgHiJkLmNo="].rx == 999999999999


def test_parse_transfer_empty_and_garbage() -> None:
    assert parse_transfer("") == {}
    assert parse_transfer("hello\nworld\n") == {}


# --------------------------------------------------------------- эпохи


def _meta(**overrides: str) -> EpochMeta:
    base = {
        "container_id": "abc123",
        "started_at": "2026-11-10T00:00:00Z",
        "pid": "4242",
        "boot_id": "boot-1",
        "ifindex": "3",
        "socket_inode": "12345",
        "socket_ctime": "2026-11-10",
    }
    base.update(overrides)
    return EpochMeta(**base)


def test_epoch_hash_deterministic() -> None:
    assert epoch_hash(_meta()) == epoch_hash(_meta())


def test_epoch_hash_changes_on_any_component() -> None:
    base = epoch_hash(_meta())
    for changed in (
        _meta(container_id="zzz"),
        _meta(pid="1"),
        _meta(boot_id="boot-2"),
        _meta(ifindex="4"),
        _meta(socket_inode="999"),
        _meta(socket_ctime="2027"),
        _meta(started_at="2030"),
    ):
        assert epoch_hash(changed) != base


def test_epochs_differ() -> None:
    assert not epochs_differ(_meta(), _meta())
    assert epochs_differ(_meta(), _meta(pid="7"))


def test_parse_epoch_meta_full() -> None:
    raw = (
        "abc123def 4242 2026-11-10T00:00:00Z|boot-1|3|12345:2026-11-10\n"
    )
    meta = parse_epoch_meta(raw, "awg2")
    assert meta.container_id == "abc123def"
    assert meta.pid == "4242"
    assert meta.boot_id == "boot-1"
    assert meta.ifindex == "3"
    assert meta.socket_inode == "12345"
    assert meta.socket_ctime == "2026-11-10"


def test_parse_epoch_meta_partial_is_stable_and_changes() -> None:
    empty = parse_epoch_meta("", "awg2")
    assert epoch_hash(empty) == epoch_hash(parse_epoch_meta("", "awg2"))
    partial = parse_epoch_meta("|||12345\n", "awg2")
    assert partial.socket_inode == "12345"
    assert epoch_hash(empty) != epoch_hash(partial)


def test_epoch_meta_from_mapping_roundtrip() -> None:
    meta = _meta()
    restored = EpochMeta.from_mapping(meta.as_dict())
    assert epoch_hash(restored) == epoch_hash(meta)
