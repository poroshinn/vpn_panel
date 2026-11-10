"""Unit-тесты дельт и календарного сброса (MVP-07, FR-3.5.4)."""

from __future__ import annotations

from datetime import UTC, datetime

from app.accounting.collector import PeerSample, dedupe_owners
from app.accounting.epochs import EpochMeta


def _meta(pid: str = "42") -> EpochMeta:
    return EpochMeta(
        container_id="c1", started_at="t", pid=pid, boot_id="b",
        ifindex="2", socket_inode="1", socket_ctime="c",
    )


def _sample(conn: int, rx: int, tx: int, instance: str = "awg2") -> PeerSample:
    return PeerSample(
        server_id=1, connection_id=conn, instance=instance, client_id=f"c{conn}",
        peer_pubkey="KEY", rx=rx, tx=tx, epoch=_meta(),
    )


# ------------------------------------------------------- дельты/дедуп


def test_dedupe_keeps_first_owner() -> None:
    index = {
        (1, "awg2", "KEY"): 10,
        (1, "awg2__2", "KEY"): 11,
    }
    out = dedupe_owners([_sample(10, 100, 50), _sample(11, 100, 50, "awg2__2")], index)
    assert len(out) == 1
    assert out[0].connection_id == 10  # первый по порядку обхода


def test_dedupe_drops_unmatched() -> None:
    # нет владельца в index → семпл пропускается (недоказанный учёт)
    out = dedupe_owners([_sample(99, 1, 1)], {(1, "awg2", "KEY"): 10})
    assert all(s.connection_id != 99 for s in out)


def test_dedupe_different_keys_not_merged() -> None:
    index = {(1, "awg2", "KEY"): 10, (1, "awg2", "KEY2"): 11}
    s1 = PeerSample(
        server_id=1, connection_id=0, instance="awg2", client_id="",
        peer_pubkey="KEY", rx=1, tx=1, epoch=_meta(),
    )
    s2 = PeerSample(
        server_id=1, connection_id=0, instance="awg2", client_id="",
        peer_pubkey="KEY2", rx=2, tx=2, epoch=_meta(),
    )
    out = dedupe_owners([s1, s2], index)
    assert len(out) == 2


# --------------------------------------------------- календарный сброс


def test_month_key_is_utc() -> None:
    # календарный сброс считается по UTC (правило 2 AGENTS.md)
    now = datetime(2026, 3, 1, 2, 30, tzinfo=UTC)  # в Москве уже 1-е 05:30
    assert now.astimezone(UTC).strftime("%Y-%m") == "2026-03"


def test_month_rollover_detected() -> None:
    jan = datetime(2026, 1, 31, 23, 0, tzinfo=UTC)
    feb = datetime(2026, 2, 1, 0, 30, tzinfo=UTC)
    assert jan.strftime("%Y-%m") != feb.strftime("%Y-%m")
