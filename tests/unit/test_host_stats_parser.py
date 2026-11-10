"""Unit-тесты парсера статистики хоста и docker ps (MVP-04)."""

from __future__ import annotations

from app.ssh.probes import parse_docker_ps, parse_host_stats

FULL_JSON = (
    '{"cpu_percent":12.5,"load_1m":0.10,"load_5m":0.20,"load_15m":0.30,'
    '"mem_total_kb":8000000,"mem_available_kb":4000000,'
    '"disk_total_bytes":100000000000,"disk_used_bytes":25000000000,'
    '"disk_percent":25,"uptime_s":123456}'
)


def test_full_parse() -> None:
    stats, partial = parse_host_stats(FULL_JSON)
    assert partial is False
    assert stats["cpu_percent"] == 12.5
    assert stats["mem_total_kb"] == 8000000
    assert stats["uptime_s"] == 123456
    assert len(stats) == 10


def test_partial_parse_missing_keys() -> None:
    raw = '{"cpu_percent":5,"load_1m":0.5}'  # почти всё отсутствует
    stats, partial = parse_host_stats(raw)
    assert stats == {"cpu_percent": 5, "load_1m": 0.5}
    assert partial is True


def test_non_numeric_values_skipped() -> None:
    raw = '{"cpu_percent":"N/A","load_1m":"0.1","mem_total_kb":"abc"}'
    stats, partial = parse_host_stats(raw)
    assert "cpu_percent" not in stats
    assert "mem_total_kb" not in stats
    assert stats.get("load_1m") in (0.1, "0.1") or "load_1m" not in stats
    assert partial is True


def test_garbage_output() -> None:
    stats, partial = parse_host_stats("bash: top: command not found")
    assert stats == {}
    assert partial is True


def test_empty_output() -> None:
    stats, partial = parse_host_stats("")
    assert stats == {}
    assert partial is True


def test_string_numbers_accepted() -> None:
    raw = '{"cpu_percent":"12.5","uptime_s":"999"}'
    stats, partial = parse_host_stats(raw)
    assert stats["cpu_percent"] == 12.5
    assert stats["uptime_s"] == 999


def test_parse_docker_ps() -> None:
    raw = (
        "awg2\trunning\tUp 3 days\n"
        "awg2__2\trunning\tUp 2 hours\n"
        "awg1\texited\tExited (0) 5 minutes ago\n"
        "junk line without tabs\n"
        "\n"
    )
    result = parse_docker_ps(raw)
    assert result == {
        "awg2": "running",
        "awg2__2": "running",
        "awg1": "exited",
    }


def test_parse_docker_ps_empty() -> None:
    assert parse_docker_ps("") == {}
    assert parse_docker_ps("error: docker not installed") == {}
