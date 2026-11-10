"""Integration-тесты SSH-пула и проб (MVP-04): mock-транспорт Paramiko.

Реальный SSH-сервер в тестах не поднимается; соединение мокается на уровне
``paramiko.SSHClient.connect`` / ``get_transport``, что позволяет проверить
логику пула, breaker'а, параллельности и no-echo секретов.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import pytest

from app.core.security import encrypt_secret
from app.ssh.known_hosts import HostKeyMismatchError, KnownHostsStore
from app.ssh.pool import (
    NodeCredentials,
    SSHError,
    SSHPool,
    normalize_host_error,
    tcp_ping,
)
from app.ssh.probes import NodeProber


class FakeTransport:
    """Минимальный mock paramiko.Transport: exec фиксированных результатов."""

    def __init__(self, results: dict[str, tuple[int, str, str]]) -> None:
        self._results = results
        self.active = True

    def is_active(self) -> bool:
        return self.active

    def getpeername(self) -> tuple[str, int]:
        return ("fake-node", 22)

    def open_session(self, timeout: float = 0.0) -> FakeChannel:
        return FakeChannel(self._results)


class FakeChannel:
    def __init__(self, results: dict[str, tuple[int, str, str]]) -> None:
        self._results = results
        self._cmd: str | None = None
        self._code = 0
        self._stdout = b""
        self._stderr = b""
        self.closed = False

    def __enter__(self) -> FakeChannel:
        return self

    def __exit__(self, *args: Any) -> None:
        self.closed = True

    def settimeout(self, timeout: float) -> None:
        pass

    def exec_command(self, command: str) -> None:
        self._cmd = command
        code, out, err = self._results.get(command, (-1, "", "no such cmd"))
        self._code = code
        self._stdout = out.encode()
        self._stderr = err.encode()

    # --- одноразовая выдача буферов, как реальный канал ---

    def recv_ready(self) -> bool:
        return bool(self._stdout)

    def recv(self, n: int) -> bytes:
        data, self._stdout = self._stdout[:n], self._stdout[n:]
        return data

    def recv_stderr_ready(self) -> bool:
        return bool(self._stderr)

    def recv_stderr(self, n: int) -> bytes:
        data, self._stderr = self._stderr[:n], self._stderr[n:]
        return data

    def exit_status_ready(self) -> bool:
        return self._cmd is not None

    def recv_exit_status(self) -> int:
        return self._code

    def close(self) -> None:
        self.closed = True


def install_fake_paramiko(
    monkeypatch: pytest.MonkeyPatch,
) -> dict[str, tuple[int, str, str]]:
    """Установить mock paramiko.SSHClient; вернуть таблицу результатов команд.

    Ключ результатов — команда; значение — (exit_code, stdout, stderr).
    Переиспользуется интеграционными тестами (servers и др.).
    """
    results: dict[str, tuple[int, str, str]] = {}

    import paramiko

    class FakeClient:
        def __init__(self) -> None:
            self._transport = FakeTransport(results)

        def set_missing_host_key_policy(self, policy: Any) -> None:
            pass

        def connect(self, **kwargs: Any) -> None:
            pass

        def get_transport(self) -> FakeTransport:
            return self._transport

        def close(self) -> None:
            self._transport.active = False

    monkeypatch.setattr(paramiko, "SSHClient", FakeClient)
    return results


@pytest.fixture
def fake_ssh(monkeypatch: pytest.MonkeyPatch) -> dict[str, tuple[int, str, str]]:
    return install_fake_paramiko(monkeypatch)


def make_creds() -> NodeCredentials:
    return NodeCredentials(
        host="fake-node",
        port=22,
        username="root",
        password_enc=encrypt_secret("s3cret-password"),
    )


# ------------------------------------------------------------------ pool


async def test_pool_executes_command(tmp_data_dir: Any, fake_ssh: dict) -> None:
    fake_ssh["echo hello"] = (0, "hello\n", "")
    pool = SSHPool()
    result = await pool.call(1, make_creds(), "echo hello")
    assert result.exit_code == 0
    assert result.stdout == "hello\n"


async def test_pool_nonzero_exit(tmp_data_dir: Any, fake_ssh: dict) -> None:
    fake_ssh["false"] = (3, "", "some error")
    pool = SSHPool()
    result = await pool.call(1, make_creds(), "false")
    assert result.exit_code == 3
    assert result.stderr == "some error"


async def test_pool_breaker_opens_after_failures(
    tmp_data_dir: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """3 подряд неудачи → breaker разомкнут, вызов отклонён без SSH-попыток."""
    import paramiko

    calls = {"n": 0}

    class FailingClient:
        def __init__(self) -> None:
            pass

        def set_missing_host_key_policy(self, policy: Any) -> None:
            pass

        def connect(self, **kwargs: Any) -> None:
            calls["n"] += 1
            raise OSError("connection refused")

        def get_transport(self) -> None:
            return None

        def close(self) -> None:
            pass

    monkeypatch.setattr(paramiko, "SSHClient", FailingClient)

    pool = SSHPool()
    for _ in range(3):
        with pytest.raises(SSHError):
            await pool.call(1, make_creds(), "any")
    assert calls["n"] == 3
    # breaker open — попыток больше нет
    with pytest.raises(SSHError, match="circuit open"):
        await pool.call(1, make_creds(), "any")
    assert calls["n"] == 3


async def test_pool_reuses_connection(tmp_data_dir: Any, fake_ssh: dict) -> None:
    fake_ssh["x"] = (0, "ok", "")
    pool = SSHPool()
    creds = make_creds()
    conn1 = await pool.get_connection(1, creds)
    conn2 = await pool.get_connection(1, creds)
    assert conn1 is conn2
    await pool.close_all()


async def test_pool_recreates_on_creds_change(tmp_data_dir: Any, fake_ssh: dict) -> None:
    fake_ssh["x"] = (0, "ok", "")
    pool = SSHPool()
    conn1 = await pool.get_connection(1, make_creds())
    other = NodeCredentials(host="fake-node", port=22, username="root",
                            password_enc=encrypt_secret("different"))
    conn2 = await pool.get_connection(1, other)
    assert conn1 is not conn2
    await pool.close_all()


async def test_secrets_not_in_logs(
    tmp_data_dir: Any, fake_ssh: dict, caplog: pytest.LogCaptureFixture
) -> None:
    """No-echo: пароль не появляется в логах при неудаче подключения."""
    fake_ssh["boom"] = (0, "", "")
    import paramiko

    class FailClient:
        def set_missing_host_key_policy(self, policy: Any) -> None:
            pass

        def connect(self, **kwargs: Any) -> None:
            raise Exception(f"auth failed with password {kwargs.get('password')}")

        def get_transport(self) -> None:
            return None

        def close(self) -> None:
            pass

    orig_client = paramiko.SSHClient
    paramiko.SSHClient = FailClient  # type: ignore[misc]
    try:
        with caplog.at_level(logging.DEBUG):
            pool = SSHPool()
            with pytest.raises(SSHError):
                await pool.call(1, make_creds(), "boom")
    finally:
        paramiko.SSHClient = orig_client  # type: ignore[misc]
    # ошибка нормализована: секрет не должен утечь ни в текст, ни в логи
    assert "s3cret-password" not in caplog.text


async def test_tcp_ping_parallel_no_event_loop_block(tmp_data_dir: Any) -> None:
    """Параллельные TCP-пробы не блокируют event loop (несуществующие адреса)."""
    targets = [(i, "127.0.0.1", 59000 + i) for i in range(8)]
    beat = {"count": 0}

    async def heartbeat() -> None:
        for _ in range(20):
            beat["count"] += 1
            await asyncio.sleep(0.001)

    hb = asyncio.create_task(heartbeat())
    results = await probe_with_heartbeat(targets, hb)
    assert beat["count"] > 0, "event loop блокировался во время проб"
    assert len(results) == 8


async def probe_with_heartbeat(targets: list, hb: asyncio.Task) -> dict:
    try:
        return await tcp_ping_all_helper(targets)
    finally:
        hb.cancel()


async def tcp_ping_all_helper(targets: list) -> dict:
    from app.ssh.probes import probe_tcp_all

    return await probe_tcp_all(targets)


async def test_tcp_ping_unreachable_returns_none(tmp_data_dir: Any) -> None:
    rtt = await tcp_ping("127.0.0.1", 59999, timeout=0.3)
    assert rtt is None


def test_normalize_host_error() -> None:
    import socket

    assert normalize_host_error(socket.gaierror()) == "dns_resolution_failed"
    assert normalize_host_error(TimeoutError()) == "timeout"
    assert normalize_host_error(ConnectionRefusedError()) == "connection_refused"
    assert normalize_host_error(RuntimeError("x")) == "network_error"


# ------------------------------------------------------------------ probes


async def test_prober_full_and_partial(tmp_data_dir: Any, fake_ssh: dict) -> None:
    from app.ssh.probes import DOCKER_PS_TEMPLATE

    fake_ssh.clear()
    fake_ssh[DOCKER_PS_TEMPLATE.format(prefix="awg")] = (
        0,
        "awg2\trunning\tUp 3 days\n",
        "",
    )
    full_stats = (
        '{"cpu_percent":10,"load_1m":0.1,"load_5m":0.2,"load_15m":0.3,'
        '"mem_total_kb":1000,"mem_available_kb":500,'
        '"disk_total_bytes":10,"disk_used_bytes":5,"disk_percent":50,"uptime_s":1}'
    )
    pool = SSHPool()
    prober = NodeProber(pool)
    creds = make_creds()

    # добавим команду статистики: импортируем фактическую константу
    from app.ssh.probes import HOST_STATS_SCRIPT

    fake_ssh[HOST_STATS_SCRIPT] = (0, full_stats, "")
    result = await prober.probe_node(1, creds)
    assert result.reachable is True
    assert result.protocols == {"awg2": "running"}
    assert result.stats_partial is False
    assert result.stats["cpu_percent"] == 10
    await pool.close_all()


async def test_prober_partial_stats(tmp_data_dir: Any, fake_ssh: dict) -> None:
    from app.ssh.probes import DOCKER_PS_TEMPLATE, HOST_STATS_SCRIPT

    fake_ssh.clear()
    fake_ssh[DOCKER_PS_TEMPLATE.format(prefix="awg")] = (0, "", "")
    fake_ssh[HOST_STATS_SCRIPT] = (0, '{"cpu_percent":7}', "")
    pool = SSHPool()
    prober = NodeProber(pool)
    result = await prober.probe_node(1, make_creds())
    assert result.stats == {"cpu_percent": 7}
    assert result.stats_partial is True
    await pool.close_all()


async def test_prober_parallel_many_nodes(tmp_data_dir: Any, fake_ssh: dict) -> None:
    from app.ssh.probes import DOCKER_PS_TEMPLATE, HOST_STATS_SCRIPT

    fake_ssh.clear()
    fake_ssh[DOCKER_PS_TEMPLATE.format(prefix="awg")] = (0, "awg1\trunning\tUp\n", "")
    fake_ssh[HOST_STATS_SCRIPT] = (0, '{"load_1m":0.5}', "")
    pool = SSHPool()
    prober = NodeProber(pool)
    creds = make_creds()
    report = await prober.probe_all([(i, creds) for i in range(1, 6)])
    assert len(report) == 5
    assert all(r.reachable for r in report.values())
    assert all(r.protocols == {"awg1": "running"} for r in report.values())
    await pool.close_all()


async def test_prober_error_isolated(tmp_data_dir: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """Ошибка пробы одной ноды не роняет пробы других (mock: connect отказ)."""
    import paramiko

    class FailClient:
        def set_missing_host_key_policy(self, policy: Any) -> None:
            pass

        def connect(self, **kwargs: Any) -> None:
            raise OSError("down")

        def get_transport(self) -> None:
            return None

        def close(self) -> None:
            pass

    monkeypatch.setattr(paramiko, "SSHClient", FailClient)
    pool = SSHPool()
    prober = NodeProber(pool)
    creds = NodeCredentials(host="x", port=22, username="u",
                            password_enc=encrypt_secret("p"))
    result = await prober.probe_node(9, creds)
    assert result.reachable is False
    assert result.error == "ssh_error"
    await pool.close_all()


# ----------------------------------------------------------- known hosts


async def test_host_key_mismatch_detected(
    tmp_data_dir: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Смена отпечатка host key → соединение отклонено, запись не перезаписана."""
    import paramiko

    key_bytes = b"\x01" * 32
    key_type = "ssh-ed25519"

    class FakeKey:
        def asbytes(self) -> bytes:
            return key_bytes

        def get_name(self) -> str:
            return key_type

    class FakeTransport:
        def is_active(self) -> bool:
            return True

        def getpeername(self) -> tuple[str, int]:
            return ("node-under-test", 2222)

    pinned_fp = KnownHostsStore.fingerprint(key_bytes)

    class ClientWithKey:
        def __init__(self) -> None:
            self._transport = FakeTransport()

        def set_missing_host_key_policy(self, policy: Any) -> None:
            self._policy = policy

        def connect(self, **kwargs: Any) -> None:
            # сымитируем вызов политики, как это делает paramiko при missing host key
            self._policy.missing_host_key(self, "node-under-test", FakeKey())

        def get_transport(self) -> FakeTransport:
            return self._transport

        def close(self) -> None:
            pass

    monkeypatch.setattr(paramiko, "SSHClient", ClientWithKey)

    store = KnownHostsStore()
    # закрепляем ДРУГОЙ отпечаток заранее
    store.pin("node-under-test", 2222, key_type, "SHA256:" + "Z" * 43)
    assert store.get("node-under-test", 2222)[1] != pinned_fp

    pool = SSHPool()
    # HostKeyMismatchError поднимается из политики → наружу как есть
    with pytest.raises((HostKeyMismatchError, SSHError)):
        await pool.call(1, make_creds(), "x")
    # закреплённый отпечаток не изменился
    assert store.get("node-under-test", 2222)[1] == "SHA256:" + "Z" * 43
    await pool.close_all()
