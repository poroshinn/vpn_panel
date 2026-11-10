"""Пул SSH-соединений (FR-3.1.5, FR-3.1.8, ADR-0002).

Paramiko — блокирующая библиотека; каждый вызов оборачивается в
``asyncio.to_thread`` (конвенции §1). Одно мультиплексированное соединение
(SFTP-каналы Paramiko не используют, только exec-каналы) на ноду,
ограничение параллельных exec-каналов на соединение — семафором.

Расшифровка ``password_enc``/``private_key_enc`` — только в памяти в момент
установки соединения (правило 3 AGENTS.md); секреты никогда не попадают в
логи/ошибки — исключения перехватываются и нормализуются в :class:`SSHError`
без подробностей аутентификации.
"""

from __future__ import annotations

import asyncio
import logging
import socket
from dataclasses import dataclass
from typing import Any

import paramiko

from app.core.config import get_settings
from app.core.security import decrypt_secret
from app.ssh.circuit_breaker import BreakerOpenError, CircuitBreaker
from app.ssh.known_hosts import HostKeyMismatch, KnownHostsStore

logger = logging.getLogger(__name__)

# Таймауты (сек)
DEFAULT_CONNECT_TIMEOUT = 10.0
DEFAULT_COMMAND_TIMEOUT = 30.0
# Ограничение параллельных exec-каналов на одно соединение
EXEC_CONCURRENCY_PER_NODE = 4
# Максимальный размер вывода команды (байт) — защита от переполнения памяти
MAX_OUTPUT_BYTES = 1_000_000


class SSHError(Exception):
    """Нормализованная ошибка SSH-операции (без секретов в сообщении)."""


@dataclass(frozen=True)
class NodeCredentials:
    """Параметры подключения к ноде. Секреты — зашифрованными токенами."""

    host: str
    port: int
    username: str
    password_enc: str | None = None
    private_key_enc: str | None = None
    key_passphrase_enc: str | None = None


@dataclass(frozen=True)
class CommandResult:
    """Результат exec-команды на ноде."""

    exit_code: int
    stdout: str
    stderr: str


def _load_private_key(
    key_pem: str, passphrase: str | None
) -> paramiko.PKey | None:
    """Загрузка приватного ключа из PEM (в памяти, ошибку — в SSHError)."""
    last_exc: Exception | None = None
    for loader in (
        paramiko.RSAKey.from_private_key,
        paramiko.Ed25519Key.from_private_key,
        paramiko.ECDSAKey.from_private_key,
    ):
        try:
            return loader(
                file_obj=__import__("io").StringIO(key_pem), password=passphrase
            )
        except paramiko.PKeyException as exc:
            last_exc = exc
        except Exception as exc:  # noqa: BLE001 — формат не тот
            last_exc = exc
    if last_exc is not None:
        raise SSHError("failed to load private key") from last_exc
    return None


class NodeConnection:
    """Обёртка одного Paramiko-соединения с ограничением каналов."""

    def __init__(self, node_id: int, credentials: NodeCredentials) -> None:
        self.node_id = node_id
        self._credentials = credentials
        self._client: paramiko.SSHClient | None = None
        self._sem = asyncio.Semaphore(EXEC_CONCURRENCY_PER_NODE)
        self._lock = asyncio.Lock()
        self._closed = False

    @property
    def connected(self) -> bool:
        transport = self._client.get_transport() if self._client else None
        return transport is not None and transport.is_active()

    # ------------------------------------------------------------ connect

    async def connect(self) -> None:
        """Установить соединение (TOFU-проверка host key). Потокобезопасно."""
        async with self._lock:
            if self._closed:
                raise SSHError("connection closed")
            if self.connected:
                return
            try:
                await asyncio.to_thread(self._connect_sync)
            except SSHError:
                raise
            except HostKeyMismatch:
                raise
            except Exception:  # noqa: BLE001 — нормализация без секретов
                # исходное исключение НЕ логируем: paramiko-ошибки могут
                # содержать часть аутентификационного диалога (правило 3)
                logger.debug("ssh connect to node %s failed", self.node_id)
                raise SSHError(f"ssh connect failed to node {self.node_id}") from None

    def _connect_sync(self) -> None:
        creds = self._credentials
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(_PanelHostKeyPolicy(self.node_id))
        connect_kwargs: dict[str, Any] = {
            "hostname": creds.host,
            "port": creds.port,
            "username": creds.username,
            "timeout": DEFAULT_CONNECT_TIMEOUT,
            "allow_agent": False,
            "look_for_keys": False,
        }
        if creds.private_key_enc:
            key_pem = decrypt_secret(creds.private_key_enc)
            passphrase = (
                decrypt_secret(creds.key_passphrase_enc)
                if creds.key_passphrase_enc
                else None
            )
            pkey = _load_private_key(key_pem, passphrase)
            del key_pem  # в памяти минимум времени; явный del перед очисткой ссылок
            connect_kwargs["pkey"] = pkey
        elif creds.password_enc:
            connect_kwargs["password"] = decrypt_secret(creds.password_enc)
        else:
            raise SSHError("node has no credentials configured")
        client.connect(**connect_kwargs)
        self._client = client

    # --------------------------------------------------------------- exec

    async def run(
        self, command: str, timeout: float = DEFAULT_COMMAND_TIMEOUT  # noqa: ASYNC109
    ) -> CommandResult:
        """Выполнить команду, вернуть exit/stdout/stderr. Параллельно ≤ семафор.

        Секреты в команде недопустимы по конвенции; ошибка нормализована в
        :class:`SSHError` без содержимого stderr (stderr возвращается только
        при успешном выполнении канала как часть результата).
        """
        await self.connect()
        async with self._sem:
            try:
                return await asyncio.wait_for(
                    asyncio.to_thread(self._run_sync, command), timeout=timeout
                )
            except TimeoutError:
                logger.warning("command on node %s timed out", self.node_id)
                raise SSHError(f"command timed out on node {self.node_id}") from None
            except SSHError:
                raise
            except Exception:  # noqa: BLE001
                logger.debug("command on node %s failed", self.node_id)
                # разрыв транспорта → пометить соединение как непригодное
                self._closed = True
                raise SSHError(f"command failed on node {self.node_id}") from None

    def _run_sync(self, command: str) -> CommandResult:
        if self._client is None:
            raise SSHError("not connected")
        transport = self._client.get_transport()
        if transport is None or not transport.is_active():
            raise SSHError("transport inactive")
        import time

        with transport.open_session(timeout=DEFAULT_CONNECT_TIMEOUT) as channel:
            channel.settimeout(DEFAULT_COMMAND_TIMEOUT)
            channel.exec_command(command)
            stdout_buf, stderr_buf = b"", b""
            while True:
                while channel.recv_ready():
                    stdout_buf += channel.recv(MAX_OUTPUT_BYTES - len(stdout_buf))
                while channel.recv_stderr_ready():
                    stderr_buf += channel.recv_stderr(MAX_OUTPUT_BYTES - len(stderr_buf))
                if (
                    channel.exit_status_ready()
                    and not channel.recv_ready()
                    and not channel.recv_stderr_ready()
                ):
                    break
                if len(stdout_buf) + len(stderr_buf) > MAX_OUTPUT_BYTES:
                    logger.warning("output truncated for node %s", self.node_id)
                    channel.close()
                    break
                time.sleep(0.02)
            exit_code = channel.recv_exit_status() if channel.closed is False else -1
            return CommandResult(
                exit_code=exit_code,
                stdout=stdout_buf.decode("utf-8", errors="replace"),
                stderr=stderr_buf.decode("utf-8", errors="replace"),
            )

    # --------------------------------------------------------------- close

    async def close(self) -> None:
        async with self._lock:
            self._closed = True
            if self._client is not None:
                try:
                    await asyncio.to_thread(self._client.close)
                except Exception:  # noqa: BLE001
                    logger.debug("error closing connection to node %s", self.node_id)
                self._client = None


class _PanelHostKeyPolicy(paramiko.MissingHostKeyPolicy):
    """TOFU-политика: сверка/закрепление через :class:`KnownHostsStore`."""

    def __init__(self, node_id: int) -> None:
        self._node_id = node_id

    def missing_host_key(
        self, client: paramiko.SSHClient, hostname: str, key: paramiko.PKey
    ) -> None:
        store = KnownHostsStore()
        transport = client.get_transport()
        port = transport.getpeername()[1] if transport else 22
        fingerprint = KnownHostsStore.fingerprint(key.asbytes())
        try:
            store.verify(hostname, port, key.get_name(), fingerprint)
        except HostKeyMismatch:
            logger.error(
                "host key mismatch for node %s (%s:%s) — possible MITM",
                self._node_id,
                hostname,
                port,
            )
            raise


class SSHPool:
    """Пул соединений + circuit breaker на ноду (in-process, правило 1)."""

    def __init__(self) -> None:
        self._connections: dict[int, NodeConnection] = {}
        self._breakers: dict[int, CircuitBreaker] = {}
        self._lock = asyncio.Lock()

    # -------------------------------------------------------------- config

    @property
    def connect_timeout(self) -> float:
        return DEFAULT_CONNECT_TIMEOUT

    # -------------------------------------------------------------- access

    async def get_connection(self, node_id: int, credentials: NodeCredentials) -> NodeConnection:
        """Соединение для ноды (переиспользуем, при смене кредов — пересоздаём)."""
        async with self._lock:
            conn = self._connections.get(node_id)
            if conn is not None and conn._credentials != credentials:
                # креды сменились — старое соединение непригодно
                await conn.close()
                conn = None
            if conn is None:
                conn = NodeConnection(node_id, credentials)
                self._connections[node_id] = conn
            return conn

    def breaker(self, node_id: int) -> CircuitBreaker:
        """Circuit breaker ноды (создаётся лениво)."""
        breaker = self._breakers.get(node_id)
        if breaker is None:
            settings = get_settings()
            breaker = CircuitBreaker(
                failure_threshold=3,
                reset_timeout=settings.ssh_breaker_reset_seconds,
            )
            self._breakers[node_id] = breaker
        return breaker

    async def call(
        self,
        node_id: int,
        credentials: NodeCredentials,
        command: str,
        timeout: float = DEFAULT_COMMAND_TIMEOUT,  # noqa: ASYNC109
    ) -> CommandResult:
        """Команда под защитой breaker'а (FR-3.1.8)."""
        breaker = self.breaker(node_id)
        conn = await self.get_connection(node_id, credentials)

        async def _execute() -> CommandResult:
            return await conn.run(command, timeout=timeout)

        try:
            return await breaker.call(_execute)
        except BreakerOpenError as exc:
            raise SSHError(str(exc)) from None

    async def reset_breaker(self, node_id: int) -> None:
        """Ручной сброс breaker'а (после правки сервера)."""
        breaker = self._breakers.get(node_id)
        if breaker is not None:
            await asyncio.to_thread(breaker.reset)

    async def close_node(self, node_id: int) -> None:
        async with self._lock:
            conn = self._connections.pop(node_id, None)
        if conn is not None:
            await conn.close()
        self._breakers.pop(node_id, None)

    async def close_all(self) -> None:
        async with self._lock:
            conns = list(self._connections.values())
            self._connections.clear()
        for conn in conns:
            await conn.close()
        self._breakers.clear()


# ------------------------------------------------------------------ helper


async def tcp_ping(host: str, port: int, timeout: float = 3.0) -> float | None:  # noqa: ASYNC109
    """TCP-проба SSH-порта (FR-3.1.9): None — недоступен, иначе RTT в мс.

    Чистый asyncio — без потоков (адрес резолвится в to_thread для
    неблокирующего DNS).
    """
    loop = asyncio.get_running_loop()
    start = loop.time()
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
    except (TimeoutError, OSError):
        return None
    rtt_ms = (loop.time() - start) * 1000.0
    writer.close()
    try:
        await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
    except (TimeoutError, OSError):
        pass
    return rtt_ms


def normalize_host_error(exc: Exception) -> str:
    """Безопасное текстовое описание ошибки сети (для API/логов)."""
    if isinstance(exc, socket.gaierror):
        return "dns_resolution_failed"
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return "timeout"
    if isinstance(exc, ConnectionRefusedError):
        return "connection_refused"
    if isinstance(exc, (ConnectionError, BrokenPipeError)):
        return "connection_error"
    return "network_error"
