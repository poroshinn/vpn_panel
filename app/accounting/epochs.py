"""Эпохи и парсер transfer (FR-3.5.1, FR-3.5.3).

**Эпоха** — идентичность физического peer'а на ноде: если хэш эпохи изменился
между семплами, счётчики сбрасывались или peer пересоздан ⇒ дельта
недоказуема, фиксируется ``traffic_accounting_gap`` с
``counters_verified_final=false`` (fail-closed, правило 5 AGENTS.md).

Хэш эпохи (FR-3.5.3) строится из:
- container ID, времени старта и PID процесса протокола,
- host boot ID (``/proc/sys/kernel/random/boot_id``),
- ifindex интерфейса,
- inode + ctime UAPI-сокетаwg-namespace.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any

# --------------------------------------------------------------- transfer ---

# `wg show <iface> transfer`:
#   <pubkey>\t<rx_bytes>\t<tx_bytes>
# Ключ base64 (44 символа с '=' либо без — не жёстко валидируем длину:
# разные сборки awg печатают ключи без паддинга).
_TRANSFER_LINE = re.compile(r"^(?P<key>[A-Za-z0-9+/=]{40,64})\t(?P<rx>\d+)\t(?P<tx>\d+)$")


@dataclass(frozen=True)
class TransferSample:
    """Семпл счётчиков одного peer'а в выводе transfer."""

    peer_key: str
    rx: int
    tx: int


def parse_transfer(raw: str) -> dict[str, TransferSample]:
    """Парсер ``wg show <iface> transfer`` (FR-3.5.1: точные целые RX/TX).

    Некорректные строки пропускаются (частичный результат допустим —
    недоказанное не считается). Возвращает {peer_pubkey: TransferSample}.
    """
    samples: dict[str, TransferSample] = {}
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        m = _TRANSFER_LINE.match(line)
        if m is None:
            continue
        samples[m.group("key")] = TransferSample(
            peer_key=m.group("key"), rx=int(m.group("rx")), tx=int(m.group("tx"))
        )
    return samples


# ------------------------------------------------------------------ эпохи ---


@dataclass(frozen=True)
class EpochMeta:
    """Метаданные эпохи инстанса (до и после чтения счётчиков, FR-3.5.3)."""

    container_id: str
    started_at: str
    pid: str
    boot_id: str
    ifindex: str
    socket_inode: str
    socket_ctime: str

    def as_dict(self) -> dict[str, str]:
        return {
            "container_id": self.container_id,
            "started_at": self.started_at,
            "pid": self.pid,
            "boot_id": self.boot_id,
            "ifindex": self.ifindex,
            "socket_inode": self.socket_inode,
            "socket_ctime": self.socket_ctime,
        }

    @classmethod
    def from_mapping(cls, data: dict[str, Any]) -> EpochMeta:
        return cls(
            container_id=str(data.get("container_id", "")),
            started_at=str(data.get("started_at", "")),
            pid=str(data.get("pid", "")),
            boot_id=str(data.get("boot_id", "")),
            ifindex=str(data.get("ifindex", "")),
            socket_inode=str(data.get("socket_inode", "")),
            socket_ctime=str(data.get("socket_ctime", "")),
        )


def epoch_hash(meta: EpochMeta) -> str:
    """Детерминированный SHA-256 хэш эпохи (FR-3.5.3)."""
    payload = "\x1f".join(
        [
            meta.container_id,
            meta.started_at,
            meta.pid,
            meta.boot_id,
            meta.ifindex,
            meta.socket_inode,
            meta.socket_ctime,
        ]
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


# Команда сбора метаданных эпохи инстанса: единый heredoc-скрипт, JSON-вывод.
# Частичный сбор допустим: отсутствующие компоненты дают пустые строки,
# но смена любого компонента меняет хэш (включая появление недостающего).
EPOCH_META_SCRIPT = r"""
CID=$(docker inspect -f '{{.Id}} {{.State.Pid}} {{.State.StartedAt}}' {instance} \
  2>/dev/null || true)
BOOT=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null || true)
IFIDX=$(docker exec {instance} sh -c \
  'cat /sys/class/net/awg0/ifindex 2>/dev/null' 2>/dev/null || true)
INODE=$(docker exec {instance} sh -c \
  'ls -Li /var/run/wireguard/awg0.sock 2>/dev/null \
  || ls -Li /var/run/awg/awg0.sock 2>/dev/null' 2>/dev/null || true)
printf '%s|%s|%s|%s\n' "$CID" "$BOOT" "$IFIDX" "$INODE"
"""


def parse_epoch_meta(raw: str, instance: str) -> EpochMeta:
    """Разбор вывода EPOCH_META_SCRIPT → EpochMeta.

    Формат: ``<id> <pid> <started>|<boot>|<ifindex>|<inode:ctime>``
    Любая недостающая часть — пустая строка (эпоха всё равно меняется
    при её появлении/исчезновении).
    """
    cid_part, boot, ifidx, inode_part = "", "", "", ""
    for line in raw.splitlines():
        parts = line.split("|")
        if len(parts) >= 1 and " " in parts[0]:
            fields = parts[0].split()
            cid_part = fields[0] if fields else ""
            if len(fields) > 1:
                cid_part = f"{fields[0]} {fields[1]} {fields[2] if len(fields) > 2 else ''}"
        if len(parts) > 1:
            boot = parts[1].strip()
        if len(parts) > 2:
            ifidx = parts[2].strip()
        if len(parts) > 3:
            inode_part = parts[3].strip()

    # CID-part: "<id> <pid> <started>" — атомарные компоненты эпохи
    container_id, started_at, pid = "", "", ""
    tokens = cid_part.split()
    if tokens:
        container_id = tokens[0]
        if len(tokens) > 1:
            pid = tokens[1]
        if len(tokens) > 2:
            started_at = tokens[2]

    # inode_part: "<inode>:<ctime>" либо "<inode>"
    socket_inode, socket_ctime = "", ""
    if inode_part:
        if ":" in inode_part:
            socket_inode, _, socket_ctime = inode_part.partition(":")
        else:
            socket_inode = inode_part

    return EpochMeta(
        container_id=container_id or instance,
        started_at=started_at,
        pid=pid,
        boot_id=boot,
        ifindex=ifidx,
        socket_inode=socket_inode,
        socket_ctime=socket_ctime,
    )


def epochs_differ(before: EpochMeta, after: EpochMeta) -> bool:
    """Сравнение метаданных до/после чтения счётчиков (FR-3.5.3)."""
    return epoch_hash(before) != epoch_hash(after)
