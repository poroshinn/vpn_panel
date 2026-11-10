"""Установка/удаление инстансов протоколов через SSH+Docker (FR-3.2.1–3.2.3).

Инстанс = Docker-контейнер на ноде; ключ вида ``awg`` / ``awg2`` / ``awg2__2``
хранится в ``servers.protocols`` (JSON: ключ → {preset_id, port, junk, bbr}).

Неопределённые SSH-исходы (таймаут/разрыв после отправки мутации) фиксируются
в ``lifecycle_uncertain`` (fail-closed, правило 5 AGENTS.md); ретрай установки
идемпотентен (compose up/down — сходятся к одному состоянию).
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from typing import Any

from app.db.database import Database
from app.protocols.presets import (
    PresetError,
    get_preset,
    instance_key,
    render_compose,
    validate_junk,
)
from app.servers.service import (
    ServerService,
    credentials_from_row,
)
from app.ssh.pool import SSHError, SSHPool

logger = logging.getLogger(__name__)

# Таймаут установки — docker pull может быть долгим
INSTALL_TIMEOUT = 300.0


class InstallError(Exception):
    """Ошибка установки/удаления инстанса (без секретов в сообщении)."""

    def __init__(self, error_code: str, message: str) -> None:
        super().__init__(message)
        self.error_code = error_code
        self.message = message


def _now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


async def record_uncertain(
    db: Database,
    *,
    operation_id: str,
    server_id: int,
    protocol: str,
    description: str,
) -> None:
    """Фиксация неопределённого исхода (fail-closed, правило 5 AGENTS.md)."""
    await db.execute(
        "INSERT INTO lifecycle_uncertain (operation_id, server_id, protocol,"
        " description, resolved, created_at) VALUES (?, ?, ?, ?, 0, ?)",
        (operation_id, server_id, protocol, description, _now_iso()),
    )
    logger.warning(
        "lifecycle uncertain: op=%s server=%s protocol=%s: %s",
        operation_id, server_id, protocol, description,
    )


def _read_protocols(row: dict[str, Any]) -> dict[str, Any]:
    try:
        data = json.loads(row.get("protocols") or "{}")
        return data if isinstance(data, dict) else {}
    except json.JSONDecodeError:
        return {}


async def _write_protocols(db: Database, server_id: int, protocols: dict[str, Any]) -> None:
    await db.execute(
        "UPDATE servers SET protocols = ? WHERE id = ?",
        (json.dumps(protocols, ensure_ascii=False), server_id),
    )


def _server_row(service: ServerService, db: Database, server_id: int) -> dict[str, Any]:
    # _get_row синхронный асинхронный вызов через сервис; дублируем здесь лёгкий fetch
    async def _fetch() -> dict[str, Any]:
        return await service._get_row(db, server_id)  # noqa: SLF001
    return _fetch()  # type: ignore[return-value]


class ProtocolInstaller:
    """Установка/удаление инстансов протоколов на нодах."""

    def __init__(self, pool: SSHPool, servers: ServerService) -> None:
        self._pool = pool
        self._servers = servers

    async def _row(self, db: Database, server_id: int) -> dict[str, Any]:
        return await self._servers._get_row(db, server_id)  # noqa: SLF001

    # ------------------------------------------------------------- install

    async def install(
        self,
        db: Database,
        server_id: int,
        *,
        preset_id: str,
        port: int | None = None,
        junk: dict[str, str] | None = None,
        bbr: bool = False,
        operation_id: str = "",
    ) -> dict[str, Any]:
        """Установить инстанс протокола (FR-3.2.1, FR-3.2.3).

        Идемпотентно: compose-up сходится к одному состоянию; при повторном
        вызове с теми же параметрами состояние не меняется.
        """
        row = await self._row(db, server_id)
        creds = credentials_from_row(row)
        try:
            preset = get_preset(preset_id)
        except PresetError as exc:
            raise InstallError("unknown_preset", str(exc)) from exc

        protocols = _read_protocols(row)
        slot = 1
        base = preset.container_base
        if preset.supports_multi_instance:
            # занятые слоты: сам базовый ключ (слот 1) и явные ``__N``
            used = {1} if base in protocols else set()
            used |= {
                int(key.rsplit("__", 1)[1])
                for key in protocols
                if key.startswith(base + "__") and key.rsplit("__", 1)[1].isdigit()
            }
            slot = max(used, default=0) + 1
        elif base in protocols:
            raise InstallError(
                "instance_exists", f"single-instance protocol {preset.protocol} already installed"
            )
        instance = instance_key(preset, slot)
        real_port = port if port is not None else preset.default_port
        try:
            junk_valid = validate_junk(preset, junk)
        except PresetError as exc:
            raise InstallError("invalid_junk", str(exc)) from exc
        if bbr and not preset.supports_bbr:
            raise InstallError("bbr_not_supported", f"preset {preset_id} has no BBR")

        compose = render_compose(
            preset, instance, port=real_port, host=row["host"], bbr=bbr
        )
        script = (
            f"mkdir -p /opt/amnezia/{instance} && cat > /opt/amnezia/{instance}/docker-compose.yml"
            f" <<'COMPOSE_EOF'\n{compose}COMPOSE_EOF\n"
            f"cd /opt/amnezia/{instance} && docker compose up -d 2>&1 || "
            "docker-compose up -d 2>&1"
        )

        op_id = operation_id or f"install:{server_id}:{instance}:{_now_iso()}"
        try:
            result = await self._pool.call(
                server_id, creds, script, timeout=INSTALL_TIMEOUT
            )
        except SSHError as exc:
            # неопределённый исход: неизвестно, применилась ли мутация на ноде
            await record_uncertain(
                db, operation_id=op_id, server_id=server_id,
                protocol=instance, description=f"install ssh error: {exc}",
            )
            raise InstallError("install_uncertain", str(exc)) from exc

        if result.exit_code != 0:
            await record_uncertain(
                db, operation_id=op_id, server_id=server_id,
                protocol=instance,
                description=f"install exit={result.exit_code}",
            )
            raise InstallError(
                "install_failed",
                f"docker compose up failed (exit {result.exit_code})",
            )

        protocols[instance] = {
            "preset_id": preset.preset_id,
            "protocol": preset.protocol,
            "port": real_port,
            "junk": junk_valid,
            "bbr": bbr,
            "installed_at": _now_iso(),
        }
        await _write_protocols(db, server_id, protocols)
        return {
            "instance": instance,
            "preset_id": preset.preset_id,
            "port": real_port,
            "junk": junk_valid,
            "bbr": bbr,
            "operation_id": op_id,
        }

    # ------------------------------------------------------------ uninstall

    async def uninstall(
        self,
        db: Database,
        server_id: int,
        instance: str,
        *,
        operation_id: str = "",
    ) -> dict[str, Any]:
        """Удалить инстанс протокола (FR-3.2.1): compose down + удаление каталога."""
        row = await self._row(db, server_id)
        creds = credentials_from_row(row)
        protocols = _read_protocols(row)
        if instance not in protocols:
            raise InstallError("instance_not_found", f"instance {instance} not installed")

        script = (
            f"cd /opt/amnezia/{instance} 2>/dev/null && "
            "(docker compose down -v 2>&1 || docker-compose down -v 2>&1); "
            f"rm -rf /opt/amnezia/{instance}"
        )

        op_id = operation_id or f"uninstall:{server_id}:{instance}:{_now_iso()}"
        try:
            result = await self._pool.call(
                server_id, creds, script, timeout=INSTALL_TIMEOUT
            )
        except SSHError as exc:
            await record_uncertain(
                db, operation_id=op_id, server_id=server_id,
                protocol=instance, description=f"uninstall ssh error: {exc}",
            )
            raise InstallError("uninstall_uncertain", str(exc)) from exc

        if result.exit_code != 0:
            await record_uncertain(
                db, operation_id=op_id, server_id=server_id,
                protocol=instance,
                description=f"uninstall exit={result.exit_code}",
            )
            raise InstallError(
                "uninstall_failed",
                f"docker compose down failed (exit {result.exit_code})",
            )

        del protocols[instance]
        await _write_protocols(db, server_id, protocols)
        return {"instance": instance, "status": "removed", "operation_id": op_id}
