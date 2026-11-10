"""REST API серверов (FR-3.1.x): /api/v1/servers.

Роли (матрица §2.2): мутирующие операции — admin; просмотр списка/статусов —
admin + support. Ошибки — единый JSON; секреты не раскрываются.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from app.auth.dependencies import client_ip, require_role
from app.auth.sessions import SessionData
from app.core.audit import log_event
from app.db.database import Database
from app.servers.service import (
    ServerError,
    ServerNotFound,
    ServerService,
    credentials_from_row,
)
from app.ssh.probes import NodeProber

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/servers", tags=["Servers"])


def get_server_service(request: Request) -> ServerService:
    return request.app.state.server_service


def get_prober(request: Request) -> NodeProber:
    return request.app.state.node_prober


def _error(exc: ServerError, status_code: int) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={"error_code": exc.error_code, "message": exc.message, "details": {}},
    )


class ServerCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    host: str = Field(min_length=1, max_length=255)
    ssh_port: int = Field(default=22, ge=1, le=65535)
    username: str = Field(default="root", min_length=1, max_length=64)
    password: str | None = Field(default=None, max_length=256)
    private_key: str | None = Field(default=None, max_length=32768)


class ServerUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    host: str | None = Field(default=None, min_length=1, max_length=255)
    ssh_port: int | None = Field(default=None, ge=1, le=65535)
    username: str | None = Field(default=None, min_length=1, max_length=64)
    password: str | None = Field(default=None, max_length=256)
    private_key: str | None = Field(default=None, max_length=32768)


class ReorderRequest(BaseModel):
    uids: list[str] = Field(min_length=1)


# ------------------------------------------------------------------ CRUD


@router.get("")
async def list_servers(
    request: Request,
    _: SessionData = Depends(require_role("admin", "support")),
    service: ServerService = Depends(get_server_service),
) -> dict:
    db: Database = request.app.state.db
    servers = await service.list_servers(db)
    return {"items": servers}


@router.post("", status_code=201)
async def create_server(
    payload: ServerCreate,
    request: Request,
    session: SessionData = Depends(require_role("admin")),
    service: ServerService = Depends(get_server_service),
) -> Any:
    db: Database = request.app.state.db
    ip = client_ip(request)
    try:
        server = await service.create_server(
            db,
            name=payload.name,
            host=payload.host,
            ssh_port=payload.ssh_port,
            username=payload.username,
            password=payload.password,
            private_key=payload.private_key,
        )
    except ServerError as exc:
        return _error(exc, 400)

    await log_event(
        db, session.username, "server.create", object=server["uid"], ip=ip,
        details={"name": server["name"], "host": server["host"]},
    )
    return server


@router.get("/{server_id}")
async def get_server(
    server_id: int,
    request: Request,
    _: SessionData = Depends(require_role("admin", "support")),
    service: ServerService = Depends(get_server_service),
) -> Any:
    db: Database = request.app.state.db
    try:
        return await service.get_server(db, server_id)
    except ServerNotFound as exc:
        return _error(exc, 404)


@router.patch("/{server_id}")
async def update_server(
    server_id: int,
    payload: ServerUpdate,
    request: Request,
    session: SessionData = Depends(require_role("admin")),
    service: ServerService = Depends(get_server_service),
) -> Any:
    db: Database = request.app.state.db
    ip = client_ip(request)
    try:
        server = await service.update_server(
            db,
            server_id,
            name=payload.name,
            host=payload.host,
            ssh_port=payload.ssh_port,
            username=payload.username,
            password=payload.password,
            private_key=payload.private_key,
        )
    except ServerNotFound as exc:
        return _error(exc, 404)
    except ServerError as exc:
        return _error(exc, 400)

    changed = payload.model_dump(exclude_unset=True, exclude={"password", "private_key"})
    await log_event(
        db, session.username, "server.update", object=server["uid"], ip=ip,
        details={"fields": changed},
    )
    return server


@router.delete("/{server_id}")
async def delete_server(
    server_id: int,
    request: Request,
    session: SessionData = Depends(require_role("admin")),
    service: ServerService = Depends(get_server_service),
) -> Any:
    db: Database = request.app.state.db
    ip = client_ip(request)
    force = request.query_params.get("force", "").lower() in ("1", "true", "yes")
    try:
        await service.delete_server(db, server_id, force=force)
    except ServerNotFound as exc:
        return _error(exc, 404)
    except ServerError as exc:
        return _error(exc, 409)

    await log_event(
        db, session.username, "server.delete", object=f"server:{server_id}",
        ip=ip, details={"force": force},
    )
    return {"status": "deleted"}


# -------------------------------------------------------------- ordering


@router.post("/reorder")
async def reorder_servers(
    payload: ReorderRequest,
    request: Request,
    session: SessionData = Depends(require_role("admin")),
    service: ServerService = Depends(get_server_service),
) -> Any:
    db: Database = request.app.state.db
    ip = client_ip(request)
    try:
        servers = await service.reorder(db, payload.uids)
    except ServerNotFound as exc:
        return _error(exc, 404)
    except ServerError as exc:
        return _error(exc, 400)

    await log_event(
        db, session.username, "server.reorder", ip=ip,
        details={"order": payload.uids},
    )
    return {"items": servers}


# ------------------------------------------------------ probes & actions


@router.post("/{server_id}/verify")
async def verify_server(
    server_id: int,
    request: Request,
    session: SessionData = Depends(require_role("admin")),
    service: ServerService = Depends(get_server_service),
) -> Any:
    """Верификация ноды: SSH-доступность, детекция контейнеров (FR-3.1.2)."""
    db: Database = request.app.state.db
    ip = client_ip(request)
    try:
        report = await service.verify_server(db, server_id)
    except ServerNotFound as exc:
        return _error(exc, 404)

    await log_event(
        db, session.username, "server.verify", object=f"server:{server_id}",
        ip=ip, result="ok" if report.ssh_ok else "failed",
        details={"containers": list(report.containers)},
    )
    return report.to_dict()


@router.post("/{server_id}/ping")
async def ping_server(
    server_id: int,
    request: Request,
    _: SessionData = Depends(require_role("admin", "support")),
    service: ServerService = Depends(get_server_service),
) -> Any:
    """TCP-ping SSH-порта ноды (FR-3.1.9)."""
    db: Database = request.app.state.db
    try:
        row = await service._get_row(db, server_id)  # noqa: SLF001 — приватный helper сервиса
    except ServerNotFound as exc:
        return _error(exc, 404)
    from app.ssh.pool import tcp_ping

    rtt = await tcp_ping(row["host"], row["ssh_port"])
    return {"reachable": rtt is not None, "rtt_ms": round(rtt, 1) if rtt is not None else None}


@router.get("/{server_id}/stats")
async def server_stats(
    server_id: int,
    request: Request,
    _: SessionData = Depends(require_role("admin", "support")),
    service: ServerService = Depends(get_server_service),
    prober: NodeProber = Depends(get_prober),
) -> Any:
    """Статистика хоста ноды (FR-3.1.13): CPU, память, диск, load."""
    db: Database = request.app.state.db
    try:
        row = await service._get_row(db, server_id)  # noqa: SLF001
    except ServerNotFound as exc:
        return _error(exc, 404)
    result = await prober.probe_node(server_id, credentials_from_row(row))
    return {
        "reachable": result.reachable,
        "stats": result.stats,
        "stats_partial": result.stats_partial,
        "protocols": result.protocols,
        "error": result.error,
    }


@router.post("/{server_id}/reboot")
async def reboot_server(
    server_id: int,
    request: Request,
    session: SessionData = Depends(require_role("admin")),
    service: ServerService = Depends(get_server_service),
) -> Any:
    """Перезагрузка сервера через SSH (admin-only)."""
    db: Database = request.app.state.db
    ip = client_ip(request)
    try:
        result = await service.reboot_server(db, server_id)
    except ServerNotFound as exc:
        return _error(exc, 404)
    except ServerError as exc:
        return _error(exc, 502)

    await log_event(
        db, session.username, "server.reboot", object=f"server:{server_id}", ip=ip
    )
    return result
