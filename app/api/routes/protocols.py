"""REST API протоколов (FR-3.2.1–3.2.3): /api/v1/servers/{id}/protocols/...

Роли (матрица §2.2): установка/удаление протоколов и мутации peer'ов — admin;
просмотр инстансов/peers/конфигураций — admin + support (конфиги — владелец
или admin/support). Ошибки — единый JSON; секреты не раскрываются.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field

from app.auth.dependencies import client_ip, get_current_session, require_role
from app.auth.sessions import SessionData
from app.core.audit import log_event
from app.db.database import Database
from app.protocols.configs import ConfigError, client_bundle
from app.protocols.installer import InstallError, ProtocolInstaller
from app.protocols.peers import PeerError, PeerService
from app.protocols.presets import list_presets
from app.servers.service import ServerNotFoundError, ServerService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["Protocols"])


def get_installer(request: Request) -> ProtocolInstaller:
    return request.app.state.protocol_installer


def get_peers(request: Request) -> PeerService:
    return request.app.state.peer_service


def get_servers(request: Request) -> ServerService:
    return request.app.state.server_service


def _error(exc: Exception, status_code: int) -> JSONResponse:
    code = getattr(exc, "error_code", "protocol_error")
    message = getattr(exc, "message", str(exc))
    return JSONResponse(
        status_code=status_code,
        content={"error_code": code, "message": message, "details": {}},
    )


# ------------------------------------------------------------- маркетплейс


class InstallRequest(BaseModel):
    preset_id: str = Field(min_length=1, max_length=64)
    port: int | None = Field(default=None, ge=1, le=65535)
    junk: dict[str, str] | None = None
    bbr: bool = False
    operation_id: str | None = Field(default=None, max_length=128)


@router.get("/presets")
async def get_presets(
    _: SessionData = Depends(require_role("admin", "support")),
) -> dict:
    """Маркетплейс пресетов (FR-3.2.1)."""
    return {"items": list_presets()}


@router.post("/servers/{server_id}/protocols", status_code=201)
async def install_protocol(
    server_id: int,
    payload: InstallRequest,
    request: Request,
    session: SessionData = Depends(require_role("admin")),
    installer: ProtocolInstaller = Depends(get_installer),
) -> Any:
    db: Database = request.app.state.db
    ip = client_ip(request)
    try:
        result = await installer.install(
            db, server_id,
            preset_id=payload.preset_id, port=payload.port,
            junk=payload.junk, bbr=payload.bbr,
            operation_id=payload.operation_id or "",
        )
    except InstallError as exc:
        if exc.error_code in ("install_uncertain", "uninstall_uncertain"):
            return _error(exc, 502)
        status = 404 if exc.error_code == "instance_not_found" else 400
        return _error(exc, status)

    await log_event(
        db, session.username, "protocol.install",
        object=f"server:{server_id}:{result['instance']}", ip=ip,
        details={"preset": payload.preset_id, "port": result["port"],
                 "bbr": result["bbr"]},
    )
    return result


@router.get("/servers/{server_id}/protocols")
async def list_instances(
    server_id: int,
    request: Request,
    _: SessionData = Depends(require_role("admin", "support")),
    servers: ServerService = Depends(get_servers),
) -> Any:
    """Список установленных инстансов сервера."""
    db: Database = request.app.state.db
    try:
        server = await servers.get_server(db, server_id)
    except ServerNotFoundError as exc:
        return _error(exc, 404)
    import json

    try:
        protocols = json.loads(server.get("protocols") or "{}")
    except json.JSONDecodeError:
        protocols = {}
    return {"items": [{"instance": k, **v} for k, v in protocols.items()]}


@router.delete("/servers/{server_id}/protocols/{instance}")
async def uninstall_protocol(
    server_id: int,
    instance: str,
    request: Request,
    session: SessionData = Depends(require_role("admin")),
    installer: ProtocolInstaller = Depends(get_installer),
) -> Any:
    db: Database = request.app.state.db
    ip = client_ip(request)
    try:
        result = await installer.uninstall(db, server_id, instance)
    except InstallError as exc:
        return _error(exc, 404 if exc.error_code == "instance_not_found" else 400)

    await log_event(
        db, session.username, "protocol.uninstall",
        object=f"server:{server_id}:{instance}", ip=ip,
        details={"operation_id": result.get("operation_id")},
    )
    return result


# ------------------------------------------------------------------ peers


class PeerCreate(BaseModel):
    instance: str = Field(min_length=1, max_length=64)
    user_id: int = Field(ge=1)
    name: str = Field(min_length=1, max_length=128)
    client_id: str | None = Field(default=None, max_length=64)
    operation_id: str | None = Field(default=None, max_length=128)


@router.post("/servers/{server_id}/connections", status_code=201)
async def create_peer_on_server(
    server_id: int,
    payload: PeerCreate,
    request: Request,
    session: SessionData = Depends(require_role("admin", "support")),
    peers: PeerService = Depends(get_peers),
) -> Any:
    """Создать peer на сервере (FR-3.4.1): идемпотентно, lifecycle-lock."""
    db: Database = request.app.state.db
    ip = client_ip(request)
    try:
        result = await peers.create_peer(
            db,
            server_id=server_id,
            instance=payload.instance,
            user_id=payload.user_id,
            name=payload.name,
            client_id=payload.client_id,
            operation_id=payload.operation_id,
            created_by=session.username,
        )
    except PeerError as exc:
        if exc.error_code == "lifecycle_uncertain":
            return _error(exc, 502)
        if exc.error_code in ("connection_not_found", "instance_not_found"):
            return _error(exc, 404)
        return _error(exc, 400)

    await log_event(
        db, session.username, "peer.create",
        object=f"server:{server_id}:{result.get('protocol')}"
               f":{result.get('client_id')}",
        ip=ip, details={"name": result.get("name"),
                        "operation_id": payload.operation_id},
    )
    return result


@router.get("/servers/{server_id}/connections")
async def list_server_peers(
    server_id: int,
    request: Request,
    _: SessionData = Depends(require_role("admin", "support")),
    peers: PeerService = Depends(get_peers),
) -> dict:
    db: Database = request.app.state.db
    items = await peers.list_peers(db, server_id=server_id)
    return {"items": items}


@router.get("/connections")
async def list_my_peers(
    request: Request,
    session: SessionData = Depends(get_current_session),
    peers: PeerService = Depends(get_peers),
) -> dict:
    """Подключения текущего пользователя (self-service, FR-3.4.3)."""
    db: Database = request.app.state.db
    items = await peers.list_peers(db, user_id=session.user_id)
    return {"items": items}


class PeerRename(BaseModel):
    name: str = Field(min_length=1, max_length=128)


@router.patch("/servers/{server_id}/connections/{connection_id}")
async def rename_peer(
    server_id: int,
    connection_id: int,
    payload: PeerRename,
    request: Request,
    session: SessionData = Depends(require_role("admin", "support")),
    peers: PeerService = Depends(get_peers),
) -> Any:
    """Переименование без гонок (FR-3.4.8)."""
    db: Database = request.app.state.db
    ip = client_ip(request)
    try:
        result = await peers.rename_peer(
            db, server_id, connection_id, name=payload.name
        )
    except PeerError as exc:
        if exc.error_code == "lifecycle_uncertain":
            return _error(exc, 502)
        if exc.error_code == "connection_not_found":
            return _error(exc, 404)
        return _error(exc, 400)

    await log_event(
        db, session.username, "peer.rename",
        object=f"connection:{connection_id}", ip=ip,
        details={"name": payload.name},
    )
    return result


@router.post("/servers/{server_id}/connections/{connection_id}/enable")
async def enable_peer(
    server_id: int,
    connection_id: int,
    request: Request,
    session: SessionData = Depends(require_role("admin", "support")),
    peers: PeerService = Depends(get_peers),
) -> Any:
    return await _set_enabled(server_id, connection_id, True, request, session, peers)


@router.post("/servers/{server_id}/connections/{connection_id}/disable")
async def disable_peer(
    server_id: int,
    connection_id: int,
    request: Request,
    session: SessionData = Depends(require_role("admin", "support")),
    peers: PeerService = Depends(get_peers),
) -> Any:
    return await _set_enabled(server_id, connection_id, False, request, session, peers)


async def _set_enabled(
    server_id: int,
    connection_id: int,
    enabled: bool,
    request: Request,
    session: SessionData,
    peers: PeerService,
) -> Any:
    db: Database = request.app.state.db
    ip = client_ip(request)
    try:
        result = await peers.set_peer_enabled(
            db, server_id, connection_id, enabled=enabled
        )
    except PeerError as exc:
        if exc.error_code == "lifecycle_uncertain":
            return _error(exc, 502)
        if exc.error_code == "connection_not_found":
            return _error(exc, 404)
        return _error(exc, 400)

    await log_event(
        db, session.username, "peer.enable" if enabled else "peer.disable",
        object=f"connection:{connection_id}", ip=ip,
    )
    return result


@router.delete("/servers/{server_id}/connections/{connection_id}")
async def delete_peer(
    server_id: int,
    connection_id: int,
    request: Request,
    session: SessionData = Depends(require_role("admin", "support")),
    peers: PeerService = Depends(get_peers),
) -> Any:
    """Удалить peer (FR-3.4.1) — идемпотентно по ``operation_id`` (query)."""
    db: Database = request.app.state.db
    ip = client_ip(request)
    operation_id = request.query_params.get("operation_id") or None
    try:
        result = await peers.delete_peer(
            db, server_id, connection_id, operation_id=operation_id
        )
    except PeerError as exc:
        if exc.error_code == "lifecycle_uncertain":
            return _error(exc, 502)
        if exc.error_code == "connection_not_found":
            return _error(exc, 404)
        return _error(exc, 400)

    await log_event(
        db, session.username, "peer.delete",
        object=f"connection:{connection_id}", ip=ip,
        details={"operation_id": result.get("operation_id")},
    )
    return result


# ---------------------------------------------------------------- configs


@router.get("/servers/{server_id}/connections/{connection_id}/config")
async def peer_config(
    server_id: int,
    connection_id: int,
    request: Request,
    session: SessionData = Depends(get_current_session),
    peers: PeerService = Depends(get_peers),
    servers: ServerService = Depends(get_servers),
) -> Any:
    """Выдача конфигурации peer'а (FR-3.4.2): JSON с conf/vpn:///QR base64.

    Доступ: admin/support или владелец подключения.
    ``?format=conf|qr`` — отдать файлом.
    """
    db: Database = request.app.state.db
    conn = await db.fetch_one(
        "SELECT * FROM user_connections WHERE id = ?", (connection_id,)
    )
    if conn is None or conn["server_id"] != server_id:
        return JSONResponse(
            status_code=404,
            content={"error_code": "connection_not_found",
                     "message": "connection not found", "details": {}},
        )
    if session.role not in ("admin", "support") and conn["user_id"] != session.user_id:
        return JSONResponse(
            status_code=403,
            content={"error_code": "insufficient_role",
                     "message": "not the owner of this connection", "details": {}},
        )

    try:
        raw = await peers.raw_config(db, server_id, connection_id)
    except PeerError as exc:
        if exc.error_code == "lifecycle_uncertain":
            return _error(exc, 502)
        if exc.error_code == "connection_not_found":
            return _error(exc, 404)
        return _error(exc, 400)

    server_row = await servers._get_row(db, server_id)  # noqa: SLF001
    import json as _json

    try:
        info = _json.loads(server_row.get("protocols") or "{}").get(
            conn["protocol"], {}
        )
    except _json.JSONDecodeError:
        info = {}
    port = int(info.get("port", 0))

    try:
        bundle = client_bundle(
            raw, instance=conn["protocol"], host=server_row["host"], port=port
        )
    except ConfigError as exc:
        return _error(exc, 422)

    fmt = request.query_params.get("format", "")
    if fmt == "conf":
        filename = f"{conn['protocol']}-{conn['client_id']}.conf"
        return Response(
            content=bundle["conf"],
            media_type="text/plain",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    if fmt == "qr":
        import base64 as _b64

        png = _b64.b64decode(bundle["qr_png_base64"])
        return Response(content=png, media_type="image/png")
    return bundle
