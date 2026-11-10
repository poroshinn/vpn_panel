"""HTML-страницы (FR-3.12.3): логин, смена пароля, дашборд, страницы серверов.

Данные дашборда — живые (polling `/api/v1/servers`); SSE — в MVP-08.
"""

from __future__ import annotations

import json
from pathlib import Path

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates

from app.auth.dependencies import get_current_session
from app.auth.sessions import SessionData
from app.db.database import Database
from app.servers.service import ServerNotFound, ServerService

templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))

router = APIRouter(include_in_schema=False)


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(request, "login.html")


@router.get("/change-password", response_class=HTMLResponse)
async def change_password_page(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(request, "change_password.html")


async def _session_or_redirect(request: Request) -> SessionData | RedirectResponse:
    try:
        return await get_current_session(request)
    except Exception:  # noqa: BLE001 — без сессии → логин
        return RedirectResponse(url="/login", status_code=302)


def _servers_service(request: Request) -> ServerService:
    return request.app.state.server_service


@router.get("/", response_class=HTMLResponse)
async def index(request: Request) -> Response:
    session = await _session_or_redirect(request)
    if isinstance(session, RedirectResponse):
        return session
    db: Database = request.app.state.db
    servers = await _servers_service(request).list_servers(db)
    return templates.TemplateResponse(
        request, "dashboard.html", {"servers": servers, "role": session.role}
    )


@router.get("/servers/new", response_class=HTMLResponse)
async def new_server_page(request: Request) -> Response:
    session = await _session_or_redirect(request)
    if isinstance(session, RedirectResponse):
        return session
    if session.role != "admin":
        return RedirectResponse(url="/", status_code=302)
    return templates.TemplateResponse(request, "server_new.html")


@router.get("/servers/{server_id}", response_class=HTMLResponse)
async def server_page(server_id: int, request: Request) -> Response:
    session = await _session_or_redirect(request)
    if isinstance(session, RedirectResponse):
        return session
    db: Database = request.app.state.db
    try:
        server = await _servers_service(request).get_server(db, server_id)
    except ServerNotFound:
        return RedirectResponse(url="/", status_code=302)
    try:
        protocols: dict[str, str] = json.loads(server.get("protocols") or "{}")
    except json.JSONDecodeError:
        protocols = {}
    return templates.TemplateResponse(
        request, "server_detail.html",
        {"server": server, "protocols": protocols, "role": session.role},
    )


@router.get("/whoami")
async def whoami(session: SessionData = Depends(get_current_session)) -> dict:
    """Вспомогательный эндпоинт для тестов/отладки сессии."""
    return {"username": session.username, "role": session.role}
