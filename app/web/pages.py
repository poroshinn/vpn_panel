"""HTML-страницы (FR-3.12.3, FR-3.13.x, FR-3.7.1 MVP-часть).

- i18n: локаль из cookie → Accept-Language → en (FR-3.14.2);
- noindex/nofollow для всех приватных страниц (FR-3.13.10) + /robots.txt;
- статика с кэш-политикой (FR-3.13.10);
- /my — подключения текущего пользователя, конфиги/QR (FR-3.7.1 MVP-часть);
- настройки — вкладки (внешний вид, заглушки CAPTCHA/бэкапы/алерты).
"""

from __future__ import annotations

import json
from pathlib import Path

from fastapi import APIRouter, Depends, Request
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates

from app.auth.dependencies import get_current_session
from app.auth.sessions import SessionData
from app.db.database import Database
from app.i18n.catalog import (
    detect_locale,
    format_datetime_iso,
    get_catalog,
)
from app.protocols.peers import PeerService
from app.servers.service import ServerNotFound, ServerService

templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
STATIC_DIR = Path(__file__).parent / "static"

router = APIRouter(include_in_schema=False)


# ------------------------------------------------------------------ i18n ctx


def _render(request: Request, name: str, ctx: dict, status_code: int = 200) -> Response:
    locale = detect_locale(request)
    catalog = get_catalog(locale)
    theme = request.cookies.get("awp_theme", "light")
    if theme not in ("light", "dark"):
        theme = "light"
    ctx.setdefault("role", None)
    ctx.update(
        t=catalog.get,
        plural=catalog.plural,
        fmt_dt=lambda v: format_datetime_iso(v, locale),
        locale=locale,
        theme=theme,
    )
    return templates.TemplateResponse(
        request, name, ctx, status_code=status_code  # type: ignore[arg-type]
    )


# ------------------------------------------------------------------- static


@router.get("/static/panel.css")
async def static_css() -> FileResponse:
    return FileResponse(STATIC_DIR / "panel.css", media_type="text/css",
                        headers={"Cache-Control": "public, max-age=3600"})


@router.get("/static/sse.js")
async def static_sse_js() -> FileResponse:
    return FileResponse(STATIC_DIR / "sse.js", media_type="text/javascript",
                        headers={"Cache-Control": "public, max-age=3600"})


# --------------------------------------------------------------- robots (3.10)


@router.get("/robots.txt")
async def robots() -> Response:
    body = "User-agent: *\nDisallow: /\n"
    return Response(content=body, media_type="text/plain")


# -------------------------------------------------------------------- pages


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request) -> Response:
    return _render(request, "login.html", {"active_nav": "login"})


@router.get("/change-password", response_class=HTMLResponse)
async def change_password_page(request: Request) -> Response:
    return _render(request, "change_password.html", {})


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
    return _render(
        request, "dashboard.html",
        {"servers": servers, "role": session.role, "active_nav": "dashboard"},
    )


@router.get("/my", response_class=HTMLResponse)
async def my_connections(request: Request) -> Response:
    """«Мои подключения» (FR-3.7.1 MVP-часть): просмотр + conf/QR."""
    session = await _session_or_redirect(request)
    if isinstance(session, RedirectResponse):
        return session
    db: Database = request.app.state.db
    peers: PeerService = request.app.state.peer_service
    servers: ServerService = _servers_service(request)
    connections = await peers.list_peers(db, user_id=session.user_id)
    # имена серверов одним запросом (без N+1 к SSH)
    servers_map: dict[int, str] = {}
    for s in await servers.list_servers(db):
        servers_map[s["id"]] = s["name"]
    for conn in connections:
        conn["server_name"] = servers_map.get(conn["server_id"])
    return _render(
        request, "my.html",
        {"connections": connections, "role": session.role, "active_nav": "my"},
    )


@router.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request) -> Response:
    session = await _session_or_redirect(request)
    if isinstance(session, RedirectResponse):
        return session
    return _render(
        request, "settings.html",
        {"role": session.role, "active_nav": "settings"},
    )


@router.get("/servers/new", response_class=HTMLResponse)
async def new_server_page(request: Request) -> Response:
    session = await _session_or_redirect(request)
    if isinstance(session, RedirectResponse):
        return session
    if session.role != "admin":
        return RedirectResponse(url="/", status_code=302)
    return _render(request, "server_new.html", {"role": session.role})


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
        protocols: dict[str, dict] = json.loads(server.get("protocols") or "{}")
    except json.JSONDecodeError:
        protocols = {}
    return _render(
        request, "server_detail.html",
        {"server": server, "protocols": protocols, "role": session.role},
    )


@router.get("/whoami")
async def whoami(session: SessionData = Depends(get_current_session)) -> dict:
    """Вспомогательный эндпоинт для тестов/отладки сессии."""
    return {"username": session.username, "role": session.role}
