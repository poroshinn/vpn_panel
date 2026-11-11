"""Публичная share-страница ``/share/{token}`` (FR-3.8.2, FR-3.8.3).

- без аутентификации панели; вход по стабильному share-токену из URL;
- при установленном share-пароле — форма (POST), после успеха — cookie
  share-сессии (HMAC-подпись, revision по токену+хэшу пароля);
- содержимое: список подключений владельца + выгрузка ``.conf``/QR
  (те же генераторы MVP-06);
- защита: XSS (Jinja2 autoescape), noindex/nofollow, rate-limit на ввод
  пароля, Cache-Control: no-store на все ответы.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from fastapi import APIRouter, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from app.db.database import Database
from app.i18n.catalog import detect_locale, get_catalog
from app.protocols.configs import ConfigError, client_bundle, render_qr_png
from app.protocols.peers import PeerService
from app.servers.service import ServerService
from app.sharing.service import (
    SHARE_COOKIE,
    ShareError,
    ShareService,
    sign_share_session,
    verify_share_session,
)

logger = logging.getLogger(__name__)

share_router = APIRouter(include_in_schema=False)

templates = Jinja2Templates(directory=str(Path(__file__).parent / ".." / "web" / "templates"))

_NO_STORE = {"Cache-Control": "no-store"}


def get_share_service(request: Request) -> ShareService:
    svc = getattr(request.app.state, "share_service", None)
    if svc is None:
        raise ShareError("share_unavailable", "sharing is not available")
    return svc


def _render(request: Request, name: str, ctx: dict, status_code: int = 200) -> Response:
    locale = detect_locale(request)
    catalog = get_catalog(locale)
    ctx.setdefault("role", None)
    ctx.update(
        t=catalog.get,
        plural=catalog.plural,
        locale=locale,
        theme="light",
    )
    resp = templates.TemplateResponse(
        request, name, ctx, status_code=status_code  # type: ignore[arg-type]
    )
    resp.headers.update(_NO_STORE)
    return resp


def _session_cookie_value(
    service: ShareService, token: str, password_hash: str | None
) -> str:
    return sign_share_session(
        service.session_value(token, password_hash),
        secret=service.secret_for_signing(),
    )


def _share_session_valid(
    request: Request, service: ShareService, token: str, password_hash: str | None
) -> bool:
    signed = request.cookies.get(SHARE_COOKIE, "")
    payload = verify_share_session(signed, secret=service.secret_for_signing())
    if payload is None:
        return False
    expected = service.session_value(token, password_hash)
    # payload = "token:rev"; сравниваем целиком (token в URL уже проверен)
    return payload == expected


async def _owner_row(db: Database, user_id: int) -> dict | None:
    return await db.fetch_one(
        "SELECT id, username FROM users WHERE id = ?", (user_id,)
    )


@share_router.get("/share/{token}", response_class=HTMLResponse)
async def share_page(token: str, request: Request) -> Response:
    """Публичная страница шеринга (FR-3.8.2)."""
    db: Database = request.app.state.db
    try:
        service = get_share_service(request)
    except ShareError:
        return _render(request, "share_error.html", {"error": "unavailable"}, 503)

    owner = await service.resolve_token(db, token)
    if owner is None:
        # 404 не раскрывает существование токена
        return _render(request, "share_error.html", {"error": "not_found"}, 404)

    needs_password = bool(owner["share_password_hash"])
    if needs_password and not _share_session_valid(
        request, service, token, owner["share_password_hash"]
    ):
        return _render(request, "share_password.html", {"token": token})

    return await _share_content(request, db, service, owner, token)


@share_router.post("/share/{token}", response_class=HTMLResponse)
async def share_password_submit(token: str, request: Request) -> Response:
    """Проверка share-пароля (FR-3.8.3) — rate-limited."""
    db: Database = request.app.state.db
    try:
        service = get_share_service(request)
    except ShareError:
        return _render(request, "share_error.html", {"error": "unavailable"}, 503)

    owner = await service.resolve_token(db, token)
    if owner is None:
        return _render(request, "share_error.html", {"error": "not_found"}, 404)

    if not owner["share_password_hash"]:
        return RedirectResponse(url=f"/share/{token}", status_code=302)

    if not service._rate_ok(f"user:{owner['id']}"):  # noqa: SLF001
        return _render(
            request, "share_password.html",
            {"token": token, "error": "rate_limited"}, 429,
        )

    form = await request.form()
    password = str(form.get("password", ""))
    ok = await service.verify_share_password(
        db, owner["id"], password=password
    )
    if not ok:
        return _render(
            request, "share_password.html",
            {"token": token, "error": "wrong_password"}, 403,
        )

    value = _session_cookie_value(service, token, owner["share_password_hash"])
    resp = RedirectResponse(url=f"/share/{token}", status_code=303)
    resp.set_cookie(
        SHARE_COOKIE, value, httponly=True, samesite="lax", path="/share"
    )
    return resp


async def _share_content(
    request: Request,
    db: Database,
    service: ShareService,
    owner: dict,
    token: str,
) -> Response:
    """Список подключений владельца (FR-3.8.2)."""
    servers: ServerService = request.app.state.server_service
    connections = await service.shared_connections(db, owner["id"])
    servers_map: dict[int, str] = {}
    for s in await servers.list_servers(db):
        servers_map[s["id"]] = s["name"]
    for conn in connections:
        conn["server_name"] = servers_map.get(conn["server_id"])
    return _render(
        request, "share.html",
        {"token": token, "owner": owner, "connections": connections},
    )


@share_router.get("/share/{token}/download/{connection_id}")
async def share_download(token: str, connection_id: int, request: Request) -> Response:
    """Выгрузка ``.conf`` подключения через share-ссылку (FR-3.8.2).

    Те же генераторы, что и в панели (MVP-06); ответ — no-store.
    """
    db: Database = request.app.state.db
    try:
        service = get_share_service(request)
    except ShareError:
        return _render(request, "share_error.html", {"error": "unavailable"}, 503)

    owner = await service.resolve_token(db, token)
    if owner is None:
        return _render(request, "share_error.html", {"error": "not_found"}, 404)
    if owner["share_password_hash"] and not _share_session_valid(
        request, service, token, owner["share_password_hash"]
    ):
        return RedirectResponse(url=f"/share/{token}", status_code=302)

    conn = await db.fetch_one(
        "SELECT * FROM user_connections WHERE id = ? AND user_id = ?",
        (connection_id, owner["id"]),
    )
    if conn is None:
        return _render(request, "share_error.html", {"error": "not_found"}, 404)

    peers: PeerService = request.app.state.peer_service
    servers: ServerService = request.app.state.server_service
    try:
        raw = await peers.raw_config(db, conn["server_id"], conn["id"])
    except Exception:  # noqa: BLE001 — нода недоступна: без деталей (правило 3)
        return _render(
            request, "share_error.html", {"error": "config_unavailable"}, 503,
        )
    server_row = await servers._get_row(db, conn["server_id"])  # noqa: SLF001
    try:
        info = json.loads(server_row.get("protocols") or "{}").get(
            conn["protocol"], {}
        )
    except json.JSONDecodeError:
        info = {}
    port = int(info.get("port", 0))
    try:
        bundle = client_bundle(
            raw, instance=conn["protocol"],
            host=server_row["host"], port=port,
        )
    except ConfigError:
        return _render(
            request, "share_error.html", {"error": "config_unavailable"}, 503,
        )

    fmt = request.query_params.get("format", "conf")
    if fmt == "qr":
        png = render_qr_png(bundle["vpn_key"])
        return Response(content=png, media_type="image/png", headers=_NO_STORE)
    filename = f"{conn['protocol']}-{conn['client_id']}.conf"
    return Response(
        content=bundle["conf"],
        media_type="text/plain",
        headers={
            **_NO_STORE,
            "Content-Disposition": f'attachment; filename="{filename}"',
        },
    )
