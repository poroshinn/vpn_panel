"""HTML-страницы (FR-3.12.3): логин, смена пароля, заглушка дашборда.

Полноценный UI — MVP-09; сейчас минимальные страницы на Jinja2.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from app.auth.dependencies import get_current_session
from app.auth.sessions import SessionData

templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))

router = APIRouter(include_in_schema=False)


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(request, "login.html")


@router.get("/change-password", response_class=HTMLResponse)
async def change_password_page(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(request, "change_password.html")


@router.get("/", response_class=HTMLResponse)
async def index(request: Request) -> HTMLResponse:
    try:
        await get_current_session(request)
    except Exception:  # noqa: BLE001 — без сессии → логин
        return RedirectResponse(url="/login", status_code=302)
    return HTMLResponse(
        "<!DOCTYPE html><html><head><meta charset='utf-8'><title>Amnezia Web Panel</title></head>"
        "<body><h1>Amnezia Web Panel</h1><p>Dashboard will appear in MVP-09. "
        "<form method='post' action='/api/auth/logout'></form>"
        "</body></html>"
    )


@router.get("/whoami")
async def whoami(session: SessionData = Depends(get_current_session)) -> dict:
    """Вспомогательный эндпоинт для тестов/отладки сессии."""
    return {"username": session.username, "role": session.role}
