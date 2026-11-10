"""REST API учёта (FR-3.5.5, FR-3.11.4): /api/v1/accounting, /api/v1/finalize.

Роли (матрица §2.2): сводка пользователя — владелец или admin/support;
квота/expiration — admin; финализация peer'а — admin.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from app.accounting.finalization import FinalizationError, FinalizationService
from app.accounting.service import AccountingService
from app.auth.dependencies import client_ip, get_current_session, require_role
from app.auth.sessions import SessionData
from app.core.audit import log_event
from app.db.database import Database

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["Accounting"])


def get_accounting(request: Request) -> AccountingService:
    return request.app.state.accounting_service


def get_finalization(request: Request) -> FinalizationService:
    return request.app.state.finalization_service


def _error(exc: Exception, status_code: int) -> JSONResponse:
    code = getattr(exc, "error_code", "accounting_error")
    message = getattr(exc, "message", str(exc))
    details: dict[str, Any] = {}
    if getattr(exc, "can_force", False):
        details["can_force"] = True
    return JSONResponse(
        status_code=status_code,
        content={"error_code": code, "message": message, "details": details},
    )


class QuotaUpdate(BaseModel):
    traffic_limit: int | None = Field(default=None, ge=0)


class FinalizeRequest(BaseModel):
    allow_unverified: bool = False


# --------------------------------------------------------------- сводка


@router.get("/accounting")
async def my_accounting(
    request: Request,
    session: SessionData = Depends(get_current_session),
    accounting: AccountingService = Depends(get_accounting),
) -> Any:
    """Сводка учёта текущего пользователя (числа, FR-3.5.5)."""
    db: Database = request.app.state.db
    try:
        return await accounting.user_accounting(db, session.user_id)
    except KeyError:
        return _error(KeyError("user"), 404)


@router.get("/users/{user_id}/accounting")
async def user_accounting(
    user_id: int,
    request: Request,
    _: SessionData = Depends(require_role("admin", "support")),
    accounting: AccountingService = Depends(get_accounting),
) -> Any:
    """Сводка учёта пользователя (admin/support)."""
    db: Database = request.app.state.db
    try:
        return await accounting.user_accounting(db, user_id)
    except KeyError:
        return _error(KeyError("user"), 404)


@router.put("/users/{user_id}/quota")
async def set_quota(
    user_id: int,
    payload: QuotaUpdate,
    request: Request,
    session: SessionData = Depends(require_role("admin")),
    accounting: AccountingService = Depends(get_accounting),
) -> Any:
    """Установить/снять квоту (admin, FR-3.5.5)."""
    db: Database = request.app.state.db
    ip = client_ip(request)
    try:
        result = await accounting.set_traffic_limit(
            db, user_id, limit=payload.traffic_limit
        )
    except ValueError as exc:
        return _error(exc, 400)
    await log_event(
        db, session.username, "accounting.quota_set", object=f"user:{user_id}",
        ip=ip, details={"traffic_limit": payload.traffic_limit},
    )
    return result


@router.post("/accounting/reset-month")
async def reset_month(
    request: Request,
    session: SessionData = Depends(require_role("admin")),
    accounting: AccountingService = Depends(get_accounting),
) -> Any:
    """Ручной календарный сброс квот (UTC; идемпотентно по месяцу)."""
    db: Database = request.app.state.db
    ip = client_ip(request)
    reset = await accounting.monthly_reset()
    await log_event(
        db, session.username, "accounting.reset_month", ip=ip,
        details={"reset_users": reset},
    )
    return {"reset_users": reset}


# ----------------------------------------------------------- финализация


@router.post("/servers/{server_id}/connections/{connection_id}/finalize")
async def finalize_peer(
    server_id: int,
    connection_id: int,
    payload: FinalizeRequest,
    request: Request,
    session: SessionData = Depends(require_role("admin")),
    finalization: FinalizationService = Depends(get_finalization),
) -> Any:
    """Финализация linked-peer'а (FR-3.11.4).

    Нечитаемый счётчик — 409 с ``details.can_force=true``; ретрай с
    ``allow_unverified=true`` коммитит tombstone без дельты.
    """
    db: Database = request.app.state.db
    ip = client_ip(request)
    try:
        result = await finalization.finalize_peer(
            db, server_id, connection_id, allow_unverified=payload.allow_unverified
        )
    except FinalizationError as exc:
        if exc.error_code == "counter_unreadable":
            return _error(exc, 409)
        return _error(exc, 404 if exc.error_code == "connection_not_found" else 400)

    await log_event(
        db, session.username, "peer.finalize",
        object=f"server:{server_id}:connection:{connection_id}", ip=ip,
        details={"verified": result["counters_verified_final"]},
    )
    return result
