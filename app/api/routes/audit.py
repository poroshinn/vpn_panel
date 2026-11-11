"""REST API audit trail (FR-3.16.2): /api/v1/audit.

Роли (матрица §2.2): admin — полный доступ, support — read-only просмотр.
Фильтры: actor, action, ts_from/ts_to (UTC ISO), result, лимит/офсет.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, Request

from app.auth.dependencies import require_role
from app.auth.sessions import SessionData
from app.db.database import Database

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/audit", tags=["Audit"])

MAX_LIMIT = 500


@router.get("")
async def list_audit(
    request: Request,
    _: SessionData = Depends(require_role("admin", "support")),
    actor: str | None = None,
    action: str | None = None,
    result: str | None = None,
    ts_from: str | None = None,
    ts_to: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> Any:
    """Журнал аудита (admin/support; read-only для обоих — записи не меняются)."""
    db: Database = request.app.state.db
    limit = max(1, min(MAX_LIMIT, limit))
    offset = max(0, offset)

    where: list[str] = []
    params: list[str] = []
    if actor:
        where.append("actor = ?")
        params.append(actor)
    if action:
        where.append("action LIKE ?")
        params.append(f"{action}%")
    if result:
        where.append("result = ?")
        params.append(result)
    if ts_from:
        where.append("ts >= ?")
        params.append(ts_from)
    if ts_to:
        where.append("ts <= ?")
        params.append(ts_to)
    # WHERE собирается из фиксированных условий со placeholder-параметрами —
    # пользовательский ввод идёт только через params (noqa: S608)
    clause = f"WHERE {' AND '.join(where)}" if where else ""  # noqa: S608

    rows = await db.fetch_all(
        f"SELECT id, ts, actor, action, object, ip, result, details "  # noqa: S608
        f"FROM audit_log {clause} ORDER BY id DESC LIMIT ? OFFSET ?",
        tuple(params + [str(limit), str(offset)]),
    )
    total_row = await db.fetch_one(
        f"SELECT COUNT(*) AS n FROM audit_log {clause}", tuple(params)  # noqa: S608
    )
    return {
        "total": int(total_row["n"]) if total_row else 0,
        "limit": limit,
        "offset": offset,
        "items": rows,
    }
