"""SSE-поток событий панели (FR-3.13.11): /api/v1/events.

Любая валидная сессия (admin/support/user). Клиент переподключается
автоматически (EventSource); при разрыве подписка корректно снимается.
"""

from __future__ import annotations

import asyncio
import logging

from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse

from app.auth.dependencies import require_session
from app.auth.sessions import SessionData
from app.web.sse import KEEPALIVE_SECONDS, Event, EventHub, get_hub

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["Events"])


@router.get("/events")
async def events_stream(
    request: Request,
    session: SessionData = Depends(require_session),
) -> StreamingResponse:
    """Живой поток событий (text/event-stream) с keep-alive комментариями."""
    hub: EventHub = get_hub(request.app)
    queue = hub.subscribe()

    async def generator():
        try:
            yield "retry: 3000\n\n"  # автопереподключение через 3 с
            while True:
                if await request.is_disconnected():
                    break
                try:
                    event: Event = await asyncio.wait_for(
                        queue.get(), timeout=KEEPALIVE_SECONDS
                    )
                    yield event.to_sse()
                except TimeoutError:
                    yield ": keep-alive\n\n"
        except asyncio.CancelledError:  # клиент отключился
            pass
        finally:
            hub.unsubscribe(queue)

    return StreamingResponse(
        generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-store",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )
