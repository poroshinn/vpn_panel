"""SSE-хаб (FR-3.13.11): процессно-локальный broadcast событий панели.

Один инстанс на процесс (правило 1 AGENTS.md). Подписчики — ``asyncio.Queue``;
медленный потребитель не блокирует издателя (дроп при переполнении очереди).
Типы событий: ``server.status`` (ping/доступность), ``operation.progress``
(установка/peer-операции), ``traffic.sample`` (счётчики).
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

MAX_QUEUE = 256
KEEPALIVE_SECONDS = 15.0


@dataclass(slots=True)
class Event:
    """Событие SSE: имя типа + JSON-совместимые данные."""

    type: str
    data: dict[str, Any] = field(default_factory=dict)
    ts: float = field(default_factory=time.time)

    def to_sse(self) -> str:
        payload = json.dumps(
            {"type": self.type, "ts": self.ts, **self.data},
            ensure_ascii=False,
            separators=(",", ":"),
        )
        return f"event: {self.type}\ndata: {payload}\n\n"


class EventHub:
    """Publish/subscribe для SSE-подписчиков."""

    def __init__(self) -> None:
        self._subscribers: set[asyncio.Queue[Event]] = set()

    def subscribe(self) -> asyncio.Queue[Event]:
        queue: asyncio.Queue[Event] = asyncio.Queue(maxsize=MAX_QUEUE)
        self._subscribers.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue[Event]) -> None:
        self._subscribers.discard(queue)

    def publish(self, event: Event) -> int:
        """Разослать событие всем подписчикам; вернуть число доставленных.

        Переполненная очередь подписчика → дроп события этому подписчику
        (клиент восстановится через fallback-polling).
        """
        delivered = 0
        for queue in tuple(self._subscribers):
            try:
                queue.put_nowait(event)
                delivered += 1
            except asyncio.QueueFull:
                logger.warning("sse subscriber queue full, event dropped")
        return delivered

    @property
    def subscriber_count(self) -> int:
        return len(self._subscribers)


def get_hub(app) -> EventHub:  # noqa: ANN001
    """Хаб из app.state; создаётся лениво (устойчивость к прямым вызовам)."""
    hub = getattr(app.state, "event_hub", None)
    if hub is None:
        hub = EventHub()
        app.state.event_hub = hub
    return hub
