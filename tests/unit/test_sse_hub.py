"""Unit-тесты SSE-хаба (FR-3.13.11): подписка/publish/отписка/переполнение."""

from __future__ import annotations

import asyncio

from app.web.sse import Event, EventHub


def test_publish_to_single_subscriber() -> None:
    hub = EventHub()
    queue = hub.subscribe()
    delivered = hub.publish(Event(type="server.status", data={"server_id": 1}))
    assert delivered == 1
    event = queue.get_nowait()
    assert event.type == "server.status"
    assert event.data["server_id"] == 1


def test_publish_no_subscribers() -> None:
    hub = EventHub()
    assert hub.publish(Event(type="x")) == 0


def test_unsubscribe_stops_delivery() -> None:
    hub = EventHub()
    queue = hub.subscribe()
    hub.unsubscribe(queue)
    assert hub.subscriber_count == 0
    assert hub.publish(Event(type="x")) == 0


def test_event_to_sse_format() -> None:
    event = Event(type="operation.progress", data={"operation_id": "op1", "pct": 40})
    frame = event.to_sse()
    assert frame.startswith("event: operation.progress\n")
    assert '"operation_id"' in frame
    assert frame.endswith("\n\n")


def test_queue_overflow_drops_event() -> None:
    hub = EventHub()
    queue = hub.subscribe()
    # заполняем очередь до отказа
    for i in range(300):
        hub.publish(Event(type="x", data={"i": i}))
    assert queue.qsize() == 256  # MAX_QUEUE
    assert hub.publish(Event(type="y")) == 0  # дроп, не блокировка


def test_multiple_subscribers_all_receive() -> None:
    hub = EventHub()
    q1, q2 = hub.subscribe(), hub.subscribe()
    assert hub.publish(Event(type="traffic.sample", data={"rx": 1})) == 2
    assert q1.get_nowait().data["rx"] == 1
    assert q2.get_nowait().data["rx"] == 1


def test_sse_frame_json_valid() -> None:
    import json

    event = Event(type="t", data={"k": "значение ru"})
    payload = json.loads(event.to_sse().split("data: ", 1)[1])
    assert payload["type"] == "t"
    assert payload["k"] == "значение ru"
    assert "ts" in payload


def test_concurrent_subscribe_publish() -> None:
    async def scenario() -> None:
        hub = EventHub()
        queue = hub.subscribe()

        async def publisher() -> None:
            for i in range(10):
                hub.publish(Event(type="x", data={"i": i}))
                await asyncio.sleep(0)

        task = asyncio.create_task(publisher())
        received = []
        while len(received) < 10:
            received.append(await queue.get())
        await task
        assert [e.data["i"] for e in received] == list(range(10))

    asyncio.run(scenario())
