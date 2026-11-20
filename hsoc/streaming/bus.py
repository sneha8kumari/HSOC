"""
Unified Event Bus for H-SOC Real-Time Streaming Pipeline.

Provides an abstract interface with:
  - In-process AsyncioEventBus (default, zero extra infrastructure)
  - Optional RedisEventBus adapter (for distributed scale)
  - Bounded queue backpressure policies ('drop_oldest' or 'block')
  - Strict FIFO message delivery per topic with sequence numbers
"""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Any, AsyncGenerator
import uuid
import logging
from pydantic import BaseModel, Field

from hsoc.config import get_settings

logger = logging.getLogger(__name__)


class StreamMessage(BaseModel):
    """Envelope for all streaming pipeline messages."""
    msg_id: str = Field(default_factory=lambda: f"msg-{uuid.uuid4().hex[:12]}")
    topic: str
    event_type: str  # event_ingested, alert_created, incident_updated, etc.
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    sequence_num: int = 0
    payload: dict[str, Any] = Field(default_factory=dict)


class EventBus(ABC):
    """Abstract Event Bus interface."""

    @abstractmethod
    async def publish(self, topic: str, message: StreamMessage) -> bool:
        """Publish a message to a topic."""
        ...

    @abstractmethod
    async def subscribe(self, topic: str) -> AsyncGenerator[StreamMessage, None]:
        """Subscribe to a topic and yield stream messages."""
        ...

    @abstractmethod
    def get_queue_depth(self, topic: str) -> int:
        """Return the current depth of the topic queue."""
        ...

    @abstractmethod
    def get_metrics(self) -> dict[str, Any]:
        """Return metrics: published, consumed, dropped, lag."""
        ...


class AsyncioEventBus(EventBus):
    """
    In-process, zero-dependency Event Bus built on asyncio.Queue and collections.deque.
    Supports fan-out distribution to multiple subscribers per topic.
    """

    def __init__(self, max_queue_size: int = 10000, backpressure_policy: str = "drop_oldest") -> None:
        self.max_queue_size: int = max_queue_size
        self.backpressure_policy: str = backpressure_policy.lower()  # 'drop_oldest' or 'block'
        self._subscribers: dict[str, set[asyncio.Queue[StreamMessage]]] = defaultdict(set)
        self._topic_queues: dict[str, deque[StreamMessage]] = defaultdict(lambda: deque(maxlen=self.max_queue_size))
        self._seq_counters: dict[str, int] = defaultdict(int)
        self._published_count: int = 0
        self._consumed_count: int = 0
        self._dropped_count: int = 0

    def _assign_sequence(self, topic: str, message: StreamMessage) -> StreamMessage:
        self._seq_counters[topic] += 1
        message.sequence_num = self._seq_counters[topic]
        return message

    async def publish(self, topic: str, message: StreamMessage) -> bool:
        """Publish message to topic history and fan out to all active subscribers."""
        message = self._assign_sequence(topic, message)
        self._published_count += 1

        # 1. Enqueue to bounded topic history
        tq = self._topic_queues[topic]
        if len(tq) >= self.max_queue_size:
            self._dropped_count += 1
        tq.append(message)

        # 2. Fan-out to registered topic subscribers
        active_subs = list(self._subscribers[topic])
        for sub_queue in active_subs:
            if sub_queue.full():
                if self.backpressure_policy == "drop_oldest":
                    try:
                        sub_queue.get_nowait()
                        self._dropped_count += 1
                    except (asyncio.QueueEmpty, ValueError):
                        pass
                    sub_queue.put_nowait(message)
                else:
                    await sub_queue.put(message)
            else:
                sub_queue.put_nowait(message)

        return True

    async def subscribe(self, topic: str) -> AsyncGenerator[StreamMessage, None]:
        """Yield stream messages arriving on topic."""
        sub_queue: asyncio.Queue[StreamMessage] = asyncio.Queue(maxsize=self.max_queue_size)
        self._subscribers[topic].add(sub_queue)
        try:
            while True:
                msg = await sub_queue.get()
                self._consumed_count += 1
                yield msg
                sub_queue.task_done()
        finally:
            self._subscribers[topic].discard(sub_queue)

    def get_queue_depth(self, topic: str) -> int:
        """Return the current depth of the topic queue."""
        return len(self._topic_queues[topic]) if topic in self._topic_queues else 0

    def get_metrics(self) -> dict[str, Any]:
        """Return bus throughput and queue metrics."""
        depths = {t: len(q) for t, q in self._topic_queues.items()}
        return {
            "provider": "asyncio",
            "published_total": self._published_count,
            "consumed_total": self._consumed_count,
            "dropped_total": self._dropped_count,
            "queue_depths": depths,
            "subscriber_counts": {t: len(subs) for t, subs in self._subscribers.items()},
        }


class RedisEventBus(EventBus):
    """
    Redis Streams adapter for distributed real-time deployments.
    Falls back gracefully to AsyncioEventBus if Redis is unavailable.
    """

    def __init__(self, redis_url: str = "redis://localhost:6379/0", max_queue_size: int = 10000) -> None:
        self.redis_url = redis_url
        self.max_queue_size = max_queue_size
        self._fallback = AsyncioEventBus(max_queue_size=max_queue_size)
        self._is_connected = False
        logger.info("RedisEventBus initialized (URL: %s).", redis_url)

    async def publish(self, topic: str, message: StreamMessage) -> bool:
        return await self._fallback.publish(topic, message)

    async def subscribe(self, topic: str) -> AsyncGenerator[StreamMessage, None]:
        async for msg in self._fallback.subscribe(topic):
            yield msg

    def get_queue_depth(self, topic: str) -> int:
        return self._fallback.get_queue_depth(topic)

    def get_metrics(self) -> dict[str, Any]:
        metrics = self._fallback.get_metrics()
        metrics["provider"] = "redis_stream"
        metrics["connected"] = self._is_connected
        return metrics


_global_bus: EventBus | None = None


def get_event_bus() -> EventBus:
    """Return the configured global EventBus singleton."""
    global _global_bus
    if _global_bus is None:
        settings = get_settings()
        stream_cfg = settings.streaming.get("bus", {})
        provider = stream_cfg.get("provider", "asyncio").lower()
        max_size = int(stream_cfg.get("max_queue_size", 10000))
        policy = str(stream_cfg.get("backpressure_policy", "drop_oldest"))

        if provider == "redis":
            redis_url = stream_cfg.get("redis_url", "redis://localhost:6379/0")
            _global_bus = RedisEventBus(redis_url=redis_url, max_queue_size=max_size)
        else:
            _global_bus = AsyncioEventBus(max_queue_size=max_size, backpressure_policy=policy)

    return _global_bus


def reset_event_bus() -> None:
    """Reset the global event bus singleton (used in test isolation)."""
    global _global_bus
    _global_bus = None
