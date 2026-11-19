
"""
NETSHADOW - Event Bus

Sistema central de comunicação entre componentes.
"""

from __future__ import annotations

import logging

from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from threading import RLock
from typing import Any, Callable
from uuid import uuid4


EventHandler = Callable[["Event"], Any]


@dataclass(frozen=True)
class Event:
    event_id: str
    name: str
    payload: dict[str, Any]
    created_at: datetime
    source: str = "NETSHADOW"


@dataclass
class Subscription:
    subscription_id: str
    event_name: str
    handler: EventHandler
    active: bool = True


class EventBus:
    """Distribui eventos entre os componentes da aplicação."""

    MAX_HISTORY = 1000

    def __init__(
        self,
        logger: logging.Logger | None = None,
    ):
        self.logger = logger or logging.getLogger("NETSHADOW")
        self._subscriptions: dict[str, Subscription] = {}
        self._history: deque[Event] = deque(
            maxlen=self.MAX_HISTORY
        )
        self._lock = RLock()

    @staticmethod
    def _validate_event_name(name: str) -> bool:
        if not isinstance(name, str):
            return False

        if not name or len(name) > 128:
            return False

        return all(
            character.isalnum()
            or character in "._-"
            for character in name
        )

    def subscribe(
        self,
        event_name: str,
        handler: EventHandler,
    ) -> str:
        if not self._validate_event_name(event_name):
            raise ValueError("Invalid event name.")

        if not callable(handler):
            raise TypeError("Event handler must be callable.")

        subscription_id = str(uuid4())

        subscription = Subscription(
            subscription_id=subscription_id,
            event_name=event_name,
            handler=handler,
        )

        with self._lock:
            self._subscriptions[subscription_id] = subscription

        self.logger.debug(
            "Event subscription registered: %s",
            event_name,
        )

        return subscription_id

    def unsubscribe(self, subscription_id: str) -> bool:
        with self._lock:
            subscription = self._subscriptions.get(
                subscription_id
            )

            if subscription is None:
                return False

            subscription.active = False
            del self._subscriptions[subscription_id]

        return True

    def publish(
        self,
        event_name: str,
        payload: dict[str, Any] | None = None,
        source: str = "NETSHADOW",
    ) -> Event:
        if not self._validate_event_name(event_name):
            raise ValueError("Invalid event name.")

        if payload is not None and not isinstance(payload, dict):
            raise TypeError("Event payload must be a dictionary.")

        if not isinstance(source, str) or not source.strip():
            raise ValueError("Invalid event source.")

        event = Event(
            event_id=str(uuid4()),
            name=event_name,
            payload=dict(payload or {}),
            created_at=datetime.now(timezone.utc),
            source=source.strip(),
        )

        with self._lock:
            self._history.append(event)

            handlers = [
                subscription.handler
                for subscription in self._subscriptions.values()
                if (
                    subscription.event_name == event_name
                    and subscription.active
                )
            ]

        for handler in handlers:
            try:
                handler(event)
            except Exception:
                self.logger.exception(
                    "Event handler failed: %s",
                    event_name,
                )

        return event

    def get_history(
        self,
        event_name: str | None = None,
        limit: int = 100,
    ) -> list[Event]:
        if not isinstance(limit, int) or limit < 1:
            return []

        limit = min(limit, self.MAX_HISTORY)

        with self._lock:
            events = list(self._history)

        if event_name is not None:
            if not self._validate_event_name(event_name):
                return []

            events = [
                event
                for event in events
                if event.name == event_name
            ]

        return events[-limit:]

    def clear_history(self) -> None:
        with self._lock:
            self._history.clear()

    def get_subscription_count(
        self,
        event_name: str | None = None,
    ) -> int:
        with self._lock:
            subscriptions = list(
                self._subscriptions.values()
            )

        if event_name is None:
            return len(subscriptions)

        return sum(
            subscription.event_name == event_name
            and subscription.active
            for subscription in subscriptions
        )

    def unsubscribe_all(self) -> int:
        with self._lock:
            count = len(self._subscriptions)

            for subscription in self._subscriptions.values():
                subscription.active = False

            self._subscriptions.clear()

        return count
