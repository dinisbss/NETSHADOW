
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping
from uuid import uuid4


class HistoryError(Exception):
    """Erro do módulo Monitoring History."""


class HistorySeverity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class HistoryEvent:
    event_id: str
    event_type: str
    category: str
    severity: HistorySeverity
    source: str
    device_id: str | None
    description: str
    timestamp: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "category": self.category,
            "severity": self.severity.value,
            "source": self.source,
            "device_id": self.device_id,
            "description": self.description,
            "timestamp": self.timestamp,
            "metadata": dict(self.metadata),
        }


class HistoryAnalyzer:
    """Regista e consulta eventos históricos locais."""

    def __init__(self, maximum_events: int = 10000) -> None:
        if (
            isinstance(maximum_events, bool)
            or not isinstance(maximum_events, int)
            or maximum_events < 1
        ):
            raise HistoryError(
                "maximum_events must be a positive integer"
            )

        self.maximum_events = maximum_events
        self._events: list[HistoryEvent] = []

    @staticmethod
    def _text(value: Any, field_name: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise HistoryError(f"{field_name} is required")
        return value.strip()

    @staticmethod
    def _severity(
        value: HistorySeverity | str,
    ) -> HistorySeverity:
        try:
            return HistorySeverity(value)
        except ValueError as exc:
            raise HistoryError(
                "Invalid event severity"
            ) from exc

    @staticmethod
    def _parse_datetime(value: str) -> datetime:
        if not isinstance(value, str) or not value.strip():
            raise HistoryError("Invalid timestamp")

        try:
            result = datetime.fromisoformat(
                value.replace("Z", "+00:00")
            )
        except ValueError as exc:
            raise HistoryError("Invalid timestamp") from exc

        if result.tzinfo is None:
            raise HistoryError(
                "Timestamp must include timezone"
            )

        return result.astimezone(timezone.utc)

    def record(
        self,
        event_type: str,
        category: str,
        description: str,
        severity: HistorySeverity | str = HistorySeverity.INFO,
        source: str = "netshadow",
        device_id: str | None = None,
        metadata: Mapping[str, Any] | None = None,
        timestamp: str | None = None,
    ) -> HistoryEvent:

        event_type = self._text(event_type, "event_type")
        category = self._text(category, "category").lower()
        description = self._text(description, "description")
        source = self._text(source, "source")
        severity = self._severity(severity)

        if device_id is not None:
            device_id = self._text(device_id, "device_id")

        event_time = (
            self._parse_datetime(timestamp).isoformat()
            if timestamp is not None
            else datetime.now(timezone.utc).isoformat()
        )

        event = HistoryEvent(
            event_id=str(uuid4()),
            event_type=event_type,
            category=category,
            severity=severity,
            source=source,
            device_id=device_id,
            description=description,
            timestamp=event_time,
            metadata=dict(metadata or {}),
        )

        self._events.append(event)

        if len(self._events) > self.maximum_events:
            self._events.pop(0)

        return event

    def get(self, event_id: str) -> HistoryEvent | None:
        return next(
            (
                event for event in self._events
                if event.event_id == event_id
            ),
            None,
        )

    def search(
        self,
        device_id: str | None = None,
        category: str | None = None,
        severity: HistorySeverity | str | None = None,
        event_type: str | None = None,
        start_time: str | None = None,
        end_time: str | None = None,
    ) -> list[HistoryEvent]:

        selected_severity = (
            self._severity(severity)
            if severity is not None
            else None
        )

        start = (
            self._parse_datetime(start_time)
            if start_time is not None
            else None
        )

        end = (
            self._parse_datetime(end_time)
            if end_time is not None
            else None
        )

        if start is not None and end is not None and start > end:
            raise HistoryError(
                "start_time must not be after end_time"
            )

        results = self._events

        if device_id is not None:
            results = [
                event for event in results
                if event.device_id == device_id
            ]

        if category is not None:
            results = [
                event for event in results
                if event.category == category.lower()
            ]

        if selected_severity is not None:
            results = [
                event for event in results
                if event.severity == selected_severity
            ]

        if event_type is not None:
            results = [
                event for event in results
                if event.event_type == event_type
            ]

        if start is not None:
            results = [
                event for event in results
                if self._parse_datetime(event.timestamp) >= start
            ]

        if end is not None:
            results = [
                event for event in results
                if self._parse_datetime(event.timestamp) <= end
            ]

        return list(results)

    def get_all(self) -> list[HistoryEvent]:
        return list(self._events)

    def export(self) -> list[dict[str, Any]]:
        return [
            event.to_dict()
            for event in self._events
        ]

    def clear(self) -> int:
        count = len(self._events)
        self._events.clear()
        return count

    def get_summary(self) -> dict[str, Any]:
        events = self._events

        return {
            "total_events": len(events),
            "devices": len({
                event.device_id
                for event in events
                if event.device_id is not None
            }),
            "by_severity": {
                severity.value: sum(
                    event.severity == severity
                    for event in events
                )
                for severity in HistorySeverity
            },
            "by_category": {
                category: sum(
                    event.category == category
                    for event in events
                )
                for category in sorted({
                    event.category for event in events
                })
            },
        }


__all__ = [
    "HistoryError",
    "HistorySeverity",
    "HistoryEvent",
    "HistoryAnalyzer",
]
