
"""
NETSHADOW - Device History

Histórico local de alterações dos dispositivos.
Não realiza descobertas nem atividade de rede.
"""

from __future__ import annotations

import ipaddress
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from threading import RLock
from typing import Any, Optional
from uuid import uuid4


class DeviceHistoryError(ValueError):
    """Erro base do histórico de dispositivos."""


@dataclass
class DeviceHistoryEntry:
    event_id: str
    device_id: str
    event_type: str
    timestamp: str
    changes: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class DeviceHistoryRecord:
    device_id: str
    first_seen: str
    last_seen: str
    total_events: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class DeviceHistory:
    """Regista e consulta alterações de dispositivos."""

    ALLOWED_EVENTS = {
        "discovered",
        "updated",
        "metadata_changed",
        "status_changed",
        "removed",
    }

    ALLOWED_FIELDS = {
        "ip_address",
        "mac_address",
        "hostname",
        "vendor",
        "device_type",
        "operating_system",
        "status",
    }

    def __init__(self, max_events: int = 10000) -> None:
        if (
            isinstance(max_events, bool)
            or not isinstance(max_events, int)
            or max_events < 1
        ):
            raise DeviceHistoryError(
                "max_events tem de ser um inteiro positivo."
            )

        self.max_events = max_events
        self._events: list[DeviceHistoryEntry] = []
        self._records: dict[str, DeviceHistoryRecord] = {}
        self._lock = RLock()

    @staticmethod
    def _validate_device_id(device_id: str) -> str:
        if not isinstance(device_id, str):
            raise DeviceHistoryError(
                "O identificador do dispositivo tem de ser texto."
            )

        device_id = device_id.strip()

        if not device_id or len(device_id) > 128:
            raise DeviceHistoryError(
                "Identificador do dispositivo inválido."
            )

        if any(ord(char) < 32 for char in device_id):
            raise DeviceHistoryError(
                "Identificador contém caracteres inválidos."
            )

        return device_id

    @staticmethod
    def _timestamp() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _validate_metadata(
        metadata: Optional[dict[str, Any]],
    ) -> dict[str, Any]:
        if metadata is None:
            return {}

        if not isinstance(metadata, dict):
            raise DeviceHistoryError(
                "metadata tem de ser um dicionário."
            )

        if len(metadata) > 100:
            raise DeviceHistoryError(
                "Demasiados campos de metadados."
            )

        return dict(metadata)

    def record_event(
        self,
        device_id: str,
        event_type: str,
        changes: Optional[dict[str, Any]] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> DeviceHistoryEntry:
        """Regista um acontecimento relacionado com um dispositivo."""

        device_id = self._validate_device_id(device_id)

        if event_type not in self.ALLOWED_EVENTS:
            raise DeviceHistoryError(
                f"Tipo de evento inválido: {event_type}"
            )

        if changes is not None and not isinstance(changes, dict):
            raise DeviceHistoryError(
                "changes tem de ser um dicionário."
            )

        changes = dict(changes or {})

        if len(changes) > 50:
            raise DeviceHistoryError(
                "Demasiadas alterações num único evento."
            )

        invalid_fields = set(changes) - self.ALLOWED_FIELDS

        if invalid_fields:
            raise DeviceHistoryError(
                f"Campos não permitidos: {sorted(invalid_fields)}"
            )

        metadata = self._validate_metadata(metadata)

        now = self._timestamp()

        entry = DeviceHistoryEntry(
            event_id=str(uuid4()),
            device_id=device_id,
            event_type=event_type,
            timestamp=now,
            changes=changes,
            metadata=metadata,
        )

        with self._lock:
            if len(self._events) >= self.max_events:
                raise DeviceHistoryError(
                    "Limite máximo de eventos atingido."
                )

            self._events.append(entry)

            record = self._records.get(device_id)

            if record is None:
                record = DeviceHistoryRecord(
                    device_id=device_id,
                    first_seen=now,
                    last_seen=now,
                    total_events=0,
                )
                self._records[device_id] = record

            record.last_seen = now
            record.total_events += 1

        return entry

    def record_discovery(
        self,
        device_id: str,
        metadata: Optional[dict[str, Any]] = None,
    ) -> DeviceHistoryEntry:
        return self.record_event(
            device_id=device_id,
            event_type="discovered",
            metadata=metadata,
        )

    def record_update(
        self,
        device_id: str,
        changes: dict[str, Any],
    ) -> DeviceHistoryEntry:
        return self.record_event(
            device_id=device_id,
            event_type="updated",
            changes=changes,
        )

    def record_removal(
        self,
        device_id: str,
        metadata: Optional[dict[str, Any]] = None,
    ) -> DeviceHistoryEntry:
        return self.record_event(
            device_id=device_id,
            event_type="removed",
            metadata=metadata,
        )

    def get_device_history(
        self,
        device_id: str,
    ) -> list[DeviceHistoryEntry]:
        device_id = self._validate_device_id(device_id)

        with self._lock:
            return [
                event
                for event in self._events
                if event.device_id == device_id
            ]

    def get_event(
        self,
        event_id: str,
    ) -> Optional[DeviceHistoryEntry]:
        if not isinstance(event_id, str):
            raise DeviceHistoryError(
                "event_id tem de ser texto."
            )

        with self._lock:
            for event in self._events:
                if event.event_id == event_id:
                    return event

        return None

    def get_all_events(self) -> list[DeviceHistoryEntry]:
        with self._lock:
            return list(self._events)

    def get_device_record(
        self,
        device_id: str,
    ) -> Optional[DeviceHistoryRecord]:
        device_id = self._validate_device_id(device_id)

        with self._lock:
            return self._records.get(device_id)

    def get_all_records(self) -> list[DeviceHistoryRecord]:
        with self._lock:
            return list(self._records.values())

    def get_events_by_type(
        self,
        event_type: str,
    ) -> list[DeviceHistoryEntry]:
        if event_type not in self.ALLOWED_EVENTS:
            raise DeviceHistoryError(
                "Tipo de evento inválido."
            )

        with self._lock:
            return [
                event
                for event in self._events
                if event.event_type == event_type
            ]

    def clear_device_history(self, device_id: str) -> int:
        device_id = self._validate_device_id(device_id)

        with self._lock:
            previous_count = len(self._events)

            self._events = [
                event
                for event in self._events
                if event.device_id != device_id
            ]

            self._records.pop(device_id, None)

            return previous_count - len(self._events)

    def clear_all(self) -> None:
        with self._lock:
            self._events.clear()
            self._records.clear()

    def get_summary(self) -> dict[str, Any]:
        with self._lock:
            events = list(self._events)
            records = list(self._records.values())

        event_types: dict[str, int] = {}

        for event in events:
            event_types[event.event_type] = (
                event_types.get(event.event_type, 0) + 1
            )

        return {
            "total_devices": len(records),
            "total_events": len(events),
            "event_types": event_types,
            "max_events": self.max_events,
        }

    def get_status(self) -> dict[str, Any]:
        with self._lock:
            return {
                "available": True,
                "storage": "memory",
                "total_devices": len(self._records),
                "total_events": len(self._events),
                "max_events": self.max_events,
            }


DeviceHistoryManager = DeviceHistory
DeviceHistoryEngine = DeviceHistory

__all__ = [
    "DeviceHistoryError",
    "DeviceHistoryEntry",
    "DeviceHistoryRecord",
    "DeviceHistory",
    "DeviceHistoryManager",
    "DeviceHistoryEngine",
]
