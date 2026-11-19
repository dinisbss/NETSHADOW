
"""
NETSHADOW - Change Detection

Deteção passiva de alterações nos dispositivos monitorizados.
Compara snapshots fornecidos por outros componentes.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from threading import RLock
from typing import Any, Optional


class ChangeDetectionError(ValueError):
    """Erro base da deteção de alterações."""


class ChangeType(str, Enum):
    ADDED = "added"
    REMOVED = "removed"
    MODIFIED = "modified"


@dataclass
class ChangeEvent:
    device_id: str
    field_name: str
    change_type: ChangeType
    previous_value: Any
    current_value: Any
    timestamp: str
    source: str = "external"

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["change_type"] = self.change_type.value
        return result


@dataclass
class DeviceSnapshot:
    device_id: str
    attributes: dict[str, Any]
    timestamp: str
    source: str = "external"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ChangeSummary:
    device_id: str
    total_changes: int
    added: int
    removed: int
    modified: int
    last_change: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ChangeDetector:
    """Compara snapshots e identifica alterações."""

    def __init__(self, max_history: int = 10000) -> None:
        if (
            isinstance(max_history, bool)
            or not isinstance(max_history, int)
            or max_history < 1
        ):
            raise ChangeDetectionError(
                "max_history tem de ser um inteiro positivo."
            )

        self.max_history = max_history

        self._snapshots: dict[str, DeviceSnapshot] = {}
        self._history: list[ChangeEvent] = []
        self._lock = RLock()

    @staticmethod
    def _validate_device_id(device_id: str) -> str:
        if not isinstance(device_id, str):
            raise ChangeDetectionError(
                "device_id tem de ser texto."
            )

        device_id = device_id.strip()

        if not device_id or len(device_id) > 128:
            raise ChangeDetectionError(
                "Identificador de dispositivo inválido."
            )

        if any(ord(char) < 32 for char in device_id):
            raise ChangeDetectionError(
                "Identificador contém caracteres inválidos."
            )

        return device_id

    @staticmethod
    def _validate_source(source: str) -> str:
        if not isinstance(source, str):
            raise ChangeDetectionError(
                "source tem de ser texto."
            )

        source = source.strip()

        if not source or len(source) > 100:
            raise ChangeDetectionError(
                "Origem inválida."
            )

        if any(ord(char) < 32 for char in source):
            raise ChangeDetectionError(
                "Origem contém caracteres inválidos."
            )

        return source

    @staticmethod
    def _validate_attributes(
        attributes: dict[str, Any],
    ) -> dict[str, Any]:
        if not isinstance(attributes, dict):
            raise ChangeDetectionError(
                "attributes tem de ser um dicionário."
            )

        if len(attributes) > 500:
            raise ChangeDetectionError(
                "Número máximo de atributos excedido."
            )

        result = {}

        for key, value in attributes.items():
            if not isinstance(key, str):
                raise ChangeDetectionError(
                    "Os nomes dos atributos têm de ser texto."
                )

            key = key.strip()

            if (
                not key
                or len(key) > 100
                or any(ord(char) < 32 for char in key)
            ):
                raise ChangeDetectionError(
                    "Nome de atributo inválido."
                )

            try:
                copied_value = deepcopy(value)
            except Exception as exc:
                raise ChangeDetectionError(
                    f"Valor inválido no atributo {key}."
                ) from exc

            result[key] = copied_value

        return result

    @staticmethod
    def _timestamp() -> str:
        return datetime.now(timezone.utc).isoformat()

    def update_snapshot(
        self,
        device_id: str,
        attributes: dict[str, Any],
        source: str = "external",
    ) -> list[ChangeEvent]:
        """Atualiza um snapshot e devolve as alterações detetadas."""

        device_id = self._validate_device_id(device_id)
        source = self._validate_source(source)

        attributes = self._validate_attributes(attributes)

        timestamp = self._timestamp()

        with self._lock:
            previous = self._snapshots.get(device_id)

            if previous is None:
                snapshot = DeviceSnapshot(
                    device_id=device_id,
                    attributes=attributes,
                    timestamp=timestamp,
                    source=source,
                )

                self._snapshots[device_id] = snapshot
                return []

            changes = []

            previous_attributes = previous.attributes

            all_fields = sorted(
                set(previous_attributes) | set(attributes)
            )

            for field_name in all_fields:
                old_exists = field_name in previous_attributes
                new_exists = field_name in attributes

                if not old_exists and new_exists:
                    change_type = ChangeType.ADDED
                    old_value = None
                    new_value = attributes[field_name]

                elif old_exists and not new_exists:
                    change_type = ChangeType.REMOVED
                    old_value = previous_attributes[field_name]
                    new_value = None

                elif previous_attributes[field_name] != attributes[field_name]:
                    change_type = ChangeType.MODIFIED
                    old_value = previous_attributes[field_name]
                    new_value = attributes[field_name]

                else:
                    continue

                changes.append(
                    ChangeEvent(
                        device_id=device_id,
                        field_name=field_name,
                        change_type=change_type,
                        previous_value=deepcopy(old_value),
                        current_value=deepcopy(new_value),
                        timestamp=timestamp,
                        source=source,
                    )
                )

            if len(self._history) + len(changes) > self.max_history:
                raise ChangeDetectionError(
                    "Limite máximo do histórico atingido."
                )

            self._history.extend(changes)

            self._snapshots[device_id] = DeviceSnapshot(
                device_id=device_id,
                attributes=attributes,
                timestamp=timestamp,
                source=source,
            )

            return list(changes)

    def get_snapshot(
        self,
        device_id: str,
    ) -> Optional[DeviceSnapshot]:
        device_id = self._validate_device_id(device_id)

        with self._lock:
            snapshot = self._snapshots.get(device_id)

            return deepcopy(snapshot) if snapshot else None

    def get_all_snapshots(self) -> list[DeviceSnapshot]:
        with self._lock:
            return deepcopy(list(self._snapshots.values()))

    def get_history(
        self,
        device_id: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> list[ChangeEvent]:
        if device_id is not None:
            device_id = self._validate_device_id(device_id)

        if limit is not None:
            if (
                isinstance(limit, bool)
                or not isinstance(limit, int)
                or limit < 1
            ):
                raise ChangeDetectionError(
                    "limit tem de ser um inteiro positivo."
                )

        with self._lock:
            history = list(self._history)

        if device_id is not None:
            history = [
                event for event in history
                if event.device_id == device_id
            ]

        if limit is not None:
            history = history[-limit:]

        return deepcopy(history)

    def get_changes_by_type(
        self,
        change_type: ChangeType | str,
    ) -> list[ChangeEvent]:
        try:
            if not isinstance(change_type, ChangeType):
                change_type = ChangeType(change_type)
        except (ValueError, TypeError) as exc:
            raise ChangeDetectionError(
                "Tipo de alteração inválido."
            ) from exc

        with self._lock:
            return deepcopy([
                event for event in self._history
                if event.change_type == change_type
            ])

    def get_summary(
        self,
        device_id: Optional[str] = None,
    ) -> ChangeSummary:
        if device_id is not None:
            device_id = self._validate_device_id(device_id)

        with self._lock:
            events = [
                event for event in self._history
                if device_id is None
                or event.device_id == device_id
            ]

        added = sum(
            event.change_type == ChangeType.ADDED
            for event in events
        )

        removed = sum(
            event.change_type == ChangeType.REMOVED
            for event in events
        )

        modified = sum(
            event.change_type == ChangeType.MODIFIED
            for event in events
        )

        devices = {event.device_id for event in events}

        target_id = (
            device_id
            if device_id is not None
            else "all"
        )

        return ChangeSummary(
            device_id=target_id,
            total_changes=len(events),
            added=added,
            removed=removed,
            modified=modified,
            last_change=events[-1].timestamp if events else None,
        )

    def remove_device(self, device_id: str) -> bool:
        device_id = self._validate_device_id(device_id)

        with self._lock:
            snapshot_removed = (
                self._snapshots.pop(device_id, None) is not None
            )

            original_length = len(self._history)

            self._history = [
                event for event in self._history
                if event.device_id != device_id
            ]

            history_removed = len(self._history) != original_length

            return snapshot_removed or history_removed

    def clear(self) -> None:
        with self._lock:
            self._snapshots.clear()
            self._history.clear()

    def get_status(self) -> dict[str, Any]:
        with self._lock:
            return {
                "available": True,
                "mode": "passive_snapshot_comparison",
                "automatic_scanning": False,
                "tracked_devices": len(self._snapshots),
                "history_entries": len(self._history),
                "max_history": self.max_history,
            }


ChangeDetection = ChangeDetector
ChangeDetectionManager = ChangeDetector
ChangeDetectionEngine = ChangeDetector

__all__ = [
    "ChangeDetectionError",
    "ChangeType",
    "ChangeEvent",
    "DeviceSnapshot",
    "ChangeSummary",
    "ChangeDetector",
    "ChangeDetection",
    "ChangeDetectionManager",
    "ChangeDetectionEngine",
]
