
"""
NETSHADOW - Availability Monitor

Monitorização passiva da disponibilidade de dispositivos.
Recebe resultados de verificações externas autorizadas.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
from threading import RLock
from typing import Any, Optional


class AvailabilityError(ValueError):
    """Erro base do monitor de disponibilidade."""


class AvailabilityState(str, Enum):
    ONLINE = "online"
    OFFLINE = "offline"
    UNKNOWN = "unknown"


@dataclass
class AvailabilityResult:
    device_id: str
    state: AvailabilityState
    timestamp: str
    source: str
    response_time_ms: Optional[float] = None
    message: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["state"] = self.state.value
        return result


@dataclass
class AvailabilityRecord:
    device_id: str
    current_state: AvailabilityState
    first_seen: str
    last_checked: str
    total_checks: int = 0
    online_checks: int = 0
    offline_checks: int = 0
    unknown_checks: int = 0

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["current_state"] = self.current_state.value
        return result


class AvailabilityMonitor:
    """Gere o estado de disponibilidade dos dispositivos."""

    def __init__(self, max_history: int = 10000) -> None:
        if (
            isinstance(max_history, bool)
            or not isinstance(max_history, int)
            or max_history < 1
        ):
            raise AvailabilityError(
                "max_history tem de ser um inteiro positivo."
            )

        self.max_history = max_history

        self._history: list[AvailabilityResult] = []
        self._records: dict[str, AvailabilityRecord] = {}

        self._lock = RLock()

    @staticmethod
    def _validate_device_id(device_id: str) -> str:
        if not isinstance(device_id, str):
            raise AvailabilityError(
                "device_id tem de ser texto."
            )

        device_id = device_id.strip()

        if not device_id or len(device_id) > 128:
            raise AvailabilityError(
                "Identificador de dispositivo inválido."
            )

        if any(ord(char) < 32 for char in device_id):
            raise AvailabilityError(
                "Identificador contém caracteres inválidos."
            )

        return device_id

    @staticmethod
    def _validate_source(source: str) -> str:
        if not isinstance(source, str):
            raise AvailabilityError(
                "source tem de ser texto."
            )

        source = source.strip()

        if not source or len(source) > 100:
            raise AvailabilityError(
                "Origem inválida."
            )

        if any(ord(char) < 32 for char in source):
            raise AvailabilityError(
                "Origem contém caracteres inválidos."
            )

        return source

    @staticmethod
    def _validate_state(
        state: AvailabilityState | str,
    ) -> AvailabilityState:
        if isinstance(state, AvailabilityState):
            return state

        if not isinstance(state, str):
            raise AvailabilityError(
                "Estado de disponibilidade inválido."
            )

        try:
            return AvailabilityState(state.lower().strip())
        except ValueError as exc:
            raise AvailabilityError(
                f"Estado desconhecido: {state}"
            ) from exc

    @staticmethod
    def _validate_response_time(
        response_time_ms: Optional[float],
    ) -> Optional[float]:
        if response_time_ms is None:
            return None

        if isinstance(response_time_ms, bool) or not isinstance(
            response_time_ms, (int, float)
        ):
            raise AvailabilityError(
                "Tempo de resposta inválido."
            )

        if response_time_ms < 0 or response_time_ms == float("inf"):
            raise AvailabilityError(
                "Tempo de resposta fora dos limites."
            )

        if response_time_ms != response_time_ms:
            raise AvailabilityError(
                "Tempo de resposta inválido."
            )

        return round(float(response_time_ms), 3)

    def record_result(
        self,
        device_id: str,
        state: AvailabilityState | str,
        source: str = "external",
        response_time_ms: Optional[float] = None,
        message: Optional[str] = None,
    ) -> AvailabilityResult:
        """Regista um resultado recebido de outra fonte."""

        device_id = self._validate_device_id(device_id)
        state = self._validate_state(state)
        source = self._validate_source(source)

        response_time_ms = self._validate_response_time(
            response_time_ms
        )

        if message is not None:
            if not isinstance(message, str):
                raise AvailabilityError(
                    "message tem de ser texto."
                )

            message = message.strip()[:500] or None

        timestamp = datetime.now(timezone.utc).isoformat()

        result = AvailabilityResult(
            device_id=device_id,
            state=state,
            timestamp=timestamp,
            source=source,
            response_time_ms=response_time_ms,
            message=message,
        )

        with self._lock:
            if len(self._history) >= self.max_history:
                raise AvailabilityError(
                    "Limite máximo do histórico atingido."
                )

            record = self._records.get(device_id)

            if record is None:
                record = AvailabilityRecord(
                    device_id=device_id,
                    current_state=state,
                    first_seen=timestamp,
                    last_checked=timestamp,
                )

                self._records[device_id] = record

            record.current_state = state
            record.last_checked = timestamp
            record.total_checks += 1

            if state == AvailabilityState.ONLINE:
                record.online_checks += 1

            elif state == AvailabilityState.OFFLINE:
                record.offline_checks += 1

            else:
                record.unknown_checks += 1

            self._history.append(result)

        return result

    def get_status(
        self,
        device_id: str,
    ) -> Optional[AvailabilityRecord]:
        device_id = self._validate_device_id(device_id)

        with self._lock:
            return self._records.get(device_id)

    def get_all_statuses(self) -> list[AvailabilityRecord]:
        with self._lock:
            return list(self._records.values())

    def get_history(
        self,
        device_id: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> list[AvailabilityResult]:
        if device_id is not None:
            device_id = self._validate_device_id(device_id)

        if limit is not None:
            if (
                isinstance(limit, bool)
                or not isinstance(limit, int)
                or limit < 1
            ):
                raise AvailabilityError(
                    "limit tem de ser um inteiro positivo."
                )

        with self._lock:
            history = list(self._history)

        if device_id is not None:
            history = [
                item for item in history
                if item.device_id == device_id
            ]

        if limit is not None:
            history = history[-limit:]

        return history

    def get_online_devices(self) -> list[AvailabilityRecord]:
        with self._lock:
            return [
                record
                for record in self._records.values()
                if record.current_state == AvailabilityState.ONLINE
            ]

    def get_offline_devices(self) -> list[AvailabilityRecord]:
        with self._lock:
            return [
                record
                for record in self._records.values()
                if record.current_state == AvailabilityState.OFFLINE
            ]

    def get_uptime_percentage(
        self,
        device_id: str,
    ) -> Optional[float]:
        device_id = self._validate_device_id(device_id)

        with self._lock:
            record = self._records.get(device_id)

            if record is None or record.total_checks == 0:
                return None

            # Resultados UNKNOWN não entram no denominador.
            known_checks = (
                record.online_checks + record.offline_checks
            )

            if known_checks == 0:
                return None

            return round(
                record.online_checks / known_checks * 100,
                2,
            )

    def remove_device(self, device_id: str) -> bool:
        device_id = self._validate_device_id(device_id)

        with self._lock:
            removed = self._records.pop(
                device_id,
                None,
            ) is not None

            self._history = [
                item
                for item in self._history
                if item.device_id != device_id
            ]

            return removed

    def clear(self) -> None:
        with self._lock:
            self._history.clear()
            self._records.clear()

    def get_summary(self) -> dict[str, Any]:
        with self._lock:
            records = list(self._records.values())

        counts = {
            state.value: sum(
                record.current_state == state
                for record in records
            )
            for state in AvailabilityState
        }

        return {
            "total_devices": len(records),
            "states": counts,
            "total_checks": sum(
                record.total_checks for record in records
            ),
        }

    def get_monitor_status(self) -> dict[str, Any]:
        with self._lock:
            return {
                "available": True,
                "mode": "passive_results",
                "automatic_probes": False,
                "tracked_devices": len(self._records),
                "history_entries": len(self._history),
                "max_history": self.max_history,
            }



Availability = AvailabilityMonitor
AvailabilityManager = AvailabilityMonitor
AvailabilityEngine = AvailabilityMonitor

__all__ = [
    "AvailabilityError",
    "AvailabilityState",
    "AvailabilityResult",
    "AvailabilityRecord",
    "AvailabilityMonitor",
    "Availability",
    "AvailabilityManager",
    "AvailabilityEngine",
]
