
"""
NETSHADOW - Latency Monitor

Registo e análise passiva de medições de latência.
Não executa sondagens nem gera tráfego de rede.
"""

from __future__ import annotations

import math
import statistics
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from threading import RLock
from typing import Any, Optional


class LatencyError(ValueError):
    """Erro base do monitor de latência."""


@dataclass
class LatencyMeasurement:
    device_id: str
    latency_ms: float
    timestamp: str
    source: str = "external"
    metadata: Optional[dict[str, Any]] = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class LatencyStatistics:
    device_id: str
    samples: int
    minimum_ms: float
    maximum_ms: float
    average_ms: float
    median_ms: float
    jitter_ms: float
    latest_ms: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class LatencyMonitor:
    """Gere medições e estatísticas de latência."""

    def __init__(self, max_history: int = 10000) -> None:
        if (
            isinstance(max_history, bool)
            or not isinstance(max_history, int)
            or max_history < 1
        ):
            raise LatencyError(
                "max_history tem de ser um inteiro positivo."
            )

        self.max_history = max_history
        self._history: list[LatencyMeasurement] = []
        self._lock = RLock()

    @staticmethod
    def _validate_device_id(device_id: str) -> str:
        if not isinstance(device_id, str):
            raise LatencyError(
                "device_id tem de ser texto."
            )

        device_id = device_id.strip()

        if not device_id or len(device_id) > 128:
            raise LatencyError(
                "Identificador de dispositivo inválido."
            )

        if any(ord(char) < 32 for char in device_id):
            raise LatencyError(
                "Identificador contém caracteres inválidos."
            )

        return device_id

    @staticmethod
    def _validate_latency(latency_ms: float) -> float:
        if isinstance(latency_ms, bool) or not isinstance(
            latency_ms, (int, float)
        ):
            raise LatencyError(
                "A latência tem de ser numérica."
            )

        value = float(latency_ms)

        if not math.isfinite(value) or value < 0:
            raise LatencyError(
                "A latência tem de ser finita e não negativa."
            )

        return round(value, 3)

    @staticmethod
    def _validate_source(source: str) -> str:
        if not isinstance(source, str):
            raise LatencyError(
                "source tem de ser texto."
            )

        source = source.strip()

        if not source or len(source) > 100:
            raise LatencyError(
                "Origem inválida."
            )

        if any(ord(char) < 32 for char in source):
            raise LatencyError(
                "Origem contém caracteres inválidos."
            )

        return source

    def record(
        self,
        device_id: str,
        latency_ms: float,
        source: str = "external",
        metadata: Optional[dict[str, Any]] = None,
    ) -> LatencyMeasurement:
        """Regista uma medição recebida externamente."""

        device_id = self._validate_device_id(device_id)
        latency_ms = self._validate_latency(latency_ms)
        source = self._validate_source(source)

        if metadata is not None and not isinstance(metadata, dict):
            raise LatencyError(
                "metadata tem de ser um dicionário."
            )

        timestamp = datetime.now(timezone.utc).isoformat()

        measurement = LatencyMeasurement(
            device_id=device_id,
            latency_ms=latency_ms,
            timestamp=timestamp,
            source=source,
            metadata=dict(metadata) if metadata is not None else None,
        )

        with self._lock:
            if len(self._history) >= self.max_history:
                raise LatencyError(
                    "Limite máximo do histórico atingido."
                )

            self._history.append(measurement)

        return measurement

    def get_history(
        self,
        device_id: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> list[LatencyMeasurement]:
        if device_id is not None:
            device_id = self._validate_device_id(device_id)

        if limit is not None:
            if (
                isinstance(limit, bool)
                or not isinstance(limit, int)
                or limit < 1
            ):
                raise LatencyError(
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

    def get_statistics(
        self,
        device_id: str,
    ) -> Optional[LatencyStatistics]:
        device_id = self._validate_device_id(device_id)

        with self._lock:
            values = [
                item.latency_ms
                for item in self._history
                if item.device_id == device_id
            ]

        if not values:
            return None

        differences = [
            abs(values[index] - values[index - 1])
            for index in range(1, len(values))
        ]

        jitter = (
            statistics.mean(differences)
            if differences
            else 0.0
        )

        return LatencyStatistics(
            device_id=device_id,
            samples=len(values),
            minimum_ms=round(min(values), 3),
            maximum_ms=round(max(values), 3),
            average_ms=round(statistics.mean(values), 3),
            median_ms=round(statistics.median(values), 3),
            jitter_ms=round(jitter, 3),
            latest_ms=round(values[-1], 3),
        )

    def get_all_statistics(self) -> dict[str, LatencyStatistics]:
        with self._lock:
            device_ids = list(
                dict.fromkeys(
                    item.device_id for item in self._history
                )
            )

        result = {}

        for device_id in device_ids:
            stats = self.get_statistics(device_id)

            if stats is not None:
                result[device_id] = stats

        return result

    def get_average(self, device_id: str) -> Optional[float]:
        stats = self.get_statistics(device_id)
        return stats.average_ms if stats else None

    def get_minimum(self, device_id: str) -> Optional[float]:
        stats = self.get_statistics(device_id)
        return stats.minimum_ms if stats else None

    def get_maximum(self, device_id: str) -> Optional[float]:
        stats = self.get_statistics(device_id)
        return stats.maximum_ms if stats else None

    def remove_device(self, device_id: str) -> bool:
        device_id = self._validate_device_id(device_id)

        with self._lock:
            original_length = len(self._history)

            self._history = [
                item for item in self._history
                if item.device_id != device_id
            ]

            return len(self._history) != original_length

    def clear(self) -> None:
        with self._lock:
            self._history.clear()

    def get_summary(self) -> dict[str, Any]:
        with self._lock:
            history = list(self._history)

        devices = list(
            dict.fromkeys(item.device_id for item in history)
        )

        return {
            "total_measurements": len(history),
            "tracked_devices": len(devices),
            "average_latency_ms": (
                round(
                    statistics.mean(
                        item.latency_ms for item in history
                    ),
                    3,
                )
                if history else None
            ),
        }

    def get_status(self) -> dict[str, Any]:
        with self._lock:
            return {
                "available": True,
                "mode": "passive_measurements",
                "automatic_probes": False,
                "measurements": len(self._history),
                "max_history": self.max_history,
            }


Latency = LatencyMonitor
LatencyManager = LatencyMonitor
LatencyEngine = LatencyMonitor
LatencyAnalyzer = LatencyMonitor

__all__ = [
    "LatencyError",
    "LatencyMeasurement",
    "LatencyStatistics",
    "LatencyMonitor",
    "Latency",
    "LatencyManager",
    "LatencyEngine",
    "LatencyAnalyzer",
]
