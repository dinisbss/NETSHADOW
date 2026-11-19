
"""
NETSHADOW - Metrics Manager

Recolha, armazenamento e análise de métricas.
Recebe valores de outros componentes, sem gerar tráfego.
"""

from __future__ import annotations

import math
import statistics
from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from threading import RLock
from typing import Any, Optional


class MetricsError(ValueError):
    """Erro base do sistema de métricas."""


@dataclass
class Metric:
    name: str
    value: float
    timestamp: str
    device_id: Optional[str] = None
    unit: Optional[str] = None
    source: str = "external"
    tags: Optional[dict[str, str]] = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class MetricStatistics:
    name: str
    samples: int
    minimum: float
    maximum: float
    average: float
    median: float
    latest: float
    total: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class MetricsManager:
    """Gere métricas e respetivos históricos."""

    def __init__(self, max_history: int = 20000) -> None:
        if (
            isinstance(max_history, bool)
            or not isinstance(max_history, int)
            or max_history < 1
        ):
            raise MetricsError(
                "max_history tem de ser um inteiro positivo."
            )

        self.max_history = max_history
        self._metrics: list[Metric] = []
        self._lock = RLock()

    @staticmethod
    def _validate_text(
        value: str,
        field: str,
        max_length: int = 100,
    ) -> str:
        if not isinstance(value, str):
            raise MetricsError(
                f"{field} tem de ser texto."
            )

        value = value.strip()

        if not value or len(value) > max_length:
            raise MetricsError(
                f"{field} inválido."
            )

        if any(ord(char) < 32 for char in value):
            raise MetricsError(
                f"{field} contém caracteres inválidos."
            )

        return value

    @staticmethod
    def _validate_value(value: float) -> float:
        if isinstance(value, bool) or not isinstance(
            value, (int, float)
        ):
            raise MetricsError(
                "O valor da métrica tem de ser numérico."
            )

        value = float(value)

        if not math.isfinite(value):
            raise MetricsError(
                "O valor da métrica tem de ser finito."
            )

        return round(value, 6)

    def record(
        self,
        name: str,
        value: float,
        device_id: Optional[str] = None,
        unit: Optional[str] = None,
        source: str = "external",
        tags: Optional[dict[str, str]] = None,
    ) -> Metric:
        """Regista uma nova métrica."""

        name = self._validate_text(name, "name")
        value = self._validate_value(value)
        source = self._validate_text(source, "source")

        if device_id is not None:
            device_id = self._validate_text(
                device_id,
                "device_id",
                128,
            )

        if unit is not None:
            unit = self._validate_text(unit, "unit", 30)

        if tags is not None:
            if not isinstance(tags, dict):
                raise MetricsError(
                    "tags tem de ser um dicionário."
                )

            validated_tags = {}

            for key, tag_value in tags.items():
                key = self._validate_text(
                    key,
                    "tag key",
                    50,
                )

                tag_value = self._validate_text(
                    tag_value,
                    "tag value",
                    100,
                )

                validated_tags[key] = tag_value

            tags = validated_tags

        metric = Metric(
            name=name,
            value=value,
            timestamp=datetime.now(timezone.utc).isoformat(),
            device_id=device_id,
            unit=unit,
            source=source,
            tags=dict(tags) if tags is not None else None,
        )

        with self._lock:
            if len(self._metrics) >= self.max_history:
                raise MetricsError(
                    "Limite máximo de métricas atingido."
                )

            self._metrics.append(metric)

        return metric

    def record_many(
        self,
        metrics: list[dict[str, Any]],
    ) -> list[Metric]:
        """Regista várias métricas de forma validada."""

        if not isinstance(metrics, list):
            raise MetricsError(
                "metrics tem de ser uma lista."
            )

        if len(metrics) > self.max_history:
            raise MetricsError(
                "Número de métricas demasiado elevado."
            )

        results = []

        for item in metrics:
            if not isinstance(item, dict):
                raise MetricsError(
                    "Cada métrica tem de ser um dicionário."
                )

            results.append(self.record(**item))

        return results

    def get_metrics(
        self,
        name: Optional[str] = None,
        device_id: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> list[Metric]:
        if name is not None:
            name = self._validate_text(name, "name")

        if device_id is not None:
            device_id = self._validate_text(
                device_id,
                "device_id",
                128,
            )

        if limit is not None:
            if (
                isinstance(limit, bool)
                or not isinstance(limit, int)
                or limit < 1
            ):
                raise MetricsError(
                    "limit tem de ser um inteiro positivo."
                )

        with self._lock:
            result = list(self._metrics)

        if name is not None:
            result = [
                metric for metric in result
                if metric.name == name
            ]

        if device_id is not None:
            result = [
                metric for metric in result
                if metric.device_id == device_id
            ]

        if limit is not None:
            result = result[-limit:]

        return result

    def get_statistics(
        self,
        name: str,
        device_id: Optional[str] = None,
    ) -> Optional[MetricStatistics]:
        metrics = self.get_metrics(
            name=name,
            device_id=device_id,
        )

        if not metrics:
            return None

        values = [metric.value for metric in metrics]

        return MetricStatistics(
            name=name,
            samples=len(values),
            minimum=round(min(values), 6),
            maximum=round(max(values), 6),
            average=round(statistics.mean(values), 6),
            median=round(statistics.median(values), 6),
            latest=values[-1],
            total=round(sum(values), 6),
        )

    def get_metric_names(self) -> list[str]:
        with self._lock:
            return sorted({
                metric.name for metric in self._metrics
            })

    def get_device_metrics(
        self,
        device_id: str,
    ) -> dict[str, list[Metric]]:
        device_id = self._validate_text(
            device_id,
            "device_id",
            128,
        )

        metrics = self.get_metrics(device_id=device_id)

        grouped: dict[str, list[Metric]] = defaultdict(list)

        for metric in metrics:
            grouped[metric.name].append(metric)

        return dict(grouped)

    def get_summary(self) -> dict[str, Any]:
        with self._lock:
            metrics = list(self._metrics)

        devices = {
            metric.device_id
            for metric in metrics
            if metric.device_id is not None
        }

        return {
            "total_metrics": len(metrics),
            "metric_types": len({
                metric.name for metric in metrics
            }),
            "tracked_devices": len(devices),
            "metric_names": sorted({
                metric.name for metric in metrics
            }),
        }

    def remove_device(self, device_id: str) -> int:
        device_id = self._validate_text(
            device_id,
            "device_id",
            128,
        )

        with self._lock:
            original = len(self._metrics)

            self._metrics = [
                metric for metric in self._metrics
                if metric.device_id != device_id
            ]

            return original - len(self._metrics)

    def remove_metric(self, name: str) -> int:
        name = self._validate_text(name, "name")

        with self._lock:
            original = len(self._metrics)

            self._metrics = [
                metric for metric in self._metrics
                if metric.name != name
            ]

            return original - len(self._metrics)

    def clear(self) -> None:
        with self._lock:
            self._metrics.clear()

    def get_status(self) -> dict[str, Any]:
        with self._lock:
            return {
                "available": True,
                "mode": "passive_collection",
                "automatic_collection": False,
                "total_metrics": len(self._metrics),
                "max_history": self.max_history,
            }


Metrics = MetricsManager
MetricsCollector = MetricsManager
MetricsEngine = MetricsManager

__all__ = [
    "MetricsError",
    "Metric",
    "MetricStatistics",
    "MetricsManager",
    "Metrics",
    "MetricsCollector",
    "MetricsEngine",
]
