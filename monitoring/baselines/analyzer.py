
from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from statistics import mean, pstdev
from typing import Any
from uuid import uuid4


class MonitoringBaselineError(Exception):
    """Erro do módulo Monitoring Baselines."""


@dataclass
class MetricBaseline:
    baseline_id: str
    device_id: str
    metric_name: str
    samples: list[float] = field(default_factory=list)
    created_at: str = ""
    updated_at: str = ""

    @property
    def sample_count(self) -> int:
        return len(self.samples)

    @property
    def average(self) -> float:
        return mean(self.samples) if self.samples else 0.0

    @property
    def minimum(self) -> float | None:
        return min(self.samples) if self.samples else None

    @property
    def maximum(self) -> float | None:
        return max(self.samples) if self.samples else None

    @property
    def standard_deviation(self) -> float:
        return pstdev(self.samples) if len(self.samples) > 1 else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "baseline_id": self.baseline_id,
            "device_id": self.device_id,
            "metric_name": self.metric_name,
            "samples": list(self.samples),
            "sample_count": self.sample_count,
            "average": self.average,
            "minimum": self.minimum,
            "maximum": self.maximum,
            "standard_deviation": self.standard_deviation,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


@dataclass
class BaselineComparison:
    baseline_id: str
    device_id: str
    metric_name: str
    current_value: float
    baseline_average: float
    deviation: float
    deviation_percent: float | None
    anomalous: bool
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "baseline_id": self.baseline_id,
            "device_id": self.device_id,
            "metric_name": self.metric_name,
            "current_value": self.current_value,
            "baseline_average": self.baseline_average,
            "deviation": self.deviation,
            "deviation_percent": self.deviation_percent,
            "anomalous": self.anomalous,
            "reason": self.reason,
        }


class MonitoringBaselineAnalyzer:
    """Mantém baselines locais e compara métricas com o histórico."""

    def __init__(
        self,
        minimum_samples: int = 3,
        deviation_threshold: float = 2.0,
        maximum_samples: int = 1000,
    ) -> None:

        if (
            isinstance(minimum_samples, bool)
            or not isinstance(minimum_samples, int)
            or minimum_samples < 2
        ):
            raise MonitoringBaselineError(
                "minimum_samples must be an integer >= 2"
            )

        if (
            isinstance(deviation_threshold, bool)
            or not isinstance(deviation_threshold, (int, float))
            or not math.isfinite(deviation_threshold)
            or deviation_threshold <= 0
        ):
            raise MonitoringBaselineError(
                "deviation_threshold must be positive and finite"
            )

        if (
            isinstance(maximum_samples, bool)
            or not isinstance(maximum_samples, int)
            or maximum_samples < minimum_samples
        ):
            raise MonitoringBaselineError(
                "maximum_samples must be >= minimum_samples"
            )

        self.minimum_samples = minimum_samples
        self.deviation_threshold = float(deviation_threshold)
        self.maximum_samples = maximum_samples
        self._baselines: dict[tuple[str, str], MetricBaseline] = {}

    @staticmethod
    def _validate_value(value: float) -> float:
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
        ):
            raise MonitoringBaselineError(
                "Metric value must be a finite number"
            )

        return float(value)

    @staticmethod
    def _validate_identifier(value: str, field_name: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise MonitoringBaselineError(
                f"{field_name} is required"
            )

        return value.strip()

    def record(
        self,
        device_id: str,
        metric_name: str,
        value: float,
    ) -> MetricBaseline:

        device_id = self._validate_identifier(
            device_id,
            "device_id",
        )
        metric_name = self._validate_identifier(
            metric_name,
            "metric_name",
        )
        value = self._validate_value(value)

        key = (device_id, metric_name)
        now = datetime.now(timezone.utc).isoformat()

        baseline = self._baselines.get(key)

        if baseline is None:
            baseline = MetricBaseline(
                baseline_id=str(uuid4()),
                device_id=device_id,
                metric_name=metric_name,
                created_at=now,
                updated_at=now,
            )
            self._baselines[key] = baseline

        baseline.samples.append(value)

        if len(baseline.samples) > self.maximum_samples:
            baseline.samples.pop(0)

        baseline.updated_at = now

        return baseline

    def get(
        self,
        device_id: str,
        metric_name: str,
    ) -> MetricBaseline | None:

        return self._baselines.get(
            (device_id, metric_name)
        )

    def compare(
        self,
        device_id: str,
        metric_name: str,
        current_value: float,
    ) -> BaselineComparison:

        current_value = self._validate_value(current_value)

        baseline = self.get(device_id, metric_name)

        if baseline is None:
            raise MonitoringBaselineError(
                "Baseline not found"
            )

        average = baseline.average
        deviation = current_value - average

        percentage = (
            (abs(deviation) / abs(average)) * 100
            if average != 0
            else None
        )

        if baseline.sample_count < self.minimum_samples:
            anomalous = False
            reason = "insufficient_baseline_samples"

        elif baseline.standard_deviation == 0:
            anomalous = current_value != average
            reason = (
                "value_differs_from_constant_baseline"
                if anomalous
                else "within_baseline"
            )

        else:
            z_score = abs(deviation) / baseline.standard_deviation
            anomalous = z_score >= self.deviation_threshold
            reason = (
                "statistical_deviation_detected"
                if anomalous
                else "within_baseline"
            )

        return BaselineComparison(
            baseline_id=baseline.baseline_id,
            device_id=device_id,
            metric_name=metric_name,
            current_value=current_value,
            baseline_average=average,
            deviation=deviation,
            deviation_percent=percentage,
            anomalous=anomalous,
            reason=reason,
        )

    def get_all(self) -> list[MetricBaseline]:
        return list(self._baselines.values())

    def delete(
        self,
        device_id: str,
        metric_name: str,
    ) -> bool:

        return self._baselines.pop(
            (device_id, metric_name),
            None,
        ) is not None

    def get_summary(self) -> dict[str, int]:
        baselines = list(self._baselines.values())

        return {
            "total_baselines": len(baselines),
            "total_samples": sum(
                item.sample_count for item in baselines
            ),
            "devices": len({
                item.device_id for item in baselines
            }),
        }


__all__ = [
    "MonitoringBaselineError",
    "MetricBaseline",
    "BaselineComparison",
    "MonitoringBaselineAnalyzer",
]
