
from __future__ import annotations

import math
from dataclasses import dataclass, field
from statistics import mean, pstdev
from typing import Any, Mapping


class AnomalyDetectionError(Exception):
    """Erro do módulo Anomaly Detection."""


@dataclass
class Anomaly:
    metric_name: str
    current_value: float
    expected_value: float
    deviation: float
    severity: str
    explanation: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "metric_name": self.metric_name,
            "current_value": self.current_value,
            "expected_value": round(self.expected_value, 4),
            "deviation": round(self.deviation, 4),
            "severity": self.severity,
            "explanation": self.explanation,
        }


@dataclass
class AnomalyReport:
    total_metrics: int
    anomalies_detected: int
    status: str
    anomalies: list[Anomaly] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_metrics": self.total_metrics,
            "anomalies_detected": self.anomalies_detected,
            "status": self.status,
            "anomalies": [
                anomaly.to_dict()
                for anomaly in self.anomalies
            ],
        }


class AnomalyDetectionAnalyzer:
    """Compara métricas atuais com séries históricas."""

    def __init__(self, threshold: float = 2.0) -> None:
        if (
            isinstance(threshold, bool)
            or not isinstance(threshold, (int, float))
            or not math.isfinite(threshold)
            or threshold <= 0
        ):
            raise AnomalyDetectionError(
                "threshold must be a positive finite number"
            )

        self.threshold = float(threshold)

    @staticmethod
    def _validate_value(value: Any, name: str) -> float:
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
        ):
            raise AnomalyDetectionError(
                f"{name} must be a finite number"
            )

        return float(value)

    def analyze(
        self,
        current_metrics: Mapping[str, Any],
        historical_metrics: Mapping[str, list[float]],
    ) -> AnomalyReport:

        if not isinstance(current_metrics, Mapping):
            raise AnomalyDetectionError(
                "current_metrics must be a mapping"
            )

        if not isinstance(historical_metrics, Mapping):
            raise AnomalyDetectionError(
                "historical_metrics must be a mapping"
            )

        anomalies = []

        for name, raw_current in current_metrics.items():
            metric_name = str(name).strip()

            if not metric_name:
                raise AnomalyDetectionError(
                    "Metric names cannot be empty"
                )

            current = self._validate_value(
                raw_current,
                metric_name,
            )

            history = historical_metrics.get(name)

            if not isinstance(history, list) or len(history) < 2:
                continue

            values = [
                self._validate_value(value, metric_name)
                for value in history
            ]

            expected = mean(values)
            deviation = pstdev(values)

            if deviation == 0:
                if current == expected:
                    continue

                severity = "high"
                explanation = (
                    "The current value differs from a stable historical baseline."
                )

                normalized_deviation = abs(current - expected)

            else:
                normalized_deviation = abs(
                    current - expected
                ) / deviation

                if normalized_deviation < self.threshold:
                    continue

                if normalized_deviation >= self.threshold * 2:
                    severity = "critical"
                elif normalized_deviation >= self.threshold * 1.5:
                    severity = "high"
                else:
                    severity = "medium"

                explanation = (
                    "The current value deviates significantly from the historical average."
                )

            anomalies.append(
                Anomaly(
                    metric_name=metric_name,
                    current_value=current,
                    expected_value=expected,
                    deviation=normalized_deviation,
                    severity=severity,
                    explanation=explanation,
                )
            )

        status = (
            "anomalies_detected"
            if anomalies
            else "normal"
        )

        return AnomalyReport(
            total_metrics=len(current_metrics),
            anomalies_detected=len(anomalies),
            status=status,
            anomalies=anomalies,
        )


__all__ = [
    "AnomalyDetectionError",
    "Anomaly",
    "AnomalyReport",
    "AnomalyDetectionAnalyzer",
]
