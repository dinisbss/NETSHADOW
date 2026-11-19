
from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from statistics import mean, pstdev
from typing import Any, Mapping


class BaselineError(Exception):
    """Erro do módulo Baseline Engine."""


@dataclass
class MetricBaseline:
    metric_name: str
    sample_count: int
    minimum: float
    maximum: float
    average: float
    standard_deviation: float
    last_value: float
    updated_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "metric_name": self.metric_name,
            "sample_count": self.sample_count,
            "minimum": self.minimum,
            "maximum": self.maximum,
            "average": round(self.average, 4),
            "standard_deviation": round(
                self.standard_deviation, 4
            ),
            "last_value": self.last_value,
            "updated_at": self.updated_at,
        }


@dataclass
class BaselineComparison:
    metric_name: str
    current_value: float
    expected_value: float
    difference: float
    within_baseline: bool
    status: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "metric_name": self.metric_name,
            "current_value": self.current_value,
            "expected_value": round(
                self.expected_value, 4
            ),
            "difference": round(self.difference, 4),
            "within_baseline": self.within_baseline,
            "status": self.status,
        }


class BaselineAnalyzer:
    """Cria e compara referências estatísticas de métricas."""

    def __init__(self) -> None:
        self._samples: dict[str, list[float]] = {}
        self._baselines: dict[str, MetricBaseline] = {}

    @staticmethod
    def _validate_name(name: str) -> str:
        if not isinstance(name, str) or not name.strip():
            raise BaselineError(
                "metric_name must be a non-empty string"
            )

        return name.strip()

    @staticmethod
    def _validate_value(value: Any) -> float:
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
        ):
            raise BaselineError(
                "Metric values must be finite numbers"
            )

        return float(value)

    def record(
        self,
        metric_name: str,
        value: float,
    ) -> MetricBaseline:

        name = self._validate_name(metric_name)
        numeric_value = self._validate_value(value)

        samples = self._samples.setdefault(name, [])
        samples.append(numeric_value)

        return self._recalculate(name)

    def record_many(
        self,
        metrics: Mapping[str, Any],
    ) -> dict[str, MetricBaseline]:

        if not isinstance(metrics, Mapping):
            raise BaselineError(
                "metrics must be a mapping"
            )

        validated = {
            self._validate_name(name): self._validate_value(value)
            for name, value in metrics.items()
        }

        results = {}

        for name, value in validated.items():
            results[name] = self.record(name, value)

        return results

    def _recalculate(self, name: str) -> MetricBaseline:
        values = self._samples[name]

        baseline = MetricBaseline(
            metric_name=name,
            sample_count=len(values),
            minimum=min(values),
            maximum=max(values),
            average=mean(values),
            standard_deviation=(
                pstdev(values) if len(values) > 1 else 0.0
            ),
            last_value=values[-1],
            updated_at=datetime.now(
                timezone.utc
            ).isoformat(),
        )

        self._baselines[name] = baseline
        return baseline

    def get(self, metric_name: str) -> MetricBaseline | None:
        name = self._validate_name(metric_name)
        return self._baselines.get(name)

    def get_all(self) -> dict[str, MetricBaseline]:
        return dict(self._baselines)

    def compare(
        self,
        metric_name: str,
        current_value: float,
        tolerance: float = 2.0,
    ) -> BaselineComparison:

        name = self._validate_name(metric_name)
        current = self._validate_value(current_value)
        allowed_deviation = self._validate_value(tolerance)

        if allowed_deviation < 0:
            raise BaselineError(
                "tolerance cannot be negative"
            )

        baseline = self._baselines.get(name)

        if baseline is None:
            raise BaselineError(
                f"No baseline exists for metric: {name}"
            )

        difference = current - baseline.average

        if baseline.standard_deviation == 0:
            within = abs(difference) <= allowed_deviation
        else:
            within = (
                abs(difference)
                <= baseline.standard_deviation * allowed_deviation
            )

        status = "within_baseline" if within else "outside_baseline"

        return BaselineComparison(
            metric_name=name,
            current_value=current,
            expected_value=baseline.average,
            difference=difference,
            within_baseline=within,
            status=status,
        )

    def clear(self, metric_name: str | None = None) -> None:
        if metric_name is None:
            self._samples.clear()
            self._baselines.clear()
            return

        name = self._validate_name(metric_name)
        self._samples.pop(name, None)
        self._baselines.pop(name, None)

    def get_status(self) -> dict[str, Any]:
        return {
            "total_metrics": len(self._baselines),
            "total_samples": sum(
                len(values) for values in self._samples.values()
            ),
            "metrics": sorted(self._baselines),
        }


__all__ = [
    "BaselineError",
    "MetricBaseline",
    "BaselineComparison",
    "BaselineAnalyzer",
]
