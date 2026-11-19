
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Mapping


class CorrelationError(Exception):
    """Erro do módulo de correlação."""


@dataclass
class CorrelationGroup:
    correlation_key: str
    device_ids: list[str]
    event_ids: list[str]
    categories: list[str]
    severity: str
    explanation: str
    recommendations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "correlation_key": self.correlation_key,
            "device_ids": list(self.device_ids),
            "event_ids": list(self.event_ids),
            "categories": list(self.categories),
            "severity": self.severity,
            "explanation": self.explanation,
            "recommendations": list(self.recommendations),
        }


@dataclass
class CorrelationReport:
    total_events: int
    correlated_events: int
    total_groups: int
    groups: list[CorrelationGroup]

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_events": self.total_events,
            "correlated_events": self.correlated_events,
            "total_groups": self.total_groups,
            "groups": [group.to_dict() for group in self.groups],
        }


class CorrelationAnalyzer:
    """Correlaciona eventos com base em indicadores partilhados."""

    SEVERITY_ORDER = {
        "info": 0,
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4,
    }

    def analyze(
        self,
        events: list[Mapping[str, Any]],
    ) -> CorrelationReport:

        if not isinstance(events, list):
            raise CorrelationError("events must be a list")

        grouped: dict[str, list[dict[str, str]]] = defaultdict(list)
        seen_ids: set[str] = set()

        for index, event in enumerate(events):
            if not isinstance(event, Mapping):
                raise CorrelationError(
                    "Each event must be a mapping"
                )

            event_id = str(
                event.get("event_id", f"event-{index}")
            ).strip()

            device_id = str(
                event.get("device_id", "")
            ).strip()

            category = str(
                event.get("category", "general")
            ).strip().lower()

            indicator = str(
                event.get("indicator", "")
            ).strip().lower()

            severity = str(
                event.get("severity", "info")
            ).strip().lower()

            if not event_id:
                raise CorrelationError(
                    "event_id cannot be empty"
                )

            if event_id in seen_ids:
                raise CorrelationError(
                    f"Duplicate event_id: {event_id}"
                )

            if severity not in self.SEVERITY_ORDER:
                raise CorrelationError(
                    f"Invalid severity: {severity}"
                )

            seen_ids.add(event_id)

            # Só correlaciona eventos com indicadores partilhados.
            if not indicator:
                continue

            grouped[indicator].append({
                "event_id": event_id,
                "device_id": device_id,
                "category": category or "general",
                "severity": severity,
            })

        results = []

        for indicator, records in sorted(grouped.items()):
            if len(records) < 2:
                continue

            device_ids = sorted({
                record["device_id"]
                for record in records
                if record["device_id"]
            })

            event_ids = sorted({
                record["event_id"]
                for record in records
            })

            categories = sorted({
                record["category"]
                for record in records
            })

            highest_severity = max(
                records,
                key=lambda record: self.SEVERITY_ORDER[
                    record["severity"]
                ],
            )["severity"]

            recommendations = []

            if len(device_ids) > 1:
                recommendations.append(
                    "Review the shared indicator across the affected devices."
                )
            else:
                recommendations.append(
                    "Review the related events on the affected device."
                )

            if len(categories) > 1:
                recommendations.append(
                    "Investigate the relationship between the different event categories."
                )

            results.append(
                CorrelationGroup(
                    correlation_key=indicator,
                    device_ids=device_ids,
                    event_ids=event_ids,
                    categories=categories,
                    severity=highest_severity,
                    explanation=(
                        f"{len(event_ids)} events share the same indicator."
                    ),
                    recommendations=recommendations,
                )
            )

        correlated_ids = {
            event_id
            for group in results
            for event_id in group.event_ids
        }

        return CorrelationReport(
            total_events=len(events),
            correlated_events=len(correlated_ids),
            total_groups=len(results),
            groups=results,
        )


__all__ = [
    "CorrelationError",
    "CorrelationGroup",
    "CorrelationReport",
    "CorrelationAnalyzer",
]
