
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any, Mapping


class ThreatIntelligenceError(Exception):
    """Erro do módulo Threat Intelligence."""


IOC_TYPES = {
    "ip",
    "domain",
    "url",
    "hash",
    "email",
}

SEVERITIES = {
    "info",
    "low",
    "medium",
    "high",
    "critical",
}


@dataclass
class ThreatIndicator:
    indicator_id: str
    indicator_type: str
    value: str
    severity: str
    confidence: float
    source: str
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "indicator_id": self.indicator_id,
            "indicator_type": self.indicator_type,
            "value": self.value,
            "severity": self.severity,
            "confidence": self.confidence,
            "source": self.source,
            "tags": list(self.tags),
        }


@dataclass
class ThreatIntelligenceReport:
    total_indicators: int
    severity_counts: dict[str, int]
    type_counts: dict[str, int]
    recommendations: list[str]
    indicators: list[ThreatIndicator]

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_indicators": self.total_indicators,
            "severity_counts": dict(self.severity_counts),
            "type_counts": dict(self.type_counts),
            "recommendations": list(self.recommendations),
            "indicators": [
                indicator.to_dict()
                for indicator in self.indicators
            ],
        }


class ThreatIntelligenceAnalyzer:
    """Valida e classifica indicadores fornecidos à aplicação."""

    @staticmethod
    def _validate_value(
        indicator_type: str,
        value: str,
    ) -> str:

        value = value.strip()

        if not value:
            raise ThreatIntelligenceError(
                "Indicator value cannot be empty"
            )

        if indicator_type == "ip":
            try:
                return str(ipaddress.ip_address(value))
            except ValueError as exc:
                raise ThreatIntelligenceError(
                    "Invalid IP indicator"
                ) from exc

        if indicator_type == "domain":
            if (
                len(value) > 253
                or not re.fullmatch(
                    r"(?=.{1,253}$)(?:[A-Za-z0-9]"
                    r"(?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
                    r"[A-Za-z]{2,63}",
                    value,
                )
            ):
                raise ThreatIntelligenceError(
                    "Invalid domain indicator"
                )

            return value.lower()

        if indicator_type == "hash":
            if not re.fullmatch(
                r"(?:[a-fA-F0-9]{32}|"
                r"[a-fA-F0-9]{40}|"
                r"[a-fA-F0-9]{64}|"
                r"[a-fA-F0-9]{128})",
                value,
            ):
                raise ThreatIntelligenceError(
                    "Invalid hash indicator"
                )

            return value.lower()

        if indicator_type == "email":
            if not re.fullmatch(
                r"[^@\s]+@[^@\s]+\.[^@\s]+",
                value,
            ):
                raise ThreatIntelligenceError(
                    "Invalid email indicator"
                )

            return value.lower()

        if indicator_type == "url":
            if (
                not re.fullmatch(
                    r"https?://[^\s/$.?#].[^\s]*",
                    value,
                    re.IGNORECASE,
                )
                or any(char in value for char in "<>\"'")
            ):
                raise ThreatIntelligenceError(
                    "Invalid URL indicator"
                )

            return value

        raise ThreatIntelligenceError(
            f"Unsupported indicator type: {indicator_type}"
        )

    def analyze(
        self,
        indicators: list[Mapping[str, Any]],
    ) -> ThreatIntelligenceReport:

        if not isinstance(indicators, list):
            raise ThreatIntelligenceError(
                "indicators must be a list"
            )

        results = []
        seen = set()

        severity_counts = {
            severity: 0 for severity in SEVERITIES
        }

        type_counts = {
            indicator_type: 0 for indicator_type in IOC_TYPES
        }

        for index, item in enumerate(indicators):
            if not isinstance(item, Mapping):
                raise ThreatIntelligenceError(
                    "Each indicator must be a mapping"
                )

            indicator_id = str(
                item.get("indicator_id", f"ioc-{index}")
            ).strip()

            indicator_type = str(
                item.get("indicator_type", "")
            ).strip().lower()

            severity = str(
                item.get("severity", "medium")
            ).strip().lower()

            source = str(
                item.get("source", "unspecified")
            ).strip()

            confidence = item.get("confidence", 0.5)

            if not indicator_id:
                raise ThreatIntelligenceError(
                    "indicator_id cannot be empty"
                )

            if indicator_type not in IOC_TYPES:
                raise ThreatIntelligenceError(
                    f"Unsupported indicator type: {indicator_type}"
                )

            if severity not in SEVERITIES:
                raise ThreatIntelligenceError(
                    f"Invalid severity: {severity}"
                )

            if (
                isinstance(confidence, bool)
                or not isinstance(confidence, (int, float))
                or not 0 <= confidence <= 1
            ):
                raise ThreatIntelligenceError(
                    "confidence must be between 0 and 1"
                )

            value = self._validate_value(
                indicator_type,
                str(item.get("value", "")),
            )

            duplicate_key = (
                indicator_type,
                value.lower(),
            )

            if duplicate_key in seen:
                continue

            seen.add(duplicate_key)

            raw_tags = item.get("tags", [])

            if not isinstance(raw_tags, list):
                raise ThreatIntelligenceError(
                    "tags must be a list"
                )

            tags = sorted({
                str(tag).strip().lower()
                for tag in raw_tags
                if str(tag).strip()
            })

            indicator = ThreatIndicator(
                indicator_id=indicator_id,
                indicator_type=indicator_type,
                value=value,
                severity=severity,
                confidence=float(confidence),
                source=source,
                tags=tags,
            )

            results.append(indicator)
            severity_counts[severity] += 1
            type_counts[indicator_type] += 1

        recommendations = []

        if any(
            indicator.severity in {"high", "critical"}
            for indicator in results
        ):
            recommendations.append(
                "Prioritize the review of high and critical indicators."
            )

        if any(
            indicator.confidence < 0.5
            for indicator in results
        ):
            recommendations.append(
                "Validate low-confidence indicators against additional trusted sources."
            )

        if not recommendations:
            recommendations.append(
                "Continue monitoring indicators and review their source reliability."
            )

        return ThreatIntelligenceReport(
            total_indicators=len(results),
            severity_counts=severity_counts,
            type_counts=type_counts,
            recommendations=recommendations,
            indicators=results,
        )


__all__ = [
    "ThreatIntelligenceError",
    "ThreatIndicator",
    "ThreatIntelligenceReport",
    "ThreatIntelligenceAnalyzer",
]
