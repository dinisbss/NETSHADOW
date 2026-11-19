
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping


class SecurityIntelligenceError(Exception):
    """Erro do módulo Security Intelligence."""


SEVERITY_WEIGHTS = {
    "info": 0,
    "low": 5,
    "medium": 10,
    "high": 20,
    "critical": 30,
}


@dataclass
class SecurityIntelligenceReport:
    total_findings: int
    risk_score: int
    risk_level: str
    severity_summary: dict[str, int]
    repeated_indicators: list[str] = field(default_factory=list)
    priorities: list[dict[str, Any]] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_findings": self.total_findings,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "severity_summary": dict(self.severity_summary),
            "repeated_indicators": list(self.repeated_indicators),
            "priorities": list(self.priorities),
            "recommendations": list(self.recommendations),
        }


class SecurityIntelligenceAnalyzer:
    """Analisa findings já recolhidos por componentes autorizados."""

    def analyze(
        self,
        findings: list[Mapping[str, Any]],
    ) -> SecurityIntelligenceReport:

        if not isinstance(findings, list):
            raise SecurityIntelligenceError(
                "findings must be a list"
            )

        summary = {
            "info": 0,
            "low": 0,
            "medium": 0,
            "high": 0,
            "critical": 0,
        }

        indicators: dict[str, int] = {}
        priorities: list[dict[str, Any]] = []
        recommendations: list[str] = []

        risk_score = 0

        for finding in findings:
            if not isinstance(finding, Mapping):
                raise SecurityIntelligenceError(
                    "Each finding must be a mapping"
                )

            severity = str(
                finding.get("severity", "info")
            ).lower()

            if severity not in SEVERITY_WEIGHTS:
                raise SecurityIntelligenceError(
                    f"Invalid severity: {severity}"
                )

            indicator = str(
                finding.get("indicator", finding.get("code", "unknown"))
            ).strip()

            if not indicator:
                indicator = "unknown"

            summary[severity] += 1
            indicators[indicator] = indicators.get(indicator, 0) + 1

            risk_score += SEVERITY_WEIGHTS[severity]

            if severity in {"high", "critical"}:
                priorities.append({
                    "indicator": indicator,
                    "severity": severity,
                    "description": str(
                        finding.get("description", "")
                    ),
                })

        risk_score = min(risk_score, 100)

        if risk_score >= 70:
            risk_level = "critical"
        elif risk_score >= 40:
            risk_level = "high"
        elif risk_score >= 20:
            risk_level = "medium"
        elif risk_score > 0:
            risk_level = "low"
        else:
            risk_level = "informational"

        repeated = [
            indicator
            for indicator, count in indicators.items()
            if count > 1
        ]

        if summary["critical"]:
            recommendations.append(
                "Prioritize investigation of critical findings."
            )

        if summary["high"]:
            recommendations.append(
                "Review high-severity findings and apply appropriate mitigations."
            )

        if repeated:
            recommendations.append(
                "Investigate repeated indicators to identify common causes."
            )

        if not findings:
            recommendations.append(
                "No findings were provided; this does not prove the environment is secure."
            )

        return SecurityIntelligenceReport(
            total_findings=len(findings),
            risk_score=risk_score,
            risk_level=risk_level,
            severity_summary=summary,
            repeated_indicators=repeated,
            priorities=priorities,
            recommendations=recommendations,
        )


__all__ = [
    "SecurityIntelligenceError",
    "SecurityIntelligenceReport",
    "SecurityIntelligenceAnalyzer",
]
