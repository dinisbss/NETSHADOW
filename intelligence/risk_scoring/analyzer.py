
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping


class RiskScoringError(Exception):
    """Erro do motor Risk Scoring."""


SEVERITY_WEIGHTS = {
    "info": 0,
    "low": 10,
    "medium": 25,
    "high": 45,
    "critical": 60,
}


@dataclass
class RiskFactor:
    finding_id: str
    category: str
    severity: str
    confidence: float
    contribution: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "category": self.category,
            "severity": self.severity,
            "confidence": self.confidence,
            "contribution": round(self.contribution, 2),
        }


@dataclass
class RiskScoringReport:
    score: int
    level: str
    total_findings: int
    factors: list[RiskFactor] = field(default_factory=list)
    explanation: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "level": self.level,
            "total_findings": self.total_findings,
            "factors": [
                factor.to_dict() for factor in self.factors
            ],
            "explanation": list(self.explanation),
        }


class RiskScoringAnalyzer:
    """Calcula uma classificação heurística de risco."""

    def analyze(
        self,
        findings: list[Mapping[str, Any]],
    ) -> RiskScoringReport:

        if not isinstance(findings, list):
            raise RiskScoringError(
                "findings must be a list"
            )

        factors = []
        seen_ids = set()
        explanation = []
        total_score = 0.0

        for index, finding in enumerate(findings):
            if not isinstance(finding, Mapping):
                raise RiskScoringError(
                    "Each finding must be a mapping"
                )

            finding_id = str(
                finding.get("finding_id", f"finding-{index}")
            ).strip()

            if not finding_id:
                raise RiskScoringError(
                    "finding_id cannot be empty"
                )

            if finding_id in seen_ids:
                continue

            seen_ids.add(finding_id)

            severity = str(
                finding.get("severity", "info")
            ).lower()

            if severity not in SEVERITY_WEIGHTS:
                raise RiskScoringError(
                    f"Invalid severity: {severity}"
                )

            confidence = finding.get("confidence", 1.0)

            if (
                isinstance(confidence, bool)
                or not isinstance(confidence, (int, float))
                or not 0 <= confidence <= 1
            ):
                raise RiskScoringError(
                    "confidence must be between 0 and 1"
                )

            contribution = (
                SEVERITY_WEIGHTS[severity] * float(confidence)
            )

            total_score += contribution

            factors.append(
                RiskFactor(
                    finding_id=finding_id,
                    category=str(
                        finding.get("category", "general")
                    ),
                    severity=severity,
                    confidence=float(confidence),
                    contribution=contribution,
                )
            )

        score = min(100, round(total_score))

        if score >= 80:
            level = "critical"
        elif score >= 60:
            level = "high"
        elif score >= 35:
            level = "medium"
        elif score > 0:
            level = "low"
        else:
            level = "informational"

        if factors:
            explanation.append(
                f"{len(factors)} unique findings contributed to the score."
            )

        if len(seen_ids) < len(findings):
            explanation.append(
                "Duplicate finding IDs were ignored."
            )

        explanation.append(
            "The score is heuristic and should not be interpreted as a certified security rating."
        )

        return RiskScoringReport(
            score=score,
            level=level,
            total_findings=len(factors),
            factors=factors,
            explanation=explanation,
        )


__all__ = [
    "RiskScoringError",
    "RiskFactor",
    "RiskScoringReport",
    "RiskScoringAnalyzer",
]
