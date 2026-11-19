
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping


class SecurityAnalystError(Exception):
    """Erro do AI Security Analyst."""


SEVERITY_PRIORITY = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

RECOMMENDATION_DATABASE = {
    "telnet": (
        "Review Telnet usage and consider an encrypted remote-access alternative."
    ),
    "ftp": (
        "Review FTP usage and consider an encrypted file-transfer alternative."
    ),
    "tls": (
        "Review TLS configuration, certificate validity and supported protocol versions."
    ),
    "dns": (
        "Review DNS configuration and investigate unexpected changes."
    ),
    "unknown": (
        "Collect additional evidence before assigning a definitive security classification."
    ),
}


@dataclass
class SecurityAnalysis:
    finding_id: str
    severity: str
    priority: str
    explanation: str
    recommendation: str
    confidence: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "severity": self.severity,
            "priority": self.priority,
            "explanation": self.explanation,
            "recommendation": self.recommendation,
            "confidence": self.confidence,
        }


@dataclass
class SecurityAnalystReport:
    total_findings: int
    critical_findings: int
    high_findings: int
    overall_priority: str
    executive_summary: str
    analyses: list[SecurityAnalysis] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_findings": self.total_findings,
            "critical_findings": self.critical_findings,
            "high_findings": self.high_findings,
            "overall_priority": self.overall_priority,
            "executive_summary": self.executive_summary,
            "analyses": [
                analysis.to_dict()
                for analysis in self.analyses
            ],
            "limitations": list(self.limitations),
        }


class AISecurityAnalyst:
    """Interpreta findings existentes sem executar operações na rede."""

    @staticmethod
    def _validate_confidence(value: Any) -> float:
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not 0 <= value <= 1
        ):
            raise SecurityAnalystError(
                "confidence must be between 0 and 1"
            )

        return float(value)

    @staticmethod
    def _recommend(category: str, title: str) -> str:
        text = f"{category} {title}".lower()

        for keyword, recommendation in RECOMMENDATION_DATABASE.items():
            if keyword in text:
                return recommendation

        return RECOMMENDATION_DATABASE["unknown"]

    def analyze(
        self,
        findings: list[Mapping[str, Any]],
    ) -> SecurityAnalystReport:

        if not isinstance(findings, list):
            raise SecurityAnalystError(
                "findings must be a list"
            )

        analyses = []
        seen_ids = set()

        for index, finding in enumerate(findings):
            if not isinstance(finding, Mapping):
                raise SecurityAnalystError(
                    "Each finding must be a mapping"
                )

            finding_id = str(
                finding.get("finding_id", f"finding-{index}")
            ).strip()

            severity = str(
                finding.get("severity", "info")
            ).strip().lower()

            category = str(
                finding.get("category", "unknown")
            ).strip().lower()

            title = str(
                finding.get("title", "Unspecified finding")
            ).strip()

            description = str(
                finding.get("description", "")
            ).strip()

            confidence = self._validate_confidence(
                finding.get("confidence", 0.5)
            )

            if not finding_id:
                raise SecurityAnalystError(
                    "finding_id cannot be empty"
                )

            if finding_id in seen_ids:
                continue

            if severity not in SEVERITY_PRIORITY:
                raise SecurityAnalystError(
                    f"Invalid severity: {severity}"
                )

            seen_ids.add(finding_id)

            priority = (
                "immediate"
                if severity == "critical"
                else "high"
                if severity == "high"
                else "normal"
            )

            explanation = (
                f"{title}. "
                f"Severity: {severity}. "
                f"Evidence: {description or 'No additional description provided.'}"
            )

            analyses.append(
                SecurityAnalysis(
                    finding_id=finding_id,
                    severity=severity,
                    priority=priority,
                    explanation=explanation,
                    recommendation=self._recommend(
                        category,
                        title,
                    ),
                    confidence=confidence,
                )
            )

        critical_count = sum(
            item.severity == "critical"
            for item in analyses
        )

        high_count = sum(
            item.severity == "high"
            for item in analyses
        )

        if critical_count:
            overall_priority = "immediate"
        elif high_count:
            overall_priority = "high"
        elif analyses:
            overall_priority = "normal"
        else:
            overall_priority = "none"

        summary = (
            f"Analysed {len(analyses)} unique findings. "
            f"Detected {critical_count} critical and "
            f"{high_count} high-severity findings. "
            f"Overall investigation priority: {overall_priority}."
        )

        limitations = [
            "Analysis is based exclusively on supplied metadata and findings.",
            "Recommendations require human review before implementation.",
            "A severity classification does not independently prove exploitation or compromise.",
            "This version does not use an external AI model.",
        ]

        return SecurityAnalystReport(
            total_findings=len(analyses),
            critical_findings=critical_count,
            high_findings=high_count,
            overall_priority=overall_priority,
            executive_summary=summary,
            analyses=analyses,
            limitations=limitations,
        )


__all__ = [
    "SecurityAnalystError",
    "SecurityAnalysis",
    "SecurityAnalystReport",
    "AISecurityAnalyst",
]
