
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping


class IntelligentReportsError(Exception):
    """Erro do módulo Intelligent Reports."""


SEVERITY_ORDER = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


@dataclass
class ReportFinding:
    finding_id: str
    title: str
    severity: str
    category: str
    description: str
    recommendation: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "severity": self.severity,
            "category": self.category,
            "description": self.description,
            "recommendation": self.recommendation,
        }


@dataclass
class IntelligentReport:
    report_id: str
    generated_at: str
    title: str
    risk_score: int
    risk_level: str
    total_findings: int
    severity_counts: dict[str, int]
    executive_summary: str
    priority_findings: list[ReportFinding]
    recommendations: list[str]
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "report_id": self.report_id,
            "generated_at": self.generated_at,
            "title": self.title,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "total_findings": self.total_findings,
            "severity_counts": dict(self.severity_counts),
            "executive_summary": self.executive_summary,
            "priority_findings": [
                finding.to_dict()
                for finding in self.priority_findings
            ],
            "recommendations": list(self.recommendations),
            "metadata": dict(self.metadata),
        }


class IntelligentReportAnalyzer:
    """Consolida resultados de análises já realizadas."""

    def analyze(
        self,
        findings: list[Mapping[str, Any]],
        risk_score: int | float | None = None,
        title: str = "NETSHADOW Security Report",
        metadata: Mapping[str, Any] | None = None,
    ) -> IntelligentReport:

        if not isinstance(findings, list):
            raise IntelligentReportsError(
                "findings must be a list"
            )

        if not isinstance(title, str) or not title.strip():
            raise IntelligentReportsError(
                "title must be a non-empty string"
            )

        if risk_score is not None:
            if (
                isinstance(risk_score, bool)
                or not isinstance(risk_score, (int, float))
                or not 0 <= risk_score <= 100
            ):
                raise IntelligentReportsError(
                    "risk_score must be between 0 and 100"
                )

            final_score = round(risk_score)
        else:
            final_score = None

        normalized_findings = []
        seen_ids = set()

        severity_counts = {
            severity: 0 for severity in SEVERITY_ORDER
        }

        for index, item in enumerate(findings):
            if not isinstance(item, Mapping):
                raise IntelligentReportsError(
                    "Each finding must be a mapping"
                )

            finding_id = str(
                item.get("finding_id", f"finding-{index}")
            ).strip()

            severity = str(
                item.get("severity", "info")
            ).strip().lower()

            if not finding_id:
                raise IntelligentReportsError(
                    "finding_id cannot be empty"
                )

            if finding_id in seen_ids:
                continue

            if severity not in SEVERITY_ORDER:
                raise IntelligentReportsError(
                    f"Invalid severity: {severity}"
                )

            seen_ids.add(finding_id)

            finding = ReportFinding(
                finding_id=finding_id,
                title=str(
                    item.get("title", "Untitled finding")
                ),
                severity=severity,
                category=str(
                    item.get("category", "general")
                ),
                description=str(
                    item.get("description", "")
                ),
                recommendation=str(
                    item.get("recommendation", "")
                ),
            )

            normalized_findings.append(finding)
            severity_counts[severity] += 1

        if final_score is None:
            weights = {
                "info": 0,
                "low": 5,
                "medium": 10,
                "high": 20,
                "critical": 30,
            }

            final_score = min(
                100,
                sum(
                    weights[finding.severity]
                    for finding in normalized_findings
                ),
            )

        if final_score >= 80:
            risk_level = "critical"
        elif final_score >= 60:
            risk_level = "high"
        elif final_score >= 35:
            risk_level = "medium"
        elif final_score > 0:
            risk_level = "low"
        else:
            risk_level = "informational"

        priority_findings = sorted(
            normalized_findings,
            key=lambda finding: (
                -SEVERITY_ORDER[finding.severity],
                finding.finding_id,
            ),
        )[:10]

        recommendations = []

        for finding in priority_findings:
            if finding.recommendation:
                if finding.recommendation not in recommendations:
                    recommendations.append(
                        finding.recommendation
                    )

        if not recommendations:
            recommendations.append(
                "Continue periodic security reviews and monitor network changes."
            )

        total = len(normalized_findings)

        executive_summary = (
            f"The analysis identified {total} unique findings. "
            f"The calculated risk score is {final_score}/100, "
            f"with an overall classification of {risk_level}."
        )

        safe_metadata = dict(metadata or {})

        return IntelligentReport(
            report_id=f"NS-REPORT-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')}",
            generated_at=datetime.now(
                timezone.utc
            ).isoformat(),
            title=title.strip(),
            risk_score=final_score,
            risk_level=risk_level,
            total_findings=total,
            severity_counts=severity_counts,
            executive_summary=executive_summary,
            priority_findings=priority_findings,
            recommendations=recommendations,
            metadata=safe_metadata,
        )


__all__ = [
    "IntelligentReportsError",
    "ReportFinding",
    "IntelligentReport",
    "IntelligentReportAnalyzer",
]
