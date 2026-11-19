
"""
NETSHADOW - Risk Analyzer

Classificação defensiva de riscos com base em findings existentes.
Não executa scans nem explora vulnerabilidades.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from threading import RLock
from typing import Any, Optional
from uuid import uuid4


class RiskAnalyzerError(ValueError):
    """Erro base do Risk Analyzer."""


class RiskLevel(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class RiskAssessment:
    assessment_id: str
    target: str
    score: int
    level: RiskLevel
    total_findings: int
    severity_counts: dict[str, int]
    recommendations: list[str]
    timestamp: str
    findings: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["level"] = self.level.value
        return result


class RiskAnalyzer:
    """Calcula níveis de risco a partir de findings existentes."""

    SEVERITY_WEIGHTS = {
        "info": 0,
        "low": 10,
        "medium": 25,
        "high": 50,
        "critical": 75,
    }

    LEVEL_THRESHOLDS = (
        (75, RiskLevel.CRITICAL),
        (50, RiskLevel.HIGH),
        (25, RiskLevel.MEDIUM),
        (1, RiskLevel.LOW),
        (0, RiskLevel.INFO),
    )

    def __init__(self) -> None:
        self._assessments: dict[str, RiskAssessment] = {}
        self._lock = RLock()

    @staticmethod
    def _validate_target(target: str) -> str:
        if not isinstance(target, str):
            raise RiskAnalyzerError("Destino inválido.")

        target = target.strip()

        if not target or len(target) > 253:
            raise RiskAnalyzerError("Destino inválido.")

        if any(ord(char) < 32 for char in target):
            raise RiskAnalyzerError(
                "Destino contém caracteres inválidos."
            )

        return target

    @staticmethod
    def _normalize_finding(
        finding: Any,
    ) -> dict[str, Any]:
        if hasattr(finding, "to_dict"):
            finding = finding.to_dict()
        elif hasattr(finding, "__dataclass_fields__"):
            finding = asdict(finding)

        if not isinstance(finding, dict):
            raise RiskAnalyzerError(
                "Cada finding tem de ser um dicionário ou objeto compatível."
            )

        severity = finding.get("severity")

        if isinstance(severity, Enum):
            severity = severity.value

        if not isinstance(severity, str):
            raise RiskAnalyzerError(
                "Finding sem gravidade válida."
            )

        severity = severity.lower().strip()

        if severity not in RiskAnalyzer.SEVERITY_WEIGHTS:
            raise RiskAnalyzerError(
                f"Gravidade desconhecida: {severity}"
            )

        return {
            **finding,
            "severity": severity,
        }

    @staticmethod
    def _calculate_score(findings: list[dict[str, Any]]) -> int:
        """
        Fórmula acumulativa limitada a 100.

        Cada finding contribui com um peso de acordo
        com a sua gravidade.
        """
        score = sum(
            RiskAnalyzer.SEVERITY_WEIGHTS[
                finding["severity"]
            ]
            for finding in findings
        )

        return min(100, score)

    @staticmethod
    def _get_level(score: int) -> RiskLevel:
        for threshold, level in RiskAnalyzer.LEVEL_THRESHOLDS:
            if score >= threshold:
                return level

        return RiskLevel.INFO

    @staticmethod
    def _count_severities(
        findings: list[dict[str, Any]],
    ) -> dict[str, int]:
        counts = {
            severity: 0
            for severity in RiskAnalyzer.SEVERITY_WEIGHTS
        }

        for finding in findings:
            counts[finding["severity"]] += 1

        return counts

    @staticmethod
    def _extract_recommendations(
        findings: list[dict[str, Any]],
    ) -> list[str]:
        recommendations = []

        for finding in findings:
            recommendation = finding.get("recommendation")

            if (
                isinstance(recommendation, str)
                and recommendation.strip()
                and recommendation not in recommendations
            ):
                recommendations.append(recommendation.strip())

        return recommendations

    def assess(
        self,
        target: str,
        findings: list[Any],
    ) -> RiskAssessment:
        """Calcula a classificação de risco de um destino."""

        target = self._validate_target(target)

        if not isinstance(findings, list):
            raise RiskAnalyzerError(
                "findings tem de ser uma lista."
            )

        if len(findings) > 10000:
            raise RiskAnalyzerError(
                "Demasiados findings para uma avaliação."
            )

        normalized = [
            self._normalize_finding(finding)
            for finding in findings
        ]

        score = self._calculate_score(normalized)
        level = self._get_level(score)
        counts = self._count_severities(normalized)
        recommendations = self._extract_recommendations(normalized)

        assessment = RiskAssessment(
            assessment_id=str(uuid4()),
            target=target,
            score=score,
            level=level,
            total_findings=len(normalized),
            severity_counts=counts,
            recommendations=recommendations,
            timestamp=datetime.now(timezone.utc).isoformat(),
            findings=normalized,
        )

        with self._lock:
            self._assessments[assessment.assessment_id] = assessment

        return assessment

    def get_assessment(
        self,
        assessment_id: str,
    ) -> Optional[RiskAssessment]:
        with self._lock:
            return self._assessments.get(assessment_id)

    def get_assessments(
        self,
        target: Optional[str] = None,
    ) -> list[RiskAssessment]:
        with self._lock:
            assessments = list(self._assessments.values())

        if target is not None:
            target = self._validate_target(target)
            assessments = [
                item
                for item in assessments
                if item.target == target
            ]

        return assessments

    def get_high_risk_assessments(self) -> list[RiskAssessment]:
        with self._lock:
            return [
                assessment
                for assessment in self._assessments.values()
                if assessment.level in {
                    RiskLevel.HIGH,
                    RiskLevel.CRITICAL,
                }
            ]

    def delete_assessment(self, assessment_id: str) -> bool:
        if not isinstance(assessment_id, str):
            raise RiskAnalyzerError(
                "assessment_id inválido."
            )

        with self._lock:
            return self._assessments.pop(
                assessment_id,
                None,
            ) is not None

    def clear(self) -> None:
        with self._lock:
            self._assessments.clear()

    def get_summary(self) -> dict[str, Any]:
        with self._lock:
            assessments = list(self._assessments.values())

        levels = {
            level.value: sum(
                item.level == level
                for item in assessments
            )
            for level in RiskLevel
        }

        average_score = (
            round(
                sum(item.score for item in assessments)
                / len(assessments),
                2,
            )
            if assessments else 0
        )

        return {
            "total_assessments": len(assessments),
            "risk_levels": levels,
            "average_score": average_score,
            "high_risk_count": (
                levels["high"] + levels["critical"]
            ),
        }

    def get_status(self) -> dict[str, Any]:
        with self._lock:
            total = len(self._assessments)

        return {
            "available": True,
            "mode": "metadata_risk_analysis",
            "assessments": total,
            "network_scanning": False,
        }


RiskAnalyzerEngine = RiskAnalyzer
RiskScoringEngine = RiskAnalyzer

__all__ = [
    "RiskAnalyzerError",
    "RiskLevel",
    "RiskAssessment",
    "RiskAnalyzer",
    "RiskAnalyzerEngine",
    "RiskScoringEngine",
]
