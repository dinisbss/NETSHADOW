
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping


class NetworkIntelligenceError(Exception):
    """Erro do módulo Network Intelligence."""


@dataclass
class NetworkIntelligenceReport:
    generated_at: str
    network_summary: dict[str, Any]
    device_count: int
    service_count: int
    finding_count: int
    risk_score: int
    observations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "network_summary": self.network_summary,
            "device_count": self.device_count,
            "service_count": self.service_count,
            "finding_count": self.finding_count,
            "risk_score": self.risk_score,
            "observations": list(self.observations),
        }


class NetworkIntelligenceAnalyzer:
    """Analisa dados já recolhidos pelos motores do NETSHADOW."""

    def analyze(
        self,
        network_data: Mapping[str, Any],
        devices: list[Mapping[str, Any]] | None = None,
        services: list[Mapping[str, Any]] | None = None,
        findings: list[Mapping[str, Any]] | None = None,
    ) -> NetworkIntelligenceReport:

        devices = devices or []
        services = services or []
        findings = findings or []

        if not isinstance(network_data, Mapping):
            raise NetworkIntelligenceError(
                "network_data must be a mapping"
            )

        observations: list[str] = []

        device_count = len(devices)
        service_count = len(services)
        finding_count = len(findings)

        severity_weights = {
            "info": 0,
            "low": 5,
            "medium": 10,
            "high": 20,
            "critical": 30,
        }

        risk_score = 0

        for finding in findings:
            severity = str(
                finding.get("severity", "info")
            ).lower()

            risk_score += severity_weights.get(severity, 0)

        risk_score = min(risk_score, 100)

        if device_count == 0:
            observations.append(
                "No devices have been registered."
            )

        if service_count == 0:
            observations.append(
                "No service information is available."
            )

        if finding_count == 0:
            observations.append(
                "No security findings were provided."
            )

        if risk_score >= 70:
            observations.append(
                "The collected findings indicate elevated risk."
            )
        elif risk_score >= 30:
            observations.append(
                "The collected findings indicate moderate risk."
            )
        else:
            observations.append(
                "The collected findings indicate a low calculated score."
            )

        return NetworkIntelligenceReport(
            generated_at=datetime.now(
                timezone.utc
            ).isoformat(),
            network_summary=dict(network_data),
            device_count=device_count,
            service_count=service_count,
            finding_count=finding_count,
            risk_score=risk_score,
            observations=observations,
        )


__all__ = [
    "NetworkIntelligenceError",
    "NetworkIntelligenceReport",
    "NetworkIntelligenceAnalyzer",
]
