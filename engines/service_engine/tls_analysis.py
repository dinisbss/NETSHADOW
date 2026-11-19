
"""
NETSHADOW - TLS Analysis

Análise passiva de metadados TLS e certificados.
Não estabelece ligações a servidores.
"""

from __future__ import annotations

import ipaddress
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from threading import RLock
from typing import Any, Optional


class TLSAnalysisError(ValueError):
    """Erro base da análise TLS."""


class TLSRisk(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class TLSAnalysisResult:
    hostname: str
    tls_version: Optional[str]
    certificate_expiry: Optional[str]
    days_remaining: Optional[int]
    expired: Optional[bool]
    hostname_match: Optional[bool]
    self_signed: Optional[bool]
    risk: TLSRisk
    findings: tuple[str, ...]
    recommendations: tuple[str, ...]
    timestamp: str

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["risk"] = self.risk.value
        result["findings"] = list(self.findings)
        result["recommendations"] = list(
            self.recommendations
        )
        return result


class TLSAnalyzer:
    """Analisa metadados TLS fornecidos externamente."""

    SUPPORTED_VERSIONS = {
        "TLS 1.2",
        "TLS 1.3",
    }

    LEGACY_VERSIONS = {
        "TLS 1.0",
        "TLS 1.1",
        "SSL 2.0",
        "SSL 3.0",
    }

    def __init__(self, expiry_warning_days: int = 30) -> None:
        if (
            isinstance(expiry_warning_days, bool)
            or not isinstance(expiry_warning_days, int)
            or expiry_warning_days < 1
            or expiry_warning_days > 365
        ):
            raise TLSAnalysisError(
                "O intervalo de aviso deve estar entre 1 e 365 dias."
            )

        self.expiry_warning_days = expiry_warning_days
        self._results: list[TLSAnalysisResult] = []
        self._lock = RLock()

    @staticmethod
    def _validate_hostname(hostname: str) -> str:
        if not isinstance(hostname, str):
            raise TLSAnalysisError(
                "Hostname tem de ser texto."
            )

        hostname = hostname.strip().lower()

        if not hostname or len(hostname) > 253:
            raise TLSAnalysisError("Hostname inválido.")

        if any(char.isspace() for char in hostname):
            raise TLSAnalysisError("Hostname inválido.")

        return hostname

    @staticmethod
    def _parse_datetime(value: Optional[str]) -> Optional[datetime]:
        if value is None:
            return None

        if not isinstance(value, str):
            raise TLSAnalysisError(
                "A data de validade tem de ser texto ISO 8601."
            )

        try:
            parsed = datetime.fromisoformat(
                value.replace("Z", "+00:00")
            )
        except ValueError as exc:
            raise TLSAnalysisError(
                "Data de validade inválida."
            ) from exc

        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)

        return parsed.astimezone(timezone.utc)

    @staticmethod
    def _normalize_version(
        version: Optional[str],
    ) -> Optional[str]:
        if version is None:
            return None

        if not isinstance(version, str):
            raise TLSAnalysisError(
                "Versão TLS inválida."
            )

        version = version.strip().upper().replace("_", " ")

        if len(version) > 20:
            raise TLSAnalysisError(
                "Versão TLS demasiado longa."
            )

        return version

    def analyze(
        self,
        hostname: str,
        tls_version: Optional[str] = None,
        certificate_expiry: Optional[str] = None,
        hostname_match: Optional[bool] = None,
        self_signed: Optional[bool] = None,
    ) -> TLSAnalysisResult:
        """Analisa informações TLS previamente recolhidas."""

        hostname = self._validate_hostname(hostname)
        tls_version = self._normalize_version(tls_version)

        if hostname_match is not None and type(hostname_match) is not bool:
            raise TLSAnalysisError(
                "hostname_match tem de ser booleano."
            )

        if self_signed is not None and type(self_signed) is not bool:
            raise TLSAnalysisError(
                "self_signed tem de ser booleano."
            )

        expiry = self._parse_datetime(certificate_expiry)
        now = datetime.now(timezone.utc)

        days_remaining = None
        expired = None

        findings: list[str] = []
        recommendations: list[str] = []
        risk = TLSRisk.UNKNOWN

        if expiry is not None:
            difference = expiry - now
            days_remaining = difference.days
            expired = difference.total_seconds() < 0

            if expired:
                findings.append("certificate_expired")
                recommendations.append(
                    "Renovar o certificado digital."
                )
                risk = TLSRisk.CRITICAL

            elif days_remaining <= self.expiry_warning_days:
                findings.append("certificate_near_expiry")
                recommendations.append(
                    "Planear a renovação do certificado."
                )
                risk = TLSRisk.MEDIUM

            else:
                findings.append("certificate_valid")

        if tls_version is not None:
            if tls_version in self.LEGACY_VERSIONS:
                findings.append("legacy_tls_version")
                recommendations.append(
                    "Atualizar para TLS 1.2 ou TLS 1.3."
                )
                risk = TLSRisk.HIGH

            elif tls_version in self.SUPPORTED_VERSIONS:
                findings.append("supported_tls_version")

            else:
                findings.append("unrecognized_tls_version")
                recommendations.append(
                    "Confirmar a versão TLS através de uma fonte fiável."
                )

        if hostname_match is False:
            findings.append("hostname_mismatch")
            recommendations.append(
                "Verificar se o certificado corresponde ao hostname."
            )
            risk = TLSRisk.HIGH

        elif hostname_match is True:
            findings.append("hostname_match")

        if self_signed is True:
            findings.append("self_signed_certificate")
            recommendations.append(
                "Validar a origem e a confiança do certificado."
            )

            if risk not in {TLSRisk.CRITICAL, TLSRisk.HIGH}:
                risk = TLSRisk.MEDIUM

        elif self_signed is False:
            findings.append("not_self_signed")

        if not findings:
            findings.append("insufficient_tls_metadata")
            recommendations.append(
                "Recolher metadados TLS adicionais."
            )

        result = TLSAnalysisResult(
            hostname=hostname,
            tls_version=tls_version,
            certificate_expiry=(
                expiry.isoformat() if expiry else None
            ),
            days_remaining=days_remaining,
            expired=expired,
            hostname_match=hostname_match,
            self_signed=self_signed,
            risk=risk,
            findings=tuple(findings),
            recommendations=tuple(recommendations),
            timestamp=now.isoformat(),
        )

        with self._lock:
            self._results.append(result)

        return result

    def get_results(
        self,
        hostname: Optional[str] = None,
        risk: Optional[TLSRisk | str] = None,
    ) -> list[TLSAnalysisResult]:
        with self._lock:
            results = list(self._results)

        if hostname is not None:
            hostname = self._validate_hostname(hostname)
            results = [
                result for result in results
                if result.hostname == hostname
            ]

        if risk is not None:
            try:
                risk = TLSRisk(risk)
            except ValueError as exc:
                raise TLSAnalysisError(
                    "Nível de risco inválido."
                ) from exc

            results = [
                result for result in results
                if result.risk == risk
            ]

        return results

    def get_summary(self) -> dict[str, Any]:
        with self._lock:
            results = list(self._results)

        risks = {
            item.value: sum(
                result.risk == item for result in results
            )
            for item in TLSRisk
        }

        return {
            "total": len(results),
            "risks": risks,
            "expired_certificates": sum(
                result.expired is True for result in results
            ),
            "hostname_mismatches": sum(
                result.hostname_match is False
                for result in results
            ),
        }

    def clear_results(self) -> None:
        with self._lock:
            self._results.clear()

    def get_status(self) -> dict[str, Any]:
        return {
            "available": True,
            "mode": "passive_tls_analysis",
            "active_connections": False,
            "analyzed_certificates": len(self._results),
        }


TLSAnalysis = TLSAnalyzer
TLSAnalysisEngine = TLSAnalyzer

__all__ = [
    "TLSAnalysisError",
    "TLSRisk",
    "TLSAnalysisResult",
    "TLSAnalyzer",
    "TLSAnalysis",
    "TLSAnalysisEngine",
]
