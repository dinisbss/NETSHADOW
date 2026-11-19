
"""
NETSHADOW - Security Checks

Verificações defensivas baseadas em metadados fornecidos.
Não executa exploração nem testes intrusivos.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from threading import RLock
from typing import Any, Optional
import ipaddress


class SecurityCheckError(ValueError):
    """Erro base das verificações de segurança."""


class CheckSeverity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class SecurityFinding:
    finding_id: str
    check_id: str
    title: str
    description: str
    severity: CheckSeverity
    target: str
    recommendation: str
    timestamp: str
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["severity"] = self.severity.value
        return result


@dataclass
class SecurityCheckResult:
    check_id: str
    target: str
    passed: bool
    findings: list[SecurityFinding]
    timestamp: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "target": self.target,
            "passed": self.passed,
            "findings": [
                finding.to_dict()
                for finding in self.findings
            ],
            "timestamp": self.timestamp,
        }


class SecurityChecks:
    """Executa verificações defensivas sobre metadados."""

    ALLOWED_TLS_VERSIONS = {
        "TLSv1.2",
        "TLSv1.3",
    }

    LEGACY_TLS_VERSIONS = {
        "TLSv1.0",
        "TLSv1.1",
        "SSLv2",
        "SSLv3",
    }

    SENSITIVE_SERVICES = {
        "telnet": (
            CheckSeverity.HIGH,
            "Considera substituir Telnet por uma alternativa cifrada."
        ),
        "ftp": (
            CheckSeverity.MEDIUM,
            "Considera utilizar uma alternativa com transferência cifrada."
        ),
        "rsh": (
            CheckSeverity.HIGH,
            "Desativa serviços remotos inseguros quando não forem necessários."
        ),
        "rlogin": (
            CheckSeverity.HIGH,
            "Desativa serviços remotos inseguros quando não forem necessários."
        ),
    }

    def __init__(self) -> None:
        self._findings: list[SecurityFinding] = []
        self._lock = RLock()
        self._counter = 0

    @staticmethod
    def _validate_target(target: str) -> str:
        if not isinstance(target, str):
            raise SecurityCheckError(
                "O destino tem de ser texto."
            )

        target = target.strip()

        if not target or len(target) > 253:
            raise SecurityCheckError(
                "Destino inválido."
            )

        if any(ord(char) < 32 for char in target):
            raise SecurityCheckError(
                "Destino contém caracteres inválidos."
            )

        return target

    @staticmethod
    def _validate_mapping(
        data: dict[str, Any],
        field_name: str,
    ) -> dict[str, Any]:
        if not isinstance(data, dict):
            raise SecurityCheckError(
                f"{field_name} tem de ser um dicionário."
            )

        if len(data) > 200:
            raise SecurityCheckError(
                f"{field_name} excede o limite permitido."
            )

        return data

    def _create_finding(
        self,
        check_id: str,
        title: str,
        description: str,
        severity: CheckSeverity,
        target: str,
        recommendation: str,
        evidence: Optional[dict[str, Any]] = None,
    ) -> SecurityFinding:
        with self._lock:
            self._counter += 1
            finding_id = f"NS-FIND-{self._counter:06d}"

            finding = SecurityFinding(
                finding_id=finding_id,
                check_id=check_id,
                title=title,
                description=description,
                severity=severity,
                target=target,
                recommendation=recommendation,
                timestamp=datetime.now(timezone.utc).isoformat(),
                evidence=dict(evidence or {}),
            )

            self._findings.append(finding)

        return finding

    def check_device_metadata(
        self,
        target: str,
        metadata: dict[str, Any],
    ) -> SecurityCheckResult:
        """Verifica a consistência dos metadados de um dispositivo."""

        target = self._validate_target(target)
        metadata = self._validate_mapping(metadata, "metadata")

        findings = []

        ip_address = metadata.get("ip_address")

        if ip_address is not None:
            try:
                ipaddress.ip_address(str(ip_address))
            except ValueError:
                findings.append(
                    self._create_finding(
                        "DEVICE_INVALID_IP",
                        "Endereço IP inválido",
                        "O endereço IP fornecido não é válido.",
                        CheckSeverity.MEDIUM,
                        target,
                        "Confirma a origem e o formato do endereço IP.",
                        {"ip_address": str(ip_address)[:100]},
                    )
                )

        if not metadata.get("hostname"):
            findings.append(
                self._create_finding(
                    "DEVICE_NO_HOSTNAME",
                    "Hostname desconhecido",
                    "Não existe um hostname associado ao dispositivo.",
                    CheckSeverity.INFO,
                    target,
                    "Obtém o hostname através de uma fonte autorizada.",
                )
            )

        if not metadata.get("operating_system"):
            findings.append(
                self._create_finding(
                    "DEVICE_NO_OS",
                    "Sistema operativo desconhecido",
                    "Não existem dados suficientes para identificar o sistema operativo.",
                    CheckSeverity.INFO,
                    target,
                    "Atualiza o inventário com informação verificada.",
                )
            )

        return SecurityCheckResult(
            check_id="DEVICE_METADATA",
            target=target,
            passed=not any(
                f.severity in {
                    CheckSeverity.HIGH,
                    CheckSeverity.CRITICAL,
                }
                for f in findings
            ),
            findings=findings,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

    def check_services(
        self,
        target: str,
        services: list[str],
    ) -> SecurityCheckResult:
        """Identifica serviços conhecidos que merecem revisão."""

        target = self._validate_target(target)

        if not isinstance(services, list) or len(services) > 200:
            raise SecurityCheckError(
                "Lista de serviços inválida."
            )

        findings = []

        for service in services:
            if not isinstance(service, str):
                raise SecurityCheckError(
                    "Nome de serviço inválido."
                )

            normalized = service.strip().lower()

            if not normalized:
                continue

            if normalized in self.SENSITIVE_SERVICES:
                severity, recommendation = (
                    self.SENSITIVE_SERVICES[normalized]
                )

                findings.append(
                    self._create_finding(
                        f"SERVICE_{normalized.upper()}",
                        f"Serviço potencialmente inseguro: {normalized}",
                        (
                            f"O serviço {normalized} merece revisão "
                            "devido às suas características de segurança."
                        ),
                        severity,
                        target,
                        recommendation,
                        {"service": normalized},
                    )
                )

        return SecurityCheckResult(
            check_id="SERVICE_REVIEW",
            target=target,
            passed=not findings,
            findings=findings,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

    def check_tls(
        self,
        target: str,
        tls_version: str,
        certificate_valid: Optional[bool] = None,
        hostname_valid: Optional[bool] = None,
    ) -> SecurityCheckResult:
        """Avalia metadados TLS fornecidos por outro componente."""

        target = self._validate_target(target)

        if not isinstance(tls_version, str):
            raise SecurityCheckError(
                "A versão TLS tem de ser texto."
            )

        tls_version = tls_version.strip()

        findings = []

        if tls_version in self.LEGACY_TLS_VERSIONS:
            findings.append(
                self._create_finding(
                    "TLS_LEGACY_VERSION",
                    "Versão TLS antiga",
                    f"A versão {tls_version} já não é recomendada.",
                    CheckSeverity.HIGH,
                    target,
                    "Configura TLS 1.2 ou TLS 1.3, conforme a compatibilidade.",
                    {"tls_version": tls_version},
                )
            )

        elif tls_version not in self.ALLOWED_TLS_VERSIONS:
            findings.append(
                self._create_finding(
                    "TLS_UNKNOWN_VERSION",
                    "Versão TLS não reconhecida",
                    "Não foi possível classificar a versão TLS fornecida.",
                    CheckSeverity.MEDIUM,
                    target,
                    "Confirma a versão TLS através de uma fonte fiável.",
                    {"tls_version": tls_version[:50]},
                )
            )

        if certificate_valid is False:
            findings.append(
                self._create_finding(
                    "TLS_INVALID_CERTIFICATE",
                    "Certificado TLS inválido",
                    "O certificado foi identificado como inválido.",
                    CheckSeverity.HIGH,
                    target,
                    "Verifica a cadeia de confiança e a validade do certificado.",
                )
            )

        if hostname_valid is False:
            findings.append(
                self._create_finding(
                    "TLS_HOSTNAME_MISMATCH",
                    "Incompatibilidade de hostname",
                    "O hostname não corresponde ao certificado apresentado.",
                    CheckSeverity.HIGH,
                    target,
                    "Confirma o hostname e o certificado utilizado.",
                )
            )

        return SecurityCheckResult(
            check_id="TLS_REVIEW",
            target=target,
            passed=not any(
                f.severity in {
                    CheckSeverity.HIGH,
                    CheckSeverity.CRITICAL,
                }
                for f in findings
            ),
            findings=findings,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

    def get_findings(
        self,
        severity: Optional[CheckSeverity] = None,
    ) -> list[SecurityFinding]:
        with self._lock:
            findings = list(self._findings)

        if severity is not None:
            findings = [
                finding
                for finding in findings
                if finding.severity == severity
            ]

        return findings

    def clear_findings(self) -> None:
        with self._lock:
            self._findings.clear()
            self._counter = 0

    def get_summary(self) -> dict[str, Any]:
        with self._lock:
            findings = list(self._findings)

        counts = {
            severity.value: sum(
                finding.severity == severity
                for finding in findings
            )
            for severity in CheckSeverity
        }

        return {
            "total_findings": len(findings),
            "severity_counts": counts,
        }

    def get_status(self) -> dict[str, Any]:
        with self._lock:
            total = len(self._findings)

        return {
            "available": True,
            "mode": "defensive_metadata_analysis",
            "network_scanning": False,
            "total_findings": total,
        }


SecurityCheckEngine = SecurityChecks
SecurityAnalyzer = SecurityChecks

__all__ = [
    "SecurityCheckError",
    "CheckSeverity",
    "SecurityFinding",
    "SecurityCheckResult",
    "SecurityChecks",
    "SecurityCheckEngine",
    "SecurityAnalyzer",
]
