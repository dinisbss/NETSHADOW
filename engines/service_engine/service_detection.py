
"""
NETSHADOW - Service Detection

Identificação passiva de serviços com base em metadados
e resultados fornecidos por componentes autorizados.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
from threading import RLock
from typing import Any, Optional


class ServiceDetectionError(ValueError):
    """Erro base da identificação de serviços."""


class ServiceProtocol(str, Enum):
    TCP = "tcp"
    UDP = "udp"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class ServiceInfo:
    name: str
    protocol: ServiceProtocol
    confidence: float
    evidence: str


@dataclass(frozen=True)
class ServiceDetectionResult:
    target: str
    port: int
    protocol: ServiceProtocol
    service: str
    version: Optional[str]
    confidence: float
    evidence: tuple[str, ...]
    timestamp: str

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["protocol"] = self.protocol.value
        result["evidence"] = list(self.evidence)
        return result


class ServiceDetector:
    """Identificador passivo de serviços de rede."""

    SERVICE_DATABASE = {
        (20, ServiceProtocol.TCP): "FTP-DATA",
        (21, ServiceProtocol.TCP): "FTP",
        (22, ServiceProtocol.TCP): "SSH",
        (23, ServiceProtocol.TCP): "TELNET",
        (25, ServiceProtocol.TCP): "SMTP",
        (53, ServiceProtocol.TCP): "DNS",
        (53, ServiceProtocol.UDP): "DNS",
        (80, ServiceProtocol.TCP): "HTTP",
        (110, ServiceProtocol.TCP): "POP3",
        (123, ServiceProtocol.UDP): "NTP",
        (143, ServiceProtocol.TCP): "IMAP",
        (161, ServiceProtocol.UDP): "SNMP",
        (443, ServiceProtocol.TCP): "HTTPS",
        (445, ServiceProtocol.TCP): "SMB",
        (3306, ServiceProtocol.TCP): "MYSQL",
        (5432, ServiceProtocol.TCP): "POSTGRESQL",
        (6379, ServiceProtocol.TCP): "REDIS",
        (8080, ServiceProtocol.TCP): "HTTP-ALT",
        (8443, ServiceProtocol.TCP): "HTTPS-ALT",
    }

    def __init__(self) -> None:
        self._results: list[ServiceDetectionResult] = []
        self._lock = RLock()

    @staticmethod
    def _validate_target(target: str) -> str:
        if not isinstance(target, str):
            raise ServiceDetectionError(
                "O destino tem de ser texto."
            )

        try:
            return str(ipaddress.ip_address(target.strip()))
        except ValueError as exc:
            raise ServiceDetectionError(
                "Endereço IP inválido."
            ) from exc

    @staticmethod
    def _validate_port(port: int) -> int:
        if isinstance(port, bool) or not isinstance(port, int):
            raise ServiceDetectionError(
                "A porta tem de ser um inteiro."
            )

        if not 1 <= port <= 65535:
            raise ServiceDetectionError(
                "A porta tem de estar entre 1 e 65535."
            )

        return port

    @staticmethod
    def _validate_text(
        value: Optional[str],
        field: str,
        max_length: int = 100,
    ) -> Optional[str]:
        if value is None:
            return None

        if not isinstance(value, str):
            raise ServiceDetectionError(
                f"{field} tem de ser texto."
            )

        value = value.strip()

        if not value:
            return None

        if len(value) > max_length:
            raise ServiceDetectionError(
                f"{field} excede o tamanho permitido."
            )

        if any(ord(char) < 32 for char in value):
            raise ServiceDetectionError(
                f"{field} contém caracteres inválidos."
            )

        return value

    @staticmethod
    def _validate_confidence(confidence: float) -> float:
        if isinstance(confidence, bool) or not isinstance(
            confidence, (int, float)
        ):
            raise ServiceDetectionError(
                "A confiança tem de ser numérica."
            )

        if not 0.0 <= confidence <= 1.0:
            raise ServiceDetectionError(
                "A confiança tem de estar entre 0 e 1."
            )

        return round(float(confidence), 2)

    def identify(
        self,
        target: str,
        port: int,
        protocol: ServiceProtocol | str,
        service_name: Optional[str] = None,
        version: Optional[str] = None,
        evidence: Optional[str] = None,
        confidence: Optional[float] = None,
    ) -> ServiceDetectionResult:
        """Identifica um serviço através de dados fornecidos."""

        target = self._validate_target(target)
        port = self._validate_port(port)

        try:
            protocol = ServiceProtocol(protocol)
        except ValueError as exc:
            raise ServiceDetectionError(
                "Protocolo inválido."
            ) from exc

        if protocol == ServiceProtocol.UNKNOWN:
            raise ServiceDetectionError(
                "É necessário indicar TCP ou UDP."
            )

        service_name = self._validate_text(
            service_name,
            "service_name",
        )

        version = self._validate_text(
            version,
            "version",
            max_length=80,
        )

        evidence = self._validate_text(
            evidence,
            "evidence",
            max_length=500,
        )

        indicators = []

        known_service = self.SERVICE_DATABASE.get(
            (port, protocol)
        )

        if service_name:
            service = service_name.upper()
            indicators.append("explicit_service_name")
            calculated_confidence = 0.95

            if known_service:
                if service == known_service:
                    indicators.append("port_matches_service")
                else:
                    indicators.append("port_service_mismatch")
                    calculated_confidence = 0.80

        elif known_service:
            service = known_service
            indicators.append("standard_port_mapping")
            calculated_confidence = 0.60

        else:
            service = "UNKNOWN"
            indicators.append("no_service_mapping")
            calculated_confidence = 0.10

        if version:
            indicators.append("version_provided")

        if evidence:
            indicators.append("external_evidence_provided")

        if confidence is None:
            confidence = calculated_confidence
        else:
            confidence = self._validate_confidence(confidence)

        result = ServiceDetectionResult(
            target=target,
            port=port,
            protocol=protocol,
            service=service,
            version=version,
            confidence=confidence,
            evidence=tuple(indicators),
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

        with self._lock:
            self._results.append(result)

        return result

    def get_results(
        self,
        target: Optional[str] = None,
        service: Optional[str] = None,
    ) -> list[ServiceDetectionResult]:
        with self._lock:
            results = list(self._results)

        if target is not None:
            target = self._validate_target(target)
            results = [
                item for item in results
                if item.target == target
            ]

        if service is not None:
            service = service.strip().upper()
            results = [
                item for item in results
                if item.service == service
            ]

        return results

    def get_summary(self) -> dict[str, Any]:
        with self._lock:
            results = list(self._results)

        services: dict[str, int] = {}

        for result in results:
            services[result.service] = (
                services.get(result.service, 0) + 1
            )

        return {
            "total": len(results),
            "services": services,
            "unique_targets": len({
                item.target for item in results
            }),
            "average_confidence": (
                round(
                    sum(item.confidence for item in results)
                    / len(results),
                    2,
                )
                if results else 0.0
            ),
        }

    def clear_results(self) -> None:
        with self._lock:
            self._results.clear()

    def get_status(self) -> dict[str, Any]:
        return {
            "available": True,
            "mode": "passive_metadata",
            "active_detection": False,
            "recorded_services": len(self._results),
        }


ServiceDetection = ServiceDetector
ServiceDetectionEngine = ServiceDetector

__all__ = [
    "ServiceDetectionError",
    "ServiceProtocol",
    "ServiceInfo",
    "ServiceDetectionResult",
    "ServiceDetector",
    "ServiceDetection",
    "ServiceDetectionEngine",
]
