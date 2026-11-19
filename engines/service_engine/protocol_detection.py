
"""
NETSHADOW - Protocol Detection

Classificação passiva de protocolos de rede.
Utiliza metadados fornecidos por componentes autorizados.
Não captura nem transmite pacotes.
"""

from __future__ import annotations

import ipaddress
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
from threading import RLock
from typing import Any, Optional


class ProtocolDetectionError(ValueError):
    """Erro base da identificação de protocolos."""


class NetworkProtocol(str, Enum):
    HTTP = "http"
    HTTPS = "https"
    DNS = "dns"
    DHCP = "dhcp"
    SSH = "ssh"
    FTP = "ftp"
    SMTP = "smtp"
    POP3 = "pop3"
    IMAP = "imap"
    SNMP = "snmp"
    NTP = "ntp"
    SMB = "smb"
    MYSQL = "mysql"
    POSTGRESQL = "postgresql"
    REDIS = "redis"
    UNKNOWN = "unknown"


class TransportProtocol(str, Enum):
    TCP = "tcp"
    UDP = "udp"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class ProtocolDetectionResult:
    target: str
    port: int
    transport: TransportProtocol
    protocol: NetworkProtocol
    confidence: float
    evidence: tuple[str, ...]
    timestamp: str

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["transport"] = self.transport.value
        result["protocol"] = self.protocol.value
        result["evidence"] = list(self.evidence)
        return result


class ProtocolDetector:
    """Identificador passivo de protocolos."""

    PORT_DATABASE = {
        (80, TransportProtocol.TCP): NetworkProtocol.HTTP,
        (443, TransportProtocol.TCP): NetworkProtocol.HTTPS,
        (53, TransportProtocol.TCP): NetworkProtocol.DNS,
        (53, TransportProtocol.UDP): NetworkProtocol.DNS,
        (67, TransportProtocol.UDP): NetworkProtocol.DHCP,
        (68, TransportProtocol.UDP): NetworkProtocol.DHCP,
        (22, TransportProtocol.TCP): NetworkProtocol.SSH,
        (20, TransportProtocol.TCP): NetworkProtocol.FTP,
        (21, TransportProtocol.TCP): NetworkProtocol.FTP,
        (25, TransportProtocol.TCP): NetworkProtocol.SMTP,
        (110, TransportProtocol.TCP): NetworkProtocol.POP3,
        (143, TransportProtocol.TCP): NetworkProtocol.IMAP,
        (161, TransportProtocol.UDP): NetworkProtocol.SNMP,
        (123, TransportProtocol.UDP): NetworkProtocol.NTP,
        (445, TransportProtocol.TCP): NetworkProtocol.SMB,
        (3306, TransportProtocol.TCP): NetworkProtocol.MYSQL,
        (5432, TransportProtocol.TCP): NetworkProtocol.POSTGRESQL,
        (6379, TransportProtocol.TCP): NetworkProtocol.REDIS,
    }

    def __init__(self) -> None:
        self._results: list[ProtocolDetectionResult] = []
        self._lock = RLock()

    @staticmethod
    def validate_target(target: str) -> str:
        if not isinstance(target, str):
            raise ProtocolDetectionError(
                "O destino tem de ser texto."
            )

        try:
            return str(ipaddress.ip_address(target.strip()))
        except ValueError as exc:
            raise ProtocolDetectionError(
                "Endereço IP inválido."
            ) from exc

    @staticmethod
    def validate_port(port: int) -> int:
        if isinstance(port, bool) or not isinstance(port, int):
            raise ProtocolDetectionError(
                "A porta tem de ser um número inteiro."
            )

        if not 1 <= port <= 65535:
            raise ProtocolDetectionError(
                "Porta fora do intervalo permitido."
            )

        return port

    @staticmethod
    def validate_confidence(confidence: float) -> float:
        if isinstance(confidence, bool) or not isinstance(
            confidence, (int, float)
        ):
            raise ProtocolDetectionError(
                "A confiança tem de ser numérica."
            )

        if not 0 <= confidence <= 1:
            raise ProtocolDetectionError(
                "A confiança tem de estar entre 0 e 1."
            )

        return round(float(confidence), 2)

    def detect(
        self,
        target: str,
        port: int,
        transport: TransportProtocol | str,
        protocol_hint: Optional[NetworkProtocol | str] = None,
    ) -> ProtocolDetectionResult:
        """Classifica um protocolo através de metadados."""

        target = self.validate_target(target)
        port = self.validate_port(port)

        try:
            transport = TransportProtocol(transport)
        except ValueError as exc:
            raise ProtocolDetectionError(
                "Protocolo de transporte inválido."
            ) from exc

        if transport == TransportProtocol.UNKNOWN:
            raise ProtocolDetectionError(
                "É necessário indicar TCP ou UDP."
            )

        indicators: list[str] = []

        detected = self.PORT_DATABASE.get(
            (port, transport),
            NetworkProtocol.UNKNOWN,
        )

        if detected != NetworkProtocol.UNKNOWN:
            indicators.append("standard_port_mapping")
            confidence = 0.60
        else:
            confidence = 0.10
            indicators.append("unknown_port_mapping")

        if protocol_hint is not None:
            try:
                hint = NetworkProtocol(protocol_hint)
            except ValueError as exc:
                raise ProtocolDetectionError(
                    "Identificador de protocolo inválido."
                ) from exc

            if hint == NetworkProtocol.UNKNOWN:
                indicators.append("unknown_protocol_hint")
            elif detected == NetworkProtocol.UNKNOWN:
                detected = hint
                confidence = 0.75
                indicators.append("external_protocol_hint")
            elif hint == detected:
                confidence = 0.95
                indicators.append("port_and_hint_match")
            else:
                indicators.append("protocol_hint_mismatch")
                confidence = 0.30

        result = ProtocolDetectionResult(
            target=target,
            port=port,
            transport=transport,
            protocol=detected,
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
        protocol: Optional[NetworkProtocol | str] = None,
    ) -> list[ProtocolDetectionResult]:
        with self._lock:
            results = list(self._results)

        if target is not None:
            target = self.validate_target(target)
            results = [
                result for result in results
                if result.target == target
            ]

        if protocol is not None:
            try:
                protocol = NetworkProtocol(protocol)
            except ValueError as exc:
                raise ProtocolDetectionError(
                    "Protocolo inválido."
                ) from exc

            results = [
                result for result in results
                if result.protocol == protocol
            ]

        return results

    def get_summary(self) -> dict[str, Any]:
        with self._lock:
            results = list(self._results)

        counts = {
            protocol.value: sum(
                result.protocol == protocol
                for result in results
            )
            for protocol in NetworkProtocol
        }

        return {
            "total": len(results),
            "protocols": counts,
            "unique_targets": len({
                result.target for result in results
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
            "packet_capture": False,
            "recorded_results": len(self._results),
        }


ProtocolDetection = ProtocolDetector
ProtocolDetectionEngine = ProtocolDetector

__all__ = [
    "ProtocolDetectionError",
    "NetworkProtocol",
    "TransportProtocol",
    "ProtocolDetectionResult",
    "ProtocolDetector",
    "ProtocolDetection",
    "ProtocolDetectionEngine",
]
