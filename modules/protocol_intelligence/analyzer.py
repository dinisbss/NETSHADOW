
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping


class ProtocolIntelligenceError(Exception):
    """Erro do módulo Protocol Intelligence."""


PROTOCOL_CATEGORIES = {
    "http": "web",
    "https": "web",
    "dns": "infrastructure",
    "dhcp": "infrastructure",
    "ssh": "remote_access",
    "telnet": "remote_access",
    "ftp": "file_transfer",
    "sftp": "file_transfer",
    "smtp": "email",
    "imap": "email",
    "pop3": "email",
    "snmp": "management",
    "ntp": "infrastructure",
}

INSECURE_PROTOCOLS = {
    "telnet",
    "ftp",
    "http",
    "pop3",
    "imap",
}


@dataclass
class ProtocolRecord:
    device_id: str
    protocol: str
    category: str
    secure_transport: bool | None
    observations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "device_id": self.device_id,
            "protocol": self.protocol,
            "category": self.category,
            "secure_transport": self.secure_transport,
            "observations": list(self.observations),
        }


@dataclass
class ProtocolIntelligenceReport:
    total_records: int
    protocol_counts: dict[str, int]
    category_counts: dict[str, int]
    unknown_protocols: list[str]
    insecure_protocols: list[str]
    recommendations: list[str]
    records: list[ProtocolRecord]

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_records": self.total_records,
            "protocol_counts": dict(self.protocol_counts),
            "category_counts": dict(self.category_counts),
            "unknown_protocols": list(self.unknown_protocols),
            "insecure_protocols": list(self.insecure_protocols),
            "recommendations": list(self.recommendations),
            "records": [
                record.to_dict() for record in self.records
            ],
        }


class ProtocolIntelligenceAnalyzer:
    """Analisa metadados de protocolos já identificados."""

    def analyze(
        self,
        protocols: list[Mapping[str, Any]],
    ) -> ProtocolIntelligenceReport:

        if not isinstance(protocols, list):
            raise ProtocolIntelligenceError(
                "protocols must be a list"
            )

        records = []
        protocol_counts: dict[str, int] = {}
        category_counts: dict[str, int] = {}
        unknown_protocols: set[str] = set()
        insecure_protocols: set[str] = set()
        recommendations: list[str] = []

        for item in protocols:
            if not isinstance(item, Mapping):
                raise ProtocolIntelligenceError(
                    "Each protocol entry must be a mapping"
                )

            device_id = str(
                item.get("device_id", "")
            ).strip()

            protocol = str(
                item.get("protocol", "")
            ).strip().lower()

            if not device_id or not protocol:
                raise ProtocolIntelligenceError(
                    "device_id and protocol are required"
                )

            category = PROTOCOL_CATEGORIES.get(
                protocol,
                "unknown",
            )

            secure_transport = item.get("secure_transport")

            if secure_transport is not None and not isinstance(
                secure_transport, bool
            ):
                raise ProtocolIntelligenceError(
                    "secure_transport must be boolean or None"
                )

            observations = []

            if category == "unknown":
                unknown_protocols.add(protocol)
                observations.append(
                    "Protocol is not present in the local classification database."
                )

            if protocol in INSECURE_PROTOCOLS:
                if secure_transport is not True:
                    insecure_protocols.add(protocol)
                    observations.append(
                        "Protocol may expose information without encrypted transport."
                    )

            protocol_counts[protocol] = (
                protocol_counts.get(protocol, 0) + 1
            )

            category_counts[category] = (
                category_counts.get(category, 0) + 1
            )

            records.append(
                ProtocolRecord(
                    device_id=device_id,
                    protocol=protocol,
                    category=category,
                    secure_transport=secure_transport,
                    observations=observations,
                )
            )

        if insecure_protocols:
            recommendations.append(
                "Review identified legacy protocols and consider encrypted alternatives."
            )

        if unknown_protocols:
            recommendations.append(
                "Review unknown protocols before assigning a security classification."
            )

        return ProtocolIntelligenceReport(
            total_records=len(records),
            protocol_counts=protocol_counts,
            category_counts=category_counts,
            unknown_protocols=sorted(unknown_protocols),
            insecure_protocols=sorted(insecure_protocols),
            recommendations=recommendations,
            records=records,
        )


__all__ = [
    "ProtocolIntelligenceError",
    "ProtocolRecord",
    "ProtocolIntelligenceReport",
    "ProtocolIntelligenceAnalyzer",
]
