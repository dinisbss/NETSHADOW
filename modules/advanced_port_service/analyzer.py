
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping


class AdvancedPortServiceError(Exception):
    """Erro do módulo Advanced Port Service."""


SENSITIVE_SERVICES = {
    "telnet",
    "ftp",
    "rsh",
    "rlogin",
}


@dataclass
class PortServiceRecord:
    device_id: str
    port: int
    protocol: str
    state: str
    service: str
    version: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "device_id": self.device_id,
            "port": self.port,
            "protocol": self.protocol,
            "state": self.state,
            "service": self.service,
            "version": self.version,
        }


@dataclass
class PortServiceReport:
    total_records: int
    open_records: int
    sensitive_services: list[dict[str, Any]] = field(
        default_factory=list
    )
    records: list[PortServiceRecord] = field(
        default_factory=list
    )
    observations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_records": self.total_records,
            "open_records": self.open_records,
            "sensitive_services": self.sensitive_services,
            "records": [
                record.to_dict() for record in self.records
            ],
            "observations": list(self.observations),
        }


class AdvancedPortServiceAnalyzer:
    """Organiza resultados existentes de portas e serviços."""

    VALID_PROTOCOLS = {"tcp", "udp"}

    VALID_STATES = {
        "open",
        "closed",
        "filtered",
        "open|filtered",
        "closed|filtered",
        "unknown",
    }

    def analyze(
        self,
        results: list[Mapping[str, Any]],
    ) -> PortServiceReport:

        if not isinstance(results, list):
            raise AdvancedPortServiceError(
                "results must be a list"
            )

        records: list[PortServiceRecord] = []
        sensitive: list[dict[str, Any]] = []
        observations: list[str] = []

        for item in results:
            if not isinstance(item, Mapping):
                raise AdvancedPortServiceError(
                    "Each result must be a mapping"
                )

            device_id = str(item.get("device_id", "")).strip()
            protocol = str(item.get("protocol", "")).lower()
            state = str(item.get("state", "unknown")).lower()
            service = str(item.get("service", "unknown")).strip()
            version = item.get("version")
            port = item.get("port")

            if not device_id:
                raise AdvancedPortServiceError(
                    "device_id cannot be empty"
                )

            if protocol not in self.VALID_PROTOCOLS:
                raise AdvancedPortServiceError(
                    f"Unsupported protocol: {protocol}"
                )

            if state not in self.VALID_STATES:
                raise AdvancedPortServiceError(
                    f"Unsupported port state: {state}"
                )

            if (
                isinstance(port, bool)
                or not isinstance(port, int)
                or not 1 <= port <= 65535
            ):
                raise AdvancedPortServiceError(
                    "port must be between 1 and 65535"
                )

            if not service:
                service = "unknown"

            record = PortServiceRecord(
                device_id=device_id,
                port=port,
                protocol=protocol,
                state=state,
                service=service,
                version=str(version) if version is not None else None,
            )

            records.append(record)

            if state == "open" and service.lower() in SENSITIVE_SERVICES:
                sensitive.append(record.to_dict())

        open_records = sum(
            record.state == "open"
            for record in records
        )

        if not records:
            observations.append(
                "No port or service records were provided."
            )

        if sensitive:
            observations.append(
                "Potentially sensitive services were identified."
            )

        if open_records:
            observations.append(
                f"{open_records} open port records were provided."
            )

        return PortServiceReport(
            total_records=len(records),
            open_records=open_records,
            sensitive_services=sensitive,
            records=records,
            observations=observations,
        )


__all__ = [
    "AdvancedPortServiceError",
    "PortServiceRecord",
    "PortServiceReport",
    "AdvancedPortServiceAnalyzer",
]
