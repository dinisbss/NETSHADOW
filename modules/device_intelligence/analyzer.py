
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping


class DeviceIntelligenceError(Exception):
    """Erro do módulo Device Intelligence."""


@dataclass
class DeviceIntelligenceProfile:
    device_id: str
    hostname: str | None
    ip_address: str | None
    vendor: str | None
    device_type: str
    operating_system: str | None
    services: list[str] = field(default_factory=list)
    protocols: list[str] = field(default_factory=list)
    confidence: float = 0.0
    observations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "device_id": self.device_id,
            "hostname": self.hostname,
            "ip_address": self.ip_address,
            "vendor": self.vendor,
            "device_type": self.device_type,
            "operating_system": self.operating_system,
            "services": list(self.services),
            "protocols": list(self.protocols),
            "confidence": self.confidence,
            "observations": list(self.observations),
        }


class DeviceIntelligenceAnalyzer:
    """Constrói perfis a partir de metadados já conhecidos."""

    def analyze(
        self,
        devices: list[Mapping[str, Any]],
    ) -> list[DeviceIntelligenceProfile]:

        if not isinstance(devices, list):
            raise DeviceIntelligenceError(
                "devices must be a list"
            )

        profiles = []

        for device in devices:
            if not isinstance(device, Mapping):
                raise DeviceIntelligenceError(
                    "Each device must be a mapping"
                )

            device_id = str(
                device.get("device_id", "")
            ).strip()

            if not device_id:
                raise DeviceIntelligenceError(
                    "device_id cannot be empty"
                )

            hostname = self._optional_text(
                device.get("hostname")
            )
            ip_address = self._optional_text(
                device.get("ip_address")
            )
            vendor = self._optional_text(
                device.get("vendor")
            )
            operating_system = self._optional_text(
                device.get("operating_system")
            )

            device_type = str(
                device.get("device_type", "unknown")
            ).strip().lower() or "unknown"

            services = self._string_list(
                device.get("services", [])
            )
            protocols = self._string_list(
                device.get("protocols", [])
            )

            observations = []

            fields_present = sum([
                hostname is not None,
                ip_address is not None,
                vendor is not None,
                operating_system is not None,
                device_type != "unknown",
                bool(services),
                bool(protocols),
            ])

            confidence = round(
                fields_present / 7,
                2,
            )

            if hostname is None:
                observations.append(
                    "Hostname information is missing."
                )

            if vendor is None:
                observations.append(
                    "Vendor information is unavailable."
                )

            if operating_system is None:
                observations.append(
                    "Operating system is not identified."
                )

            if confidence < 0.4:
                observations.append(
                    "Device profile has limited information."
                )

            profiles.append(
                DeviceIntelligenceProfile(
                    device_id=device_id,
                    hostname=hostname,
                    ip_address=ip_address,
                    vendor=vendor,
                    device_type=device_type,
                    operating_system=operating_system,
                    services=services,
                    protocols=protocols,
                    confidence=confidence,
                    observations=observations,
                )
            )

        return profiles

    @staticmethod
    def _optional_text(value: Any) -> str | None:
        if value is None:
            return None

        result = str(value).strip()
        return result or None

    @staticmethod
    def _string_list(value: Any) -> list[str]:
        if not isinstance(value, (list, tuple, set)):
            raise DeviceIntelligenceError(
                "Services and protocols must be collections"
            )

        return sorted({
            str(item).strip()
            for item in value
            if str(item).strip()
        })


__all__ = [
    "DeviceIntelligenceError",
    "DeviceIntelligenceProfile",
    "DeviceIntelligenceAnalyzer",
]
