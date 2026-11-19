
"""
NETSHADOW - Device Detection

Classificação passiva de dispositivos com base em metadados.
Não realiza sondagens nem fingerprinting ativo.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any, Optional


class DeviceDetectionError(ValueError):
    """Erro base de identificação de dispositivos."""


class DeviceType(str, Enum):
    UNKNOWN = "unknown"
    COMPUTER = "computer"
    SERVER = "server"
    ROUTER = "router"
    PRINTER = "printer"
    MOBILE = "mobile"
    NETWORK_DEVICE = "network_device"
    VIRTUAL_MACHINE = "virtual_machine"
    IOT = "iot"


@dataclass(frozen=True)
class DeviceDetectionResult:
    """Resultado da classificação de um dispositivo."""

    ip_address: Optional[str]
    hostname: Optional[str]
    vendor: Optional[str]
    device_type: DeviceType
    confidence: float
    indicators: tuple[str, ...]
    source: str = "passive_metadata"

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["device_type"] = self.device_type.value
        result["indicators"] = list(self.indicators)
        return result


class DeviceDetector:
    """Classificador de dispositivos baseado em metadados."""

    _KEYWORDS = {
        DeviceType.ROUTER: (
            "router", "gateway", "firewall",
        ),
        DeviceType.PRINTER: (
            "printer", "print", "laserjet", "deskjet",
        ),
        DeviceType.SERVER: (
            "server", "srv", "nas",
        ),
        DeviceType.MOBILE: (
            "iphone", "android", "mobile", "tablet",
        ),
        DeviceType.VIRTUAL_MACHINE: (
            "virtual", "vmware", "virtualbox", "hyper-v",
        ),
        DeviceType.IOT: (
            "camera", "sensor", "smart", "iot",
        ),
        DeviceType.NETWORK_DEVICE: (
            "switch", "access-point", "accesspoint",
        ),
    }

    def __init__(self) -> None:
        self._results: list[DeviceDetectionResult] = []

    @staticmethod
    def _normalize_text(
        value: Optional[str],
        field_name: str,
    ) -> Optional[str]:
        if value is None:
            return None

        if not isinstance(value, str):
            raise DeviceDetectionError(
                f"{field_name} tem de ser texto."
            )

        value = value.strip()

        if not value:
            return None

        if len(value) > 253:
            raise DeviceDetectionError(
                f"{field_name} excede o tamanho permitido."
            )

        if any(ord(char) < 32 for char in value):
            raise DeviceDetectionError(
                f"{field_name} contém caracteres inválidos."
            )

        return value

    @staticmethod
    def _normalize_ip(
        value: Optional[str],
    ) -> Optional[str]:
        if value is None:
            return None

        try:
            return str(ipaddress.ip_address(value.strip()))
        except (ValueError, AttributeError) as exc:
            raise DeviceDetectionError(
                "Endereço IP inválido."
            ) from exc

    @staticmethod
    def _normalize_mac(
        value: Optional[str],
    ) -> Optional[str]:
        if value is None:
            return None

        normalized = value.strip().replace("-", ":").upper()

        if not re.fullmatch(
            r"(?:[0-9A-F]{2}:){5}[0-9A-F]{2}",
            normalized,
        ):
            raise DeviceDetectionError(
                "Endereço MAC inválido."
            )

        return normalized

    def detect(
        self,
        ip_address: Optional[str] = None,
        hostname: Optional[str] = None,
        vendor: Optional[str] = None,
        mac_address: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> DeviceDetectionResult:
        """Classifica um dispositivo através de metadados fornecidos."""

        ip_address = self._normalize_ip(ip_address)
        hostname = self._normalize_text(hostname, "hostname")
        vendor = self._normalize_text(vendor, "vendor")
        mac_address = self._normalize_mac(mac_address)

        if metadata is not None and not isinstance(metadata, dict):
            raise DeviceDetectionError(
                "metadata tem de ser um dicionário."
            )

        metadata = metadata or {}

        searchable = " ".join(
            str(value).casefold()
            for value in (
                hostname or "",
                vendor or "",
                metadata.get("device_type", ""),
                metadata.get("description", ""),
            )
            if value
        )

        detected_type = DeviceType.UNKNOWN
        indicators: list[str] = []
        confidence = 0.0

        for device_type, keywords in self._KEYWORDS.items():
            matched = [
                keyword
                for keyword in keywords
                if keyword in searchable
            ]

            if matched:
                detected_type = device_type
                indicators.extend(
                    f"keyword:{keyword}"
                    for keyword in matched
                )
                confidence = min(
                    0.65 + (0.1 * (len(matched) - 1)),
                    0.85,
                )
                break

        if detected_type == DeviceType.UNKNOWN:
            if hostname:
                detected_type = DeviceType.COMPUTER
                indicators.append("hostname_available")
                confidence = 0.35

        if vendor:
            indicators.append("vendor_available")
            confidence = min(confidence + 0.05, 0.90)

        if mac_address:
            indicators.append("mac_available")

        result = DeviceDetectionResult(
            ip_address=ip_address,
            hostname=hostname,
            vendor=vendor,
            device_type=detected_type,
            confidence=round(confidence, 2),
            indicators=tuple(indicators),
        )

        self._results.append(result)
        return result

    def get_results(self) -> list[DeviceDetectionResult]:
        return list(self._results)

    def clear_results(self) -> None:
        self._results.clear()

    def get_summary(self) -> dict[str, Any]:
        counts: dict[str, int] = {}

        for result in self._results:
            key = result.device_type.value
            counts[key] = counts.get(key, 0) + 1

        return {
            "total": len(self._results),
            "types": counts,
            "results": [
                result.to_dict()
                for result in self._results
            ],
        }

    def get_status(self) -> dict[str, Any]:
        return {
            "available": True,
            "mode": "passive_metadata",
            "active_fingerprinting": False,
            "classified_devices": len(self._results),
        }


# Compatibilidade com nomes alternativos.
DeviceDetection = DeviceDetector
DeviceDetectionEngine = DeviceDetector

__all__ = [
    "DeviceDetectionError",
    "DeviceType",
    "DeviceDetectionResult",
    "DeviceDetector",
    "DeviceDetection",
    "DeviceDetectionEngine",
]
