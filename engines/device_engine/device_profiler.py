
"""
NETSHADOW - Device Profiler

Criação e gestão de perfis estruturados de dispositivos.
Utiliza exclusivamente metadados fornecidos por outros componentes.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from threading import RLock
from typing import Any, Optional


class DeviceProfilerError(ValueError):
    """Erro base do Device Profiler."""


@dataclass
class DeviceProfile:
    device_id: str
    ip_address: str
    hostname: Optional[str] = None
    mac_address: Optional[str] = None
    vendor: Optional[str] = None
    device_type: str = "unknown"
    operating_system: Optional[str] = None
    services: list[str] = field(default_factory=list)
    protocols: list[str] = field(default_factory=list)
    confidence: float = 0.0
    first_seen: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    last_updated: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class DeviceProfiler:
    """Gere perfis de dispositivos identificados."""

    def __init__(self) -> None:
        self._profiles: dict[str, DeviceProfile] = {}
        self._lock = RLock()

    @staticmethod
    def _validate_text(
        value: Optional[str],
        field_name: str,
        max_length: int = 253,
    ) -> Optional[str]:
        if value is None:
            return None

        if not isinstance(value, str):
            raise DeviceProfilerError(
                f"{field_name} tem de ser texto."
            )

        value = value.strip()

        if not value:
            return None

        if len(value) > max_length:
            raise DeviceProfilerError(
                f"{field_name} excede o tamanho permitido."
            )

        if any(ord(char) < 32 for char in value):
            raise DeviceProfilerError(
                f"{field_name} contém caracteres inválidos."
            )

        return value

    @staticmethod
    def _validate_ip(ip_address: str) -> str:
        if not isinstance(ip_address, str):
            raise DeviceProfilerError(
                "O endereço IP tem de ser texto."
            )

        try:
            return str(ipaddress.ip_address(ip_address.strip()))
        except ValueError as exc:
            raise DeviceProfilerError(
                "Endereço IP inválido."
            ) from exc

    @staticmethod
    def _validate_mac(mac_address: Optional[str]) -> Optional[str]:
        if mac_address is None:
            return None

        if not isinstance(mac_address, str):
            raise DeviceProfilerError(
                "O endereço MAC tem de ser texto."
            )

        normalized = mac_address.strip().replace("-", ":").upper()

        if not re.fullmatch(
            r"(?:[0-9A-F]{2}:){5}[0-9A-F]{2}",
            normalized,
        ):
            raise DeviceProfilerError(
                "Endereço MAC inválido."
            )

        return normalized

    @staticmethod
    def _validate_confidence(confidence: float) -> float:
        if isinstance(confidence, bool) or not isinstance(
            confidence, (int, float)
        ):
            raise DeviceProfilerError(
                "A confiança tem de ser numérica."
            )

        if not 0 <= confidence <= 1:
            raise DeviceProfilerError(
                "A confiança deve estar entre 0 e 1."
            )

        return round(float(confidence), 2)

    @staticmethod
    def _validate_list(
        values: Optional[list[str]],
        field_name: str,
    ) -> list[str]:
        if values is None:
            return []

        if not isinstance(values, list):
            raise DeviceProfilerError(
                f"{field_name} tem de ser uma lista."
            )

        if len(values) > 100:
            raise DeviceProfilerError(
                f"{field_name} excede o limite de elementos."
            )

        normalized = []

        for value in values:
            if not isinstance(value, str):
                raise DeviceProfilerError(
                    f"Elemento inválido em {field_name}."
                )

            value = value.strip()

            if not value or len(value) > 100:
                raise DeviceProfilerError(
                    f"Elemento inválido em {field_name}."
                )

            if any(ord(char) < 32 for char in value):
                raise DeviceProfilerError(
                    f"Caracteres inválidos em {field_name}."
                )

            if value not in normalized:
                normalized.append(value)

        return normalized

    def create_profile(
        self,
        ip_address: str,
        hostname: Optional[str] = None,
        mac_address: Optional[str] = None,
        vendor: Optional[str] = None,
        device_type: str = "unknown",
        operating_system: Optional[str] = None,
        services: Optional[list[str]] = None,
        protocols: Optional[list[str]] = None,
        confidence: float = 0.0,
        metadata: Optional[dict[str, Any]] = None,
    ) -> DeviceProfile:
        """Cria um perfil de dispositivo."""

        ip_address = self._validate_ip(ip_address)

        hostname = self._validate_text(hostname, "hostname")
        mac_address = self._validate_mac(mac_address)
        vendor = self._validate_text(vendor, "vendor", 100)

        device_type = self._validate_text(
            device_type,
            "device_type",
            50,
        ) or "unknown"

        operating_system = self._validate_text(
            operating_system,
            "operating_system",
            100,
        )

        confidence = self._validate_confidence(confidence)

        services = self._validate_list(services, "services")
        protocols = self._validate_list(protocols, "protocols")

        if metadata is not None and not isinstance(metadata, dict):
            raise DeviceProfilerError(
                "metadata tem de ser um dicionário."
            )

        metadata = dict(metadata or {})

        if len(metadata) > 100:
            raise DeviceProfilerError(
                "Demasiados campos de metadados."
            )

        with self._lock:
            existing = self._profiles.get(ip_address)

            now = datetime.now(timezone.utc).isoformat()

            if existing:
                existing.hostname = hostname or existing.hostname
                existing.mac_address = mac_address or existing.mac_address
                existing.vendor = vendor or existing.vendor

                if device_type != "unknown":
                    existing.device_type = device_type

                existing.operating_system = (
                    operating_system or existing.operating_system
                )

                existing.services = list(
                    dict.fromkeys(existing.services + services)
                )

                existing.protocols = list(
                    dict.fromkeys(existing.protocols + protocols)
                )

                existing.confidence = max(
                    existing.confidence,
                    confidence,
                )

                existing.metadata.update(metadata)
                existing.last_updated = now

                return existing

            profile = DeviceProfile(
                device_id=ip_address,
                ip_address=ip_address,
                hostname=hostname,
                mac_address=mac_address,
                vendor=vendor,
                device_type=device_type,
                operating_system=operating_system,
                services=services,
                protocols=protocols,
                confidence=confidence,
                metadata=metadata,
            )

            self._profiles[ip_address] = profile
            return profile

    def get_profile(self, ip_address: str) -> Optional[DeviceProfile]:
        ip_address = self._validate_ip(ip_address)

        with self._lock:
            return self._profiles.get(ip_address)

    def get_all_profiles(self) -> list[DeviceProfile]:
        with self._lock:
            return list(self._profiles.values())

    def get_profiles_by_type(
        self,
        device_type: str,
    ) -> list[DeviceProfile]:
        device_type = self._validate_text(
            device_type,
            "device_type",
            50,
        )

        with self._lock:
            return [
                profile
                for profile in self._profiles.values()
                if profile.device_type == device_type
            ]

    def delete_profile(self, ip_address: str) -> bool:
        ip_address = self._validate_ip(ip_address)

        with self._lock:
            return self._profiles.pop(ip_address, None) is not None

    def get_summary(self) -> dict[str, Any]:
        with self._lock:
            profiles = list(self._profiles.values())

        types: dict[str, int] = {}

        for profile in profiles:
            types[profile.device_type] = (
                types.get(profile.device_type, 0) + 1
            )

        return {
            "total_devices": len(profiles),
            "device_types": types,
            "known_vendors": len({
                profile.vendor
                for profile in profiles
                if profile.vendor
            }),
            "average_confidence": (
                round(
                    sum(p.confidence for p in profiles)
                    / len(profiles),
                    2,
                )
                if profiles else 0.0
            ),
        }

    def clear_profiles(self) -> None:
        with self._lock:
            self._profiles.clear()

    def get_status(self) -> dict[str, Any]:
        with self._lock:
            total = len(self._profiles)

        return {
            "available": True,
            "mode": "passive_metadata",
            "active_fingerprinting": False,
            "profiles": total,
        }


DeviceProfileManager = DeviceProfiler
DeviceProfilerEngine = DeviceProfiler

__all__ = [
    "DeviceProfilerError",
    "DeviceProfile",
    "DeviceProfiler",
    "DeviceProfileManager",
    "DeviceProfilerEngine",
]
