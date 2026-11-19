
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping
from uuid import uuid4


class DeviceProfileError(Exception):
    """Erro do módulo Device Profiles."""


@dataclass
class DeviceProfile:
    profile_id: str
    device_id: str
    ip_address: str
    mac_address: str | None
    hostname: str | None
    vendor: str | None
    operating_system: str | None
    device_type: str
    services: list[str]
    created_at: str
    updated_at: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "profile_id": self.profile_id,
            "device_id": self.device_id,
            "ip_address": self.ip_address,
            "mac_address": self.mac_address,
            "hostname": self.hostname,
            "vendor": self.vendor,
            "operating_system": self.operating_system,
            "device_type": self.device_type,
            "services": list(self.services),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "metadata": dict(self.metadata),
        }


@dataclass
class DeviceProfileChange:
    profile_id: str
    device_id: str
    changed_fields: list[str]
    detected_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "profile_id": self.profile_id,
            "device_id": self.device_id,
            "changed_fields": list(self.changed_fields),
            "detected_at": self.detected_at,
        }


class DeviceProfileAnalyzer:
    """Gere perfis e compara metadados de dispositivos."""

    def __init__(self) -> None:
        self._profiles: dict[str, DeviceProfile] = {}
        self._history: dict[str, list[DeviceProfileChange]] = {}

    @staticmethod
    def _validate_ip(value: str) -> str:
        try:
            return str(ipaddress.ip_address(value))
        except (ValueError, TypeError) as exc:
            raise DeviceProfileError(
                "Invalid IP address"
            ) from exc

    @staticmethod
    def _validate_mac(value: str | None) -> str | None:
        if value is None:
            return None

        if not isinstance(value, str):
            raise DeviceProfileError("Invalid MAC address")

        normalized = value.strip().lower().replace("-", ":")

        if not re.fullmatch(
            r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}",
            normalized,
        ):
            raise DeviceProfileError("Invalid MAC address")

        return normalized

    @staticmethod
    def _optional_text(
        value: Any,
        field_name: str,
    ) -> str | None:
        if value is None:
            return None

        if not isinstance(value, str):
            raise DeviceProfileError(
                f"{field_name} must be a string"
            )

        value = value.strip()
        return value or None

    def create(
        self,
        device_id: str,
        ip_address: str,
        mac_address: str | None = None,
        hostname: str | None = None,
        vendor: str | None = None,
        operating_system: str | None = None,
        device_type: str = "unknown",
        services: list[str] | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> DeviceProfile:

        if not isinstance(device_id, str) or not device_id.strip():
            raise DeviceProfileError("device_id is required")

        normalized_ip = self._validate_ip(ip_address)
        normalized_mac = self._validate_mac(mac_address)

        normalized_services = sorted({
            service.strip().lower()
            for service in (services or [])
            if isinstance(service, str) and service.strip()
        })

        now = datetime.now(timezone.utc).isoformat()

        profile = DeviceProfile(
            profile_id=str(uuid4()),
            device_id=device_id.strip(),
            ip_address=normalized_ip,
            mac_address=normalized_mac,
            hostname=self._optional_text(hostname, "hostname"),
            vendor=self._optional_text(vendor, "vendor"),
            operating_system=self._optional_text(
                operating_system,
                "operating_system",
            ),
            device_type=str(device_type).strip().lower() or "unknown",
            services=normalized_services,
            created_at=now,
            updated_at=now,
            metadata=dict(metadata or {}),
        )

        if profile.device_id in self._profiles:
            raise DeviceProfileError(
                "A profile already exists for this device"
            )

        self._profiles[profile.device_id] = profile
        self._history[profile.device_id] = []

        return profile

    def get(self, device_id: str) -> DeviceProfile | None:
        return self._profiles.get(device_id)

    def get_all(self) -> list[DeviceProfile]:
        return list(self._profiles.values())

    def update(
        self,
        device_id: str,
        **changes: Any,
    ) -> DeviceProfile:

        profile = self.get(device_id)

        if profile is None:
            raise DeviceProfileError("Device profile not found")

        allowed = {
            "ip_address",
            "mac_address",
            "hostname",
            "vendor",
            "operating_system",
            "device_type",
            "services",
            "metadata",
        }

        unknown = set(changes) - allowed

        if unknown:
            raise DeviceProfileError(
                f"Unsupported fields: {sorted(unknown)}"
            )

        before = profile.to_dict()
        updated = dict(before)
        updated.update(changes)

        candidate = DeviceProfile(
            profile_id=profile.profile_id,
            device_id=profile.device_id,
            ip_address=self._validate_ip(updated["ip_address"]),
            mac_address=self._validate_mac(updated["mac_address"]),
            hostname=self._optional_text(updated["hostname"], "hostname"),
            vendor=self._optional_text(updated["vendor"], "vendor"),
            operating_system=self._optional_text(
                updated["operating_system"],
                "operating_system",
            ),
            device_type=str(updated["device_type"]).strip().lower(),
            services=sorted({
                service.strip().lower()
                for service in updated["services"]
                if isinstance(service, str) and service.strip()
            }),
            created_at=profile.created_at,
            updated_at=datetime.now(timezone.utc).isoformat(),
            metadata=dict(updated["metadata"]),
        )

        fields = [
            "ip_address",
            "mac_address",
            "hostname",
            "vendor",
            "operating_system",
            "device_type",
            "services",
            "metadata",
        ]

        changed = [
            name for name in fields
            if before[name] != candidate.to_dict()[name]
        ]

        self._profiles[device_id] = candidate

        if changed:
            event = DeviceProfileChange(
                profile_id=profile.profile_id,
                device_id=device_id,
                changed_fields=changed,
                detected_at=candidate.updated_at,
            )
            self._history[device_id].append(event)

        return candidate

    def compare(
        self,
        device_id: str,
        current: Mapping[str, Any],
    ) -> list[str]:

        profile = self.get(device_id)

        if profile is None:
            raise DeviceProfileError("Device profile not found")

        if not isinstance(current, Mapping):
            raise DeviceProfileError("current must be a mapping")

        changes = []

        if "ip_address" in current:
            if self._validate_ip(current["ip_address"]) != profile.ip_address:
                changes.append("ip_address")

        if "mac_address" in current:
            if self._validate_mac(current["mac_address"]) != profile.mac_address:
                changes.append("mac_address")

        for field_name in (
            "hostname",
            "vendor",
            "operating_system",
            "device_type",
        ):
            if field_name in current:
                value = current[field_name]

                if field_name == "device_type":
                    value = str(value).strip().lower()
                else:
                    value = self._optional_text(value, field_name)

                if value != getattr(profile, field_name):
                    changes.append(field_name)

        if "services" in current:
            services = sorted({
                service.strip().lower()
                for service in current["services"]
                if isinstance(service, str) and service.strip()
            })

            if services != profile.services:
                changes.append("services")

        return changes

    def get_history(
        self,
        device_id: str,
    ) -> list[DeviceProfileChange]:
        return list(self._history.get(device_id, []))

    def delete(self, device_id: str) -> bool:
        self._history.pop(device_id, None)
        return self._profiles.pop(device_id, None) is not None

    def get_status(self) -> dict[str, int]:
        return {
            "total_profiles": len(self._profiles),
            "total_changes": sum(
                len(events)
                for events in self._history.values()
            ),
        }


__all__ = [
    "DeviceProfileError",
    "DeviceProfile",
    "DeviceProfileChange",
    "DeviceProfileAnalyzer",
]
