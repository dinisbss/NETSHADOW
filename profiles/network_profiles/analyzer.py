
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping
from uuid import uuid4


class NetworkProfileError(Exception):
    """Erro do módulo Network Profiles."""


@dataclass
class NetworkProfile:
    profile_id: str
    name: str
    subnet: str
    gateway: str | None
    dns_servers: list[str]
    description: str
    created_at: str
    updated_at: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "profile_id": self.profile_id,
            "name": self.name,
            "subnet": self.subnet,
            "gateway": self.gateway,
            "dns_servers": list(self.dns_servers),
            "description": self.description,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "metadata": dict(self.metadata),
        }


@dataclass
class NetworkProfileComparison:
    profile_id: str
    matches: bool
    changes: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "profile_id": self.profile_id,
            "matches": self.matches,
            "changes": list(self.changes),
        }


class NetworkProfileAnalyzer:
    """Cria, gere e compara perfis de redes através de metadados."""

    def __init__(self) -> None:
        self._profiles: dict[str, NetworkProfile] = {}

    @staticmethod
    def _validate_ip(value: str, field_name: str) -> str:
        try:
            return str(ipaddress.ip_address(value))
        except (ValueError, TypeError) as exc:
            raise NetworkProfileError(
                f"Invalid {field_name}"
            ) from exc

    @staticmethod
    def _validate_subnet(value: str) -> str:
        try:
            return str(
                ipaddress.ip_network(value, strict=False)
            )
        except (ValueError, TypeError) as exc:
            raise NetworkProfileError(
                "Invalid subnet"
            ) from exc

    def create(
        self,
        name: str,
        subnet: str,
        gateway: str | None = None,
        dns_servers: list[str] | None = None,
        description: str = "",
        metadata: Mapping[str, Any] | None = None,
    ) -> NetworkProfile:

        if not isinstance(name, str) or not name.strip():
            raise NetworkProfileError(
                "Profile name is required"
            )

        normalized_subnet = self._validate_subnet(subnet)

        normalized_gateway = None

        if gateway is not None:
            normalized_gateway = self._validate_ip(
                gateway,
                "gateway",
            )

            if ipaddress.ip_address(normalized_gateway) not in (
                ipaddress.ip_network(normalized_subnet)
            ):
                raise NetworkProfileError(
                    "Gateway must belong to the configured subnet"
                )

        normalized_dns = []

        for server in dns_servers or []:
            normalized_dns.append(
                self._validate_ip(server, "DNS server")
            )

        now = datetime.now(timezone.utc).isoformat()

        profile = NetworkProfile(
            profile_id=str(uuid4()),
            name=name.strip(),
            subnet=normalized_subnet,
            gateway=normalized_gateway,
            dns_servers=sorted(set(normalized_dns)),
            description=str(description).strip(),
            created_at=now,
            updated_at=now,
            metadata=dict(metadata or {}),
        )

        self._profiles[profile.profile_id] = profile
        return profile

    def get(self, profile_id: str) -> NetworkProfile | None:
        return self._profiles.get(profile_id)

    def get_all(self) -> list[NetworkProfile]:
        return list(self._profiles.values())

    def update(
        self,
        profile_id: str,
        **changes: Any,
    ) -> NetworkProfile:

        profile = self.get(profile_id)

        if profile is None:
            raise NetworkProfileError(
                "Profile not found"
            )

        allowed_fields = {
            "name",
            "subnet",
            "gateway",
            "dns_servers",
            "description",
            "metadata",
        }

        unknown = set(changes) - allowed_fields

        if unknown:
            raise NetworkProfileError(
                f"Unsupported fields: {sorted(unknown)}"
            )

        updated = profile.to_dict()

        updated.update(changes)

        gateway = updated["gateway"]

        replacement = self.create(
            name=updated["name"],
            subnet=updated["subnet"],
            gateway=gateway,
            dns_servers=updated["dns_servers"],
            description=updated["description"],
            metadata=updated["metadata"],
        )

        replacement.profile_id = profile.profile_id
        replacement.created_at = profile.created_at
        replacement.updated_at = datetime.now(
            timezone.utc
        ).isoformat()

        self._profiles[profile.profile_id] = replacement

        return replacement

    def compare(
        self,
        profile_id: str,
        current: Mapping[str, Any],
    ) -> NetworkProfileComparison:

        profile = self.get(profile_id)

        if profile is None:
            raise NetworkProfileError(
                "Profile not found"
            )

        if not isinstance(current, Mapping):
            raise NetworkProfileError(
                "current must be a mapping"
            )

        changes = []

        current_subnet = self._validate_subnet(
            current.get("subnet", "")
        )

        if current_subnet != profile.subnet:
            changes.append("subnet_changed")

        current_gateway = current.get("gateway")

        if current_gateway is not None:
            current_gateway = self._validate_ip(
                current_gateway,
                "gateway",
            )

        if current_gateway != profile.gateway:
            changes.append("gateway_changed")

        current_dns = sorted({
            self._validate_ip(server, "DNS server")
            for server in current.get("dns_servers", [])
        })

        if current_dns != profile.dns_servers:
            changes.append("dns_servers_changed")

        return NetworkProfileComparison(
            profile_id=profile.profile_id,
            matches=not changes,
            changes=changes,
        )

    def delete(self, profile_id: str) -> bool:
        return self._profiles.pop(profile_id, None) is not None

    def get_status(self) -> dict[str, int]:
        return {
            "total_profiles": len(self._profiles),
        }


__all__ = [
    "NetworkProfileError",
    "NetworkProfile",
    "NetworkProfileComparison",
    "NetworkProfileAnalyzer",
]
