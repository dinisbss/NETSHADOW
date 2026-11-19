
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping


class AssetIntelligenceError(Exception):
    """Erro do módulo Asset Intelligence."""


@dataclass
class AssetRecord:
    asset_id: str
    hostname: str | None
    ip_address: str | None
    vendor: str | None
    category: str
    status: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "hostname": self.hostname,
            "ip_address": self.ip_address,
            "vendor": self.vendor,
            "category": self.category,
            "status": self.status,
            "metadata": dict(self.metadata),
        }


@dataclass
class AssetInventoryReport:
    total_assets: int
    categories: dict[str, int]
    statuses: dict[str, int]
    duplicate_ids: list[str]
    duplicate_ips: list[str]
    incomplete_assets: list[str]
    assets: list[AssetRecord]

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_assets": self.total_assets,
            "categories": dict(self.categories),
            "statuses": dict(self.statuses),
            "duplicate_ids": list(self.duplicate_ids),
            "duplicate_ips": list(self.duplicate_ips),
            "incomplete_assets": list(self.incomplete_assets),
            "assets": [asset.to_dict() for asset in self.assets],
        }


class AssetIntelligenceAnalyzer:
    """Organiza ativos a partir de inventários fornecidos."""

    def analyze(
        self,
        devices: list[Mapping[str, Any]],
    ) -> AssetInventoryReport:

        if not isinstance(devices, list):
            raise AssetIntelligenceError(
                "devices must be a list"
            )

        assets: list[AssetRecord] = []
        categories: dict[str, int] = {}
        statuses: dict[str, int] = {}

        seen_ids: set[str] = set()
        seen_ips: set[str] = set()

        duplicate_ids: set[str] = set()
        duplicate_ips: set[str] = set()
        incomplete_assets: list[str] = []

        for device in devices:
            if not isinstance(device, Mapping):
                raise AssetIntelligenceError(
                    "Each device must be a mapping"
                )

            asset_id = str(
                device.get("asset_id", device.get("device_id", ""))
            ).strip()

            if not asset_id:
                raise AssetIntelligenceError(
                    "Every asset requires an asset_id"
                )

            ip_address = self._optional_text(
                device.get("ip_address")
            )

            hostname = self._optional_text(
                device.get("hostname")
            )

            vendor = self._optional_text(
                device.get("vendor")
            )

            category = str(
                device.get("category", device.get("device_type", "unknown"))
            ).strip().lower() or "unknown"

            status = str(
                device.get("status", "unknown")
            ).strip().lower() or "unknown"

            if asset_id in seen_ids:
                duplicate_ids.add(asset_id)

            seen_ids.add(asset_id)

            if ip_address:
                if ip_address in seen_ips:
                    duplicate_ips.add(ip_address)

                seen_ips.add(ip_address)

            if not hostname or not vendor or not ip_address:
                incomplete_assets.append(asset_id)

            categories[category] = categories.get(category, 0) + 1
            statuses[status] = statuses.get(status, 0) + 1

            metadata = device.get("metadata", {})

            if not isinstance(metadata, Mapping):
                raise AssetIntelligenceError(
                    "metadata must be a mapping"
                )

            assets.append(
                AssetRecord(
                    asset_id=asset_id,
                    hostname=hostname,
                    ip_address=ip_address,
                    vendor=vendor,
                    category=category,
                    status=status,
                    metadata=dict(metadata),
                )
            )

        return AssetInventoryReport(
            total_assets=len(assets),
            categories=categories,
            statuses=statuses,
            duplicate_ids=sorted(duplicate_ids),
            duplicate_ips=sorted(duplicate_ips),
            incomplete_assets=incomplete_assets,
            assets=assets,
        )

    @staticmethod
    def _optional_text(value: Any) -> str | None:
        if value is None:
            return None

        result = str(value).strip()
        return result or None


__all__ = [
    "AssetIntelligenceError",
    "AssetRecord",
    "AssetInventoryReport",
    "AssetIntelligenceAnalyzer",
]
