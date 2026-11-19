
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Mapping


class FingerprintingError(Exception):
    """Erro do módulo Fingerprinting."""


@dataclass
class DeviceFingerprint:
    device_id: str
    fingerprint: str
    indicators: dict[str, str]
    confidence: float
    missing_indicators: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "device_id": self.device_id,
            "fingerprint": self.fingerprint,
            "indicators": dict(self.indicators),
            "confidence": round(self.confidence, 2),
            "missing_indicators": list(self.missing_indicators),
        }


@dataclass
class FingerprintComparison:
    device_id: str
    previous_fingerprint: str
    current_fingerprint: str
    changed: bool
    changed_indicators: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "device_id": self.device_id,
            "previous_fingerprint": self.previous_fingerprint,
            "current_fingerprint": self.current_fingerprint,
            "changed": self.changed,
            "changed_indicators": list(self.changed_indicators),
        }


class FingerprintingAnalyzer:
    """Cria e compara assinaturas a partir de metadados passivos."""

    INDICATORS = (
        "hostname",
        "vendor",
        "device_type",
        "operating_system",
        "mac_address",
        "services",
        "protocols",
    )

    def _normalize_value(self, value: Any) -> str:
        if value is None:
            return ""

        if isinstance(value, (list, tuple, set)):
            normalized = [
                self._normalize_value(item)
                for item in value
            ]
            return ",".join(sorted(filter(None, normalized)))

        if isinstance(value, Mapping):
            normalized = {
                str(key): self._normalize_value(item)
                for key, item in value.items()
            }
            return json.dumps(
                normalized,
                sort_keys=True,
                ensure_ascii=True,
            )

        return str(value).strip().lower()

    def _build_hash(self, indicators: dict[str, str]) -> str:
        payload = json.dumps(
            indicators,
            sort_keys=True,
            separators=(",", ":"),
        )

        return hashlib.sha256(
            payload.encode("utf-8")
        ).hexdigest()

    def create(
        self,
        device_id: str,
        metadata: Mapping[str, Any],
    ) -> DeviceFingerprint:

        device_id = str(device_id).strip()

        if not device_id:
            raise FingerprintingError(
                "device_id is required"
            )

        if not isinstance(metadata, Mapping):
            raise FingerprintingError(
                "metadata must be a mapping"
            )

        indicators = {}
        missing = []

        for name in self.INDICATORS:
            value = self._normalize_value(
                metadata.get(name)
            )

            indicators[name] = value

            if not value:
                missing.append(name)

        available = len(self.INDICATORS) - len(missing)
        confidence = available / len(self.INDICATORS)

        fingerprint = self._build_hash(indicators)

        return DeviceFingerprint(
            device_id=device_id,
            fingerprint=fingerprint,
            indicators=indicators,
            confidence=confidence,
            missing_indicators=missing,
        )

    def compare(
        self,
        previous: DeviceFingerprint,
        current: DeviceFingerprint,
    ) -> FingerprintComparison:

        if previous.device_id != current.device_id:
            raise FingerprintingError(
                "Cannot compare fingerprints from different devices"
            )

        changed = [
            name
            for name in self.INDICATORS
            if previous.indicators.get(name)
            != current.indicators.get(name)
        ]

        return FingerprintComparison(
            device_id=current.device_id,
            previous_fingerprint=previous.fingerprint,
            current_fingerprint=current.fingerprint,
            changed=bool(changed),
            changed_indicators=changed,
        )


__all__ = [
    "FingerprintingError",
    "DeviceFingerprint",
    "FingerprintComparison",
    "FingerprintingAnalyzer",
]
