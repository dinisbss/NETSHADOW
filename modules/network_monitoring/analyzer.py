
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping


class NetworkMonitoringError(Exception):
    """Erro do módulo Network Monitoring."""


@dataclass
class MonitoringReport:
    generated_at: str
    total_devices: int
    available_devices: int
    unavailable_devices: int
    average_latency_ms: float | None
    new_devices: list[str] = field(default_factory=list)
    missing_devices: list[str] = field(default_factory=list)
    alerts: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "total_devices": self.total_devices,
            "available_devices": self.available_devices,
            "unavailable_devices": self.unavailable_devices,
            "average_latency_ms": self.average_latency_ms,
            "new_devices": list(self.new_devices),
            "missing_devices": list(self.missing_devices),
            "alerts": list(self.alerts),
        }


class NetworkMonitoringAnalyzer:
    """Analisa observações de monitorização fornecidas externamente."""

    def analyze(
        self,
        current_devices: list[Mapping[str, Any]],
        previous_devices: list[Mapping[str, Any]] | None = None,
        latency_measurements: list[Mapping[str, Any]] | None = None,
    ) -> MonitoringReport:

        if not isinstance(current_devices, list):
            raise NetworkMonitoringError(
                "current_devices must be a list"
            )

        previous_devices = previous_devices or []
        latency_measurements = latency_measurements or []

        def extract_ids(items: list[Mapping[str, Any]]) -> set[str]:
            result = set()

            for item in items:
                if not isinstance(item, Mapping):
                    raise NetworkMonitoringError(
                        "Device entries must be mappings"
                    )

                device_id = str(item.get("device_id", "")).strip()

                if not device_id:
                    raise NetworkMonitoringError(
                        "Every device requires a device_id"
                    )

                result.add(device_id)

            return result

        current_ids = extract_ids(current_devices)
        previous_ids = extract_ids(previous_devices)

        available = 0
        unavailable = 0
        alerts: list[str] = []

        for device in current_devices:
            status = str(
                device.get("status", "unknown")
            ).lower()

            if status in {"online", "available", "up"}:
                available += 1
            elif status in {"offline", "unavailable", "down"}:
                unavailable += 1
                alerts.append(
                    f"Device unavailable: {device['device_id']}"
                )

        new_devices = sorted(current_ids - previous_ids)
        missing_devices = sorted(previous_ids - current_ids)

        if new_devices:
            alerts.append(
                f"{len(new_devices)} new device records detected."
            )

        if missing_devices:
            alerts.append(
                f"{len(missing_devices)} previous device records are missing."
            )

        latencies: list[float] = []

        for measurement in latency_measurements:
            if not isinstance(measurement, Mapping):
                raise NetworkMonitoringError(
                    "Latency entries must be mappings"
                )

            value = measurement.get("latency_ms")

            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or value < 0
                or value == float("inf")
                or value != value
            ):
                raise NetworkMonitoringError(
                    "Invalid latency measurement"
                )

            latencies.append(float(value))

        average_latency = (
            sum(latencies) / len(latencies)
            if latencies else None
        )

        if average_latency is not None and average_latency > 200:
            alerts.append(
                "Average recorded latency is above 200 ms."
            )

        return MonitoringReport(
            generated_at=datetime.now(timezone.utc).isoformat(),
            total_devices=len(current_ids),
            available_devices=available,
            unavailable_devices=unavailable,
            average_latency_ms=average_latency,
            new_devices=new_devices,
            missing_devices=missing_devices,
            alerts=alerts,
        )


__all__ = [
    "NetworkMonitoringError",
    "MonitoringReport",
    "NetworkMonitoringAnalyzer",
]
