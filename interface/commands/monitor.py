
"""Monitoring commands for NETSHADOW."""

from __future__ import annotations

from typing import Any, Optional
import inspect

from engines.monitoring_engine.availability import AvailabilityMonitor
from engines.monitoring_engine.latency import LatencyMonitor
from engines.monitoring_engine.metrics import MetricsManager
from engines.monitoring_engine.change_detection import ChangeDetector


class MonitorCommandError(RuntimeError):
    """Raised when a monitoring command fails."""


class MonitorCommand:
    """Read-only interface to monitoring components."""

    def __init__(
        self,
        availability: Optional[AvailabilityMonitor] = None,
        latency: Optional[LatencyMonitor] = None,
        metrics: Optional[MetricsManager] = None,
        changes: Optional[ChangeDetector] = None,
    ) -> None:
        self.availability = (
            availability if availability is not None
            else AvailabilityMonitor()
        )
        self.latency = (
            latency if latency is not None
            else LatencyMonitor()
        )
        self.metrics = (
            metrics if metrics is not None
            else MetricsManager()
        )
        self.changes = (
            changes if changes is not None
            else ChangeDetector()
        )

    @staticmethod
    def _serialize(value: Any) -> Any:
        if value is None or isinstance(value, (str, int, float, bool)):
            return value

        if isinstance(value, dict):
            return {
                str(key): MonitorCommand._serialize(item)
                for key, item in value.items()
            }

        if isinstance(value, (list, tuple)):
            return [
                MonitorCommand._serialize(item)
                for item in value
            ]

        if hasattr(value, "to_dict"):
            return MonitorCommand._serialize(value.to_dict())

        if hasattr(value, "__dict__"):
            return {
                key: MonitorCommand._serialize(item)
                for key, item in vars(value).items()
                if not key.startswith("_")
            }

        return str(value)

    @staticmethod
    def _read_component(
        component: Any,
        methods: tuple[str, ...],
    ) -> Any:
        """Call only methods that do not require arguments."""
        for method_name in methods:
            method = getattr(component, method_name, None)

            if not callable(method):
                continue

            try:
                signature = inspect.signature(method)
                signature.bind()
            except (TypeError, ValueError):
                continue

            return method()

        for attribute in (
            "records",
            "history",
            "metrics",
            "events",
            "results",
        ):
            value = getattr(component, attribute, None)

            if value is not None:
                return value

        return {}

    def _read(
        self,
        component: Any,
        methods: tuple[str, ...],
        component_name: str,
    ) -> Any:
        try:
            result = self._read_component(component, methods)
            return self._serialize(result)
        except Exception as exc:
            raise MonitorCommandError(
                f"Unable to retrieve {component_name}: {exc}"
            ) from exc

    def get_availability(self) -> Any:
        return self._read(
            self.availability,
            ("get_summary", "get_results", "get_all"),
            "availability",
        )

    def get_latency(self) -> Any:
        return self._read(
            self.latency,
            ("get_statistics", "get_summary", "get_results", "get_all"),
            "latency",
        )

    def get_metrics(self) -> Any:
        return self._read(
            self.metrics,
            ("get_summary", "get_metrics", "get_all"),
            "metrics",
        )

    def get_changes(self) -> Any:
        return self._read(
            self.changes,
            ("get_summary", "get_changes", "get_events", "get_all"),
            "changes",
        )

    def get_dashboard(self) -> dict[str, Any]:
        return {
            "availability": self.get_availability(),
            "latency": self.get_latency(),
            "metrics": self.get_metrics(),
            "changes": self.get_changes(),
        }

    def display_dashboard(self) -> None:
        dashboard = self.get_dashboard()

        print("\nNETSHADOW - MONITORING DASHBOARD")
        print("=" * 55)

        for section, data in dashboard.items():
            print(f"\n{section.upper()}")
            print("-" * 55)
            print(data)

        print("\n" + "=" * 55)


MonitoringCommand = MonitorCommand
MonitorCommands = MonitorCommand

__all__ = [
    "MonitorCommandError",
    "MonitorCommand",
    "MonitoringCommand",
    "MonitorCommands",
]
