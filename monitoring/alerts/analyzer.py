
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping
from uuid import uuid4


class AlertError(Exception):
    """Erro do módulo de alertas."""


class AlertSeverity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertStatus(str, Enum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    DISMISSED = "dismissed"


@dataclass
class Alert:
    alert_id: str
    title: str
    message: str
    severity: AlertSeverity
    category: str
    source: str
    status: AlertStatus
    created_at: str
    updated_at: str
    occurrences: int = 1
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "title": self.title,
            "message": self.message,
            "severity": self.severity.value,
            "category": self.category,
            "source": self.source,
            "status": self.status.value,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "occurrences": self.occurrences,
            "metadata": dict(self.metadata),
        }


class AlertAnalyzer:
    """Cria, agrupa e acompanha alertas locais."""

    def __init__(self) -> None:
        self._alerts: dict[str, Alert] = {}
        self._history: list[dict[str, Any]] = []

    @staticmethod
    def _text(value: Any, field_name: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise AlertError(f"{field_name} is required")
        return value.strip()

    @staticmethod
    def _severity(value: AlertSeverity | str) -> AlertSeverity:
        try:
            return AlertSeverity(value)
        except ValueError as exc:
            raise AlertError("Invalid alert severity") from exc

    @staticmethod
    def _status(value: AlertStatus | str) -> AlertStatus:
        try:
            return AlertStatus(value)
        except ValueError as exc:
            raise AlertError("Invalid alert status") from exc

    def create(
        self,
        title: str,
        message: str,
        severity: AlertSeverity | str = AlertSeverity.INFO,
        category: str = "general",
        source: str = "netshadow",
        metadata: Mapping[str, Any] | None = None,
        deduplicate: bool = True,
    ) -> Alert:

        title = self._text(title, "title")
        message = self._text(message, "message")
        category = self._text(category, "category").lower()
        source = self._text(source, "source")
        severity = self._severity(severity)

        if not isinstance(deduplicate, bool):
            raise AlertError("deduplicate must be boolean")

        metadata_dict = dict(metadata or {})
        now = datetime.now(timezone.utc).isoformat()

        if deduplicate:
            for alert in self._alerts.values():
                if (
                    alert.title == title
                    and alert.category == category
                    and alert.source == source
                    and alert.status in (
                        AlertStatus.OPEN,
                        AlertStatus.ACKNOWLEDGED,
                    )
                ):
                    alert.occurrences += 1
                    alert.updated_at = now

                    self._record(
                        "repeated",
                        alert.alert_id,
                        {"occurrences": alert.occurrences},
                    )
                    return alert

        alert = Alert(
            alert_id=str(uuid4()),
            title=title,
            message=message,
            severity=severity,
            category=category,
            source=source,
            status=AlertStatus.OPEN,
            created_at=now,
            updated_at=now,
            metadata=metadata_dict,
        )

        self._alerts[alert.alert_id] = alert
        self._record("created", alert.alert_id)

        return alert

    def get(self, alert_id: str) -> Alert | None:
        return self._alerts.get(alert_id)

    def get_all(
        self,
        status: AlertStatus | str | None = None,
        severity: AlertSeverity | str | None = None,
        category: str | None = None,
    ) -> list[Alert]:

        selected_status = (
            self._status(status) if status is not None else None
        )
        selected_severity = (
            self._severity(severity) if severity is not None else None
        )

        results = list(self._alerts.values())

        if selected_status is not None:
            results = [
                item for item in results
                if item.status == selected_status
            ]

        if selected_severity is not None:
            results = [
                item for item in results
                if item.severity == selected_severity
            ]

        if category is not None:
            results = [
                item for item in results
                if item.category == category.lower()
            ]

        return results

    def update_status(
        self,
        alert_id: str,
        status: AlertStatus | str,
    ) -> Alert:

        alert = self.get(alert_id)

        if alert is None:
            raise AlertError("Alert not found")

        new_status = self._status(status)

        if alert.status in (
            AlertStatus.RESOLVED,
            AlertStatus.DISMISSED,
        ):
            raise AlertError("Closed alerts cannot be modified")

        if new_status == alert.status:
            return alert

        alert.status = new_status
        alert.updated_at = datetime.now(timezone.utc).isoformat()

        self._record(
            "status_changed",
            alert_id,
            {"status": new_status.value},
        )

        return alert

    def acknowledge(self, alert_id: str) -> Alert:
        return self.update_status(
            alert_id,
            AlertStatus.ACKNOWLEDGED,
        )

    def resolve(self, alert_id: str) -> Alert:
        return self.update_status(
            alert_id,
            AlertStatus.RESOLVED,
        )

    def dismiss(self, alert_id: str) -> Alert:
        return self.update_status(
            alert_id,
            AlertStatus.DISMISSED,
        )

    def _record(
        self,
        action: str,
        alert_id: str,
        details: Mapping[str, Any] | None = None,
    ) -> None:

        self._history.append({
            "event_id": str(uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "alert_id": alert_id,
            "details": dict(details or {}),
        })

    def get_history(
        self,
        alert_id: str | None = None,
    ) -> list[dict[str, Any]]:

        if alert_id is None:
            return [dict(item) for item in self._history]

        return [
            dict(item)
            for item in self._history
            if item["alert_id"] == alert_id
        ]

    def get_summary(self) -> dict[str, Any]:
        alerts = list(self._alerts.values())

        return {
            "total": len(alerts),
            "open": sum(
                item.status == AlertStatus.OPEN for item in alerts
            ),
            "acknowledged": sum(
                item.status == AlertStatus.ACKNOWLEDGED
                for item in alerts
            ),
            "resolved": sum(
                item.status == AlertStatus.RESOLVED for item in alerts
            ),
            "dismissed": sum(
                item.status == AlertStatus.DISMISSED for item in alerts
            ),
            "critical": sum(
                item.severity == AlertSeverity.CRITICAL
                for item in alerts
            ),
            "high": sum(
                item.severity == AlertSeverity.HIGH for item in alerts
            ),
            "total_occurrences": sum(
                item.occurrences for item in alerts
            ),
        }


__all__ = [
    "AlertError",
    "AlertSeverity",
    "AlertStatus",
    "Alert",
    "AlertAnalyzer",
]
