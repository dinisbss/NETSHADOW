
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4


class PermissionAnalyzerError(Exception):
    """Erro do módulo Permission Manager."""


class PermissionScope(str, Enum):
    READ = "read"
    AUDIT = "audit"
    MONITOR = "monitor"


class PermissionDecision(str, Enum):
    ALLOWED = "allowed"
    DENIED = "denied"
    EXPIRED = "expired"
    OUT_OF_SCOPE = "out_of_scope"


@dataclass
class PermissionGrant:
    grant_id: str
    subject: str
    target: str
    scope: PermissionScope
    issued_at: str
    expires_at: str
    active: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "grant_id": self.grant_id,
            "subject": self.subject,
            "target": self.target,
            "scope": self.scope.value,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "active": self.active,
        }


@dataclass
class PermissionResult:
    allowed: bool
    decision: PermissionDecision
    reason: str
    grant_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "decision": self.decision.value,
            "reason": self.reason,
            "grant_id": self.grant_id,
        }


class PermissionAnalyzer:
    """Avalia autorizações registadas localmente."""

    def __init__(self) -> None:
        self._grants: dict[str, PermissionGrant] = {}
        self._audit_log: list[dict[str, Any]] = []

    @staticmethod
    def _parse_datetime(value: str) -> datetime:
        if not isinstance(value, str) or not value.strip():
            raise PermissionAnalyzerError(
                "Datetime must be a non-empty ISO string"
            )

        try:
            parsed = datetime.fromisoformat(
                value.replace("Z", "+00:00")
            )
        except ValueError as exc:
            raise PermissionAnalyzerError(
                "Invalid datetime"
            ) from exc

        if parsed.tzinfo is None:
            raise PermissionAnalyzerError(
                "Datetime must include a timezone"
            )

        return parsed.astimezone(timezone.utc)

    def grant(
        self,
        subject: str,
        target: str,
        scope: PermissionScope | str,
        expires_at: str,
    ) -> PermissionGrant:

        if not isinstance(subject, str) or not subject.strip():
            raise PermissionAnalyzerError(
                "subject is required"
            )

        if not isinstance(target, str) or not target.strip():
            raise PermissionAnalyzerError(
                "target is required"
            )

        try:
            permission_scope = PermissionScope(scope)
        except ValueError as exc:
            raise PermissionAnalyzerError(
                "Unsupported permission scope"
            ) from exc

        expiration = self._parse_datetime(expires_at)
        now = datetime.now(timezone.utc)

        if expiration <= now:
            raise PermissionAnalyzerError(
                "Expiration must be in the future"
            )

        grant = PermissionGrant(
            grant_id=str(uuid4()),
            subject=subject.strip(),
            target=target.strip(),
            scope=permission_scope,
            issued_at=now.isoformat(),
            expires_at=expiration.isoformat(),
            active=True,
        )

        self._grants[grant.grant_id] = grant
        return grant

    def revoke(self, grant_id: str) -> bool:
        grant = self._grants.get(grant_id)

        if grant is None or not grant.active:
            return False

        grant.active = False
        return True

    def check(
        self,
        subject: str,
        target: str,
        scope: PermissionScope | str,
    ) -> PermissionResult:

        try:
            requested_scope = PermissionScope(scope)
        except ValueError:
            return self._record(
                PermissionResult(
                    False,
                    PermissionDecision.DENIED,
                    "Unsupported permission scope.",
                )
            )

        if not subject or not target:
            return self._record(
                PermissionResult(
                    False,
                    PermissionDecision.DENIED,
                    "Subject and target are required.",
                )
            )

        matching = [
            grant
            for grant in self._grants.values()
            if (
                grant.subject == subject
                and grant.target == target
                and grant.scope == requested_scope
            )
        ]

        if not matching:
            return self._record(
                PermissionResult(
                    False,
                    PermissionDecision.OUT_OF_SCOPE,
                    "No matching authorization exists.",
                )
            )

        now = datetime.now(timezone.utc)

        for grant in reversed(matching):
            if not grant.active:
                continue

            if now >= self._parse_datetime(grant.expires_at):
                continue

            return self._record(
                PermissionResult(
                    True,
                    PermissionDecision.ALLOWED,
                    "A valid matching authorization exists.",
                    grant.grant_id,
                )
            )

        return self._record(
            PermissionResult(
                False,
                PermissionDecision.EXPIRED,
                "No active, unexpired matching authorization exists.",
            )
        )

    def _record(
        self,
        result: PermissionResult,
    ) -> PermissionResult:

        self._audit_log.append({
            "timestamp": datetime.now(
                timezone.utc
            ).isoformat(),
            **result.to_dict(),
        })

        return result

    def get_grants(self) -> list[PermissionGrant]:
        return list(self._grants.values())

    def get_audit_log(self) -> list[dict[str, Any]]:
        return [dict(item) for item in self._audit_log]

    def get_status(self) -> dict[str, int]:
        return {
            "total_grants": len(self._grants),
            "active_grants": sum(
                grant.active
                for grant in self._grants.values()
            ),
            "authorization_checks": len(self._audit_log),
        }


__all__ = [
    "PermissionAnalyzerError",
    "PermissionScope",
    "PermissionDecision",
    "PermissionGrant",
    "PermissionResult",
    "PermissionAnalyzer",
]
