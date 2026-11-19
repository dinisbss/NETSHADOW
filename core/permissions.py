
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from ipaddress import ip_address, ip_network
from threading import RLock
from uuid import uuid4


class PermissionMode(str, Enum):
    SAFE = "SAFE"
    AUDIT = "AUDIT"
    MONITOR = "MONITOR"


@dataclass(frozen=True)
class Authorization:
    reference: str
    scope: str
    reason: str
    created_at: datetime
    expires_at: datetime
    revoked: bool = False


@dataclass(frozen=True)
class PermissionResult:
    allowed: bool
    reason: str
    authorization_reference: str | None = None


class PermissionManager:
    READ_ONLY_OPERATIONS = frozenset({
        "network_info",
        "device_info",
        "read_history",
        "generate_report",
        "analyze_findings",
    })

    MAX_AUTHORIZATIONS = 10000
    MAX_REASON_LENGTH = 500

    def __init__(self):
        self._mode = PermissionMode.SAFE
        self._authorizations: dict[str, Authorization] = {}
        self._lock = RLock()

    @property
    def mode(self) -> PermissionMode:
        with self._lock:
            return self._mode

    def set_mode(self, mode: str) -> None:
        if not isinstance(mode, str):
            raise ValueError("Invalid permission mode.")

        try:
            selected_mode = PermissionMode(mode.upper())
        except ValueError as error:
            raise ValueError("Invalid permission mode.") from error

        with self._lock:
            self._mode = selected_mode

    def create_authorization(
        self,
        scope: str,
        reason: str,
        confirmation: bool = False,
        validity_minutes: int = 60,
    ) -> Authorization:
        if confirmation is not True:
            raise PermissionError(
                "Explicit confirmation is required."
            )

        if not isinstance(scope, str) or not scope.strip():
            raise ValueError("Authorization scope is required.")

        if not isinstance(reason, str) or not reason.strip():
            raise ValueError("Authorization reason is required.")

        if len(reason) > self.MAX_REASON_LENGTH:
            raise ValueError("Authorization reason is too long.")

        if any(ord(char) < 32 for char in reason):
            raise ValueError("Invalid characters in authorization reason.")

        if (
            isinstance(validity_minutes, bool)
            or not isinstance(validity_minutes, int)
            or not 1 <= validity_minutes <= 1440
        ):
            raise ValueError("Invalid authorization validity.")

        try:
            parsed_scope = ip_network(scope.strip(), strict=False)
        except ValueError:
            try:
                parsed_scope = ip_address(scope.strip())
            except ValueError as error:
                raise ValueError("Invalid authorization scope.") from error

        now = datetime.now(timezone.utc)

        authorization = Authorization(
            reference=uuid4().hex,
            scope=str(parsed_scope),
            reason=reason.strip(),
            created_at=now,
            expires_at=now + timedelta(minutes=validity_minutes),
        )

        with self._lock:
            if len(self._authorizations) >= self.MAX_AUTHORIZATIONS:
                raise PermissionError(
                    "Authorization storage limit reached."
                )

            self._authorizations[authorization.reference] = authorization

        return authorization

    def revoke_authorization(self, reference: str) -> bool:
        if not isinstance(reference, str):
            return False

        with self._lock:
            authorization = self._authorizations.get(reference)

            if authorization is None or authorization.revoked:
                return False

            self._authorizations[reference] = Authorization(
                reference=authorization.reference,
                scope=authorization.scope,
                reason=authorization.reason,
                created_at=authorization.created_at,
                expires_at=authorization.expires_at,
                revoked=True,
            )

            return True

    def get_authorization(
        self,
        reference: str,
    ) -> Authorization | None:
        if not isinstance(reference, str):
            return None

        with self._lock:
            return self._authorizations.get(reference)

    def _valid_authorization(
        self,
        target: str,
        reference: str | None,
    ) -> Authorization | None:
        if not isinstance(target, str):
            return None

        if not isinstance(reference, str) or not reference:
            return None

        with self._lock:
            authorization = self._authorizations.get(reference)

        if authorization is None or authorization.revoked:
            return None

        if datetime.now(timezone.utc) >= authorization.expires_at:
            return None

        try:
            address = ip_address(target)
            scope = ip_network(authorization.scope, strict=False)

            if address not in scope:
                return None

        except (ValueError, TypeError):
            return None

        return authorization

    def authorize_network(self, network: str) -> None:
        try:
            ip_network(network, strict=False)
        except ValueError as error:
            raise ValueError("Invalid network address.") from error

        raise PermissionError(
            "A network selection does not grant authorization. "
            "Use create_authorization() with explicit confirmation."
        )

    def authorize_device(self, address: str) -> None:
        try:
            ip_address(address)
        except ValueError as error:
            raise ValueError("Invalid device address.") from error

        raise PermissionError(
            "A device selection does not grant authorization. "
            "Use create_authorization() with explicit confirmation."
        )

    def is_network_authorized(
        self,
        network: str,
        authorization_reference: str | None = None,
    ) -> bool:
        try:
            requested = ip_network(network, strict=False)
        except ValueError:
            return False

        authorization = self._valid_authorization(
            str(requested.network_address),
            authorization_reference,
        )

        if authorization is None:
            return False

        try:
            authorized_scope = ip_network(
                authorization.scope,
                strict=False,
            )

            return requested.subnet_of(authorized_scope)

        except (ValueError, TypeError):
            return False

    def is_device_authorized(
        self,
        address: str,
        authorization_reference: str | None = None,
    ) -> bool:
        try:
            target = ip_address(address)
        except ValueError:
            return False

        authorization = self._valid_authorization(
            str(target),
            authorization_reference,
        )

        return authorization is not None

    def check_operation(
        self,
        operation: str,
        target: str | None = None,
        authorization_reference: str | None = None,
    ) -> PermissionResult:
        if not isinstance(operation, str):
            return PermissionResult(False, "Invalid operation.")

        operation = operation.strip().lower()

        if operation not in self.READ_ONLY_OPERATIONS:
            return PermissionResult(
                False,
                "Operation not permitted.",
            )

        with self._lock:
            current_mode = self._mode

        if current_mode == PermissionMode.SAFE:
            return PermissionResult(
                True,
                "Read-only operation allowed.",
            )

        if target is None:
            return PermissionResult(
                False,
                "An explicit target is required.",
            )

        authorization = self._valid_authorization(
            target,
            authorization_reference,
        )

        if authorization is None:
            return PermissionResult(
                False,
                "Valid authorization required.",
            )

        return PermissionResult(
            True,
            "Operation permitted.",
            authorization.reference,
        )

    def clear_authorizations(self) -> None:
        with self._lock:
            self._authorizations.clear()


__all__ = [
    "PermissionMode",
    "Authorization",
    "PermissionResult",
    "PermissionManager",
]
