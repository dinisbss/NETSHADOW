
"""
NETSHADOW - Scan Commands

Gestão de pedidos de auditoria de rede.
Este componente não executa scans nem envia pacotes.
"""

from __future__ import annotations

import ipaddress
import logging

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from threading import RLock
from typing import Any
from uuid import uuid4

from core.permissions import PermissionManager, PermissionMode
from core.network_context import NetworkContextManager
from interface.console import NetShadowConsole


class ScanStatus(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    CANCELLED = "CANCELLED"
    REJECTED = "REJECTED"


@dataclass
class ScanRequest:
    request_id: str
    target: str
    target_type: str
    mode: str
    status: ScanStatus
    created_at: datetime
    updated_at: datetime
    authorization_reference: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


class ScanCommands:
    """
    Gere pedidos de auditoria autorizados.

    Não executa operações de descoberta ou análise de portas.
    """

    MAX_REQUESTS = 10000
    MAX_IPV4_ADDRESSES = 256
    MAX_IPV6_ADDRESSES = 256

    def __init__(
        self,
        permission_manager: PermissionManager,
        network_context: NetworkContextManager,
        console: NetShadowConsole | None = None,
        logger: logging.Logger | None = None,
    ):
        if not isinstance(permission_manager, PermissionManager):
            raise TypeError("A valid PermissionManager is required.")

        if not isinstance(network_context, NetworkContextManager):
            raise TypeError("A valid NetworkContextManager is required.")

        self.permission_manager = permission_manager
        self.network_context = network_context
        self.console = console or NetShadowConsole()
        self.logger = logger or logging.getLogger("NETSHADOW")

        self.requests: dict[str, ScanRequest] = {}
        self._lock = RLock()

    @staticmethod
    def _now() -> datetime:
        return datetime.now(timezone.utc)

    def _validate_target(
        self,
        target: str,
        target_type: str,
    ) -> str | None:
        if not isinstance(target, str) or not target.strip():
            return None

        try:
            if target_type == "network":
                parsed = ipaddress.ip_network(
                    target.strip(),
                    strict=False,
                )

                limit = (
                    self.MAX_IPV4_ADDRESSES
                    if parsed.version == 4
                    else self.MAX_IPV6_ADDRESSES
                )

                if parsed.num_addresses > limit:
                    return None

                return str(parsed)

            if target_type == "device":
                return str(ipaddress.ip_address(target.strip()))

        except ValueError:
            return None

        return None

    def _is_authorized(
        self,
        target: str,
        target_type: str,
        authorization_reference: str | None,
    ) -> bool:
        if not isinstance(authorization_reference, str):
            return False

        if not authorization_reference.strip():
            return False

        if target_type == "network":
            return self.permission_manager.is_network_authorized(
                target,
                authorization_reference,
            )

        if target_type == "device":
            return self.permission_manager.is_device_authorized(
                target,
                authorization_reference,
            )

        return False

    def create_request(
        self,
        authorization_reference: str | None = None,
    ) -> ScanRequest | None:
        context = self.network_context.get_context()

        if context is None:
            self.console.warning(
                "Select a target before creating a request."
            )
            return None

        target_type = (
            "network" if context.is_network else "device"
        )

        target = self._validate_target(
            str(context.target),
            target_type,
        )

        if target is None:
            self.console.error("The selected target is invalid or too large.")
            return None

        mode = self.permission_manager.mode

        if mode == PermissionMode.SAFE:
            self.console.warning(
                "SAFE mode does not allow audit requests."
            )
            return None

        if mode != PermissionMode.AUDIT:
            self.console.warning(
                "Audit requests require AUDIT permission mode."
            )
            return None

        if not self._is_authorized(
            target,
            target_type,
            authorization_reference,
        ):
            self.console.error(
                "A valid authorization for this target is required."
            )
            return None

        now = self._now()

        request = ScanRequest(
            request_id=str(uuid4()),
            target=target,
            target_type=target_type,
            mode=mode.value,
            status=ScanStatus.APPROVED,
            created_at=now,
            updated_at=now,
            authorization_reference=authorization_reference,
        )

        with self._lock:
            if len(self.requests) >= self.MAX_REQUESTS:
                self.console.error(
                    "Maximum number of requests reached."
                )
                return None

            self.requests[request.request_id] = request

        self.console.success(
            f"Audit request registered: {request.request_id}"
        )

        self.logger.info(
            "Audit request registered: id=%s target=%s type=%s",
            request.request_id,
            request.target,
            request.target_type,
        )

        return request

    def get_request(
        self,
        request_id: str,
    ) -> ScanRequest | None:
        if not isinstance(request_id, str):
            return None

        with self._lock:
            return self.requests.get(request_id)

    def list_requests(self) -> list[dict[str, Any]]:
        with self._lock:
            requests = list(self.requests.values())

        return [
            {
                "request_id": request.request_id,
                "target": request.target,
                "target_type": request.target_type,
                "mode": request.mode,
                "status": request.status.value,
                "created_at": request.created_at.isoformat(),
                "updated_at": request.updated_at.isoformat(),
            }
            for request in requests
        ]

    def cancel_request(self, request_id: str) -> bool:
        with self._lock:
            request = self.requests.get(request_id)

            if request is None:
                return False

            if request.status not in {
                ScanStatus.PENDING,
                ScanStatus.APPROVED,
            }:
                return False

            request.status = ScanStatus.CANCELLED
            request.updated_at = self._now()

        self.console.info(
            f"Audit request cancelled: {request_id}"
        )

        self.logger.info(
            "Audit request cancelled: %s",
            request_id,
        )

        return True

    def reject_request(self, request_id: str) -> bool:
        with self._lock:
            request = self.requests.get(request_id)

            if request is None:
                return False

            if request.status not in {
                ScanStatus.PENDING,
                ScanStatus.APPROVED,
            }:
                return False

            request.status = ScanStatus.REJECTED
            request.updated_at = self._now()

        self.logger.info(
            "Audit request rejected: %s",
            request_id,
        )

        return True

    def get_status_summary(self) -> dict[str, int]:
        with self._lock:
            requests = list(self.requests.values())

        summary = {
            status.value: 0
            for status in ScanStatus
        }

        for request in requests:
            summary[request.status.value] += 1

        return summary
