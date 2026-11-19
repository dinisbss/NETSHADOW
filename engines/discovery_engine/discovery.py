
"""
NETSHADOW - Discovery Engine

Gestão controlada de pedidos e resultados de descoberta.
Não executa sondagens de rede nem envia pacotes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from ipaddress import ip_address, ip_network
from threading import RLock
from typing import Any
from uuid import uuid4


class DiscoveryMode(str, Enum):
    SAFE = "SAFE"
    AUDIT = "AUDIT"


class DiscoveryStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    REJECTED = "REJECTED"
    FAILED = "FAILED"


@dataclass
class DiscoveryRequest:
    request_id: str
    target: str
    mode: DiscoveryMode
    status: DiscoveryStatus
    created_at: str
    authorization_reference: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class DiscoveryResult:
    request_id: str
    target: str
    status: DiscoveryStatus
    discovered_devices: list[dict[str, Any]]
    created_at: str


class DiscoveryEngine:
    """
    Gere pedidos de descoberta e resultados passivos.

    SAFE é o modo predefinido.
    AUDIT exige autorização explícita e válida.
    """

    MAX_IPV4_ADDRESSES = 256
    MAX_IPV6_ADDRESSES = 256
    MAX_TARGET_LENGTH = 64
    MAX_DISCOVERED_DEVICES = 256

    def __init__(self, permission_manager=None):
        self.permission_manager = permission_manager
        self.requests: dict[str, DiscoveryRequest] = {}
        self.results: dict[str, DiscoveryResult] = {}
        self._lock = RLock()

    @staticmethod
    def _timestamp() -> str:
        return datetime.now(timezone.utc).isoformat()

    @classmethod
    def validate_target(cls, target: str) -> bool:
        if not isinstance(target, str):
            return False

        target = target.strip()

        if not target or len(target) > cls.MAX_TARGET_LENGTH:
            return False

        try:
            ip_address(target)
            return True
        except ValueError:
            pass

        try:
            network = ip_network(target, strict=False)
        except ValueError:
            return False

        if network.version == 4:
            return network.num_addresses <= cls.MAX_IPV4_ADDRESSES

        return network.num_addresses <= cls.MAX_IPV6_ADDRESSES

    def _has_valid_authorization(
        self,
        target: str,
        reference: str | None,
    ) -> bool:
        if self.permission_manager is None or not reference:
            return False

        try:
            address = ip_address(target)
        except ValueError:
            try:
                network = ip_network(target, strict=False)
            except ValueError:
                return False

            return self.permission_manager.is_network_authorized(
                str(network),
                reference,
            )

        return self.permission_manager.is_device_authorized(
            str(address),
            reference,
        )

    def create_request(
        self,
        target: str,
        mode: DiscoveryMode = DiscoveryMode.SAFE,
        authorization_reference: str | None = None,
    ) -> DiscoveryRequest | None:

        if not self.validate_target(target):
            return None

        try:
            mode = DiscoveryMode(mode)
        except (ValueError, TypeError):
            return None

        normalized_target = target.strip()

        if mode == DiscoveryMode.AUDIT:
            if not self._has_valid_authorization(
                normalized_target,
                authorization_reference,
            ):
                return None

        request = DiscoveryRequest(
            request_id=str(uuid4()),
            target=normalized_target,
            mode=mode,
            status=DiscoveryStatus.PENDING,
            created_at=self._timestamp(),
            authorization_reference=authorization_reference,
        )

        with self._lock:
            self.requests[request.request_id] = request

        return request

    def get_request(
        self,
        request_id: str,
    ) -> DiscoveryRequest | None:
        if not isinstance(request_id, str):
            return None

        with self._lock:
            return self.requests.get(request_id)

    def list_requests(self) -> list[DiscoveryRequest]:
        with self._lock:
            return list(self.requests.values())

    def get_result(
        self,
        request_id: str,
    ) -> DiscoveryResult | None:
        if not isinstance(request_id, str):
            return None

        with self._lock:
            return self.results.get(request_id)

    def register_result(
        self,
        request_id: str,
        discovered_devices: list[dict[str, Any]] | None = None,
    ) -> DiscoveryResult | None:
        """
        Regista observações passivas fornecidas por outro componente.
        Não executa descoberta de dispositivos.
        """

        if discovered_devices is None:
            devices = []
        elif not isinstance(discovered_devices, list):
            return None
        else:
            devices = discovered_devices

        if len(devices) > self.MAX_DISCOVERED_DEVICES:
            return None

        if any(not isinstance(device, dict) for device in devices):
            return None

        with self._lock:
            request = self.requests.get(request_id)

            if request is None:
                return None

            if request.status != DiscoveryStatus.PENDING:
                return None

            # Volta a validar a autorização no momento do registo.
            if request.mode == DiscoveryMode.AUDIT:
                if not self._has_valid_authorization(
                    request.target,
                    request.authorization_reference,
                ):
                    request.status = DiscoveryStatus.REJECTED
                    return None

            request.status = DiscoveryStatus.COMPLETED

            result = DiscoveryResult(
                request_id=request_id,
                target=request.target,
                status=DiscoveryStatus.COMPLETED,
                discovered_devices=[dict(device) for device in devices],
                created_at=self._timestamp(),
            )

            self.results[request_id] = result

            return result

    def reject_request(self, request_id: str) -> bool:
        with self._lock:
            request = self.requests.get(request_id)

            if request is None:
                return False

            if request.status != DiscoveryStatus.PENDING:
                return False

            request.status = DiscoveryStatus.REJECTED
            return True

    def get_summary(self) -> dict[str, int]:
        with self._lock:
            requests = list(self.requests.values())

        return {
            "total": len(requests),
            "pending": sum(
                item.status == DiscoveryStatus.PENDING
                for item in requests
            ),
            "running": sum(
                item.status == DiscoveryStatus.RUNNING
                for item in requests
            ),
            "completed": sum(
                item.status == DiscoveryStatus.COMPLETED
                for item in requests
            ),
            "rejected": sum(
                item.status == DiscoveryStatus.REJECTED
                for item in requests
            ),
            "failed": sum(
                item.status == DiscoveryStatus.FAILED
                for item in requests
            ),
        }
