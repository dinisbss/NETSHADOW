
"""
NETSHADOW - Secure Core

Camada central de controlo de permissões.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from core.permissions import (
    PermissionManager,
    PermissionMode,
    PermissionResult,
)


@dataclass
class SecurityStatus:
    mode: str
    authorized: bool
    reason: str


class SecureCore:
    """Centraliza verificações de autorização."""

    def __init__(
        self,
        permission_manager: PermissionManager | None = None,
    ):
        self.permission_manager = (
            permission_manager or PermissionManager()
        )

    @property
    def mode(self) -> PermissionMode:
        return self.permission_manager.mode

    def set_mode(self, mode: PermissionMode | str) -> None:
        self.permission_manager.set_mode(mode)

    def check_operation(
        self,
        operation: str,
        target: str | None = None,
        authorization_reference: str | None = None,
    ) -> PermissionResult:
        """
        Verifica se uma operação está autorizada.

        A decisão final pertence sempre ao PermissionManager.
        """

        if not isinstance(operation, str) or not operation.strip():
            return PermissionResult(
                allowed=False,
                reason="Invalid operation.",
            )

        return self.permission_manager.check_operation(
            operation=operation,
            target=target,
            authorization_reference=authorization_reference,
        )

    def check_network(
        self,
        network: str,
        authorization_reference: str | None = None,
    ) -> PermissionResult:
        if not isinstance(network, str) or not network.strip():
            return PermissionResult(
                allowed=False,
                reason="Invalid network.",
            )

        return self.permission_manager.check_operation(
            operation="network_info",
            target=network,
            authorization_reference=authorization_reference,
        )

    def check_device(
        self,
        device: str,
        authorization_reference: str | None = None,
    ) -> PermissionResult:
        if not isinstance(device, str) or not device.strip():
            return PermissionResult(
                allowed=False,
                reason="Invalid device.",
            )

        return self.permission_manager.check_operation(
            operation="device_info",
            target=device,
            authorization_reference=authorization_reference,
        )

    def get_status(self) -> SecurityStatus:
        return SecurityStatus(
            mode=self.mode.value,
            authorized=True,
            reason="Permission manager active.",
        )

    def get_permission_manager(self) -> PermissionManager:
        return self.permission_manager
