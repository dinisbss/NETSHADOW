
"""Network information commands for NETSHADOW."""

from __future__ import annotations

import json
from typing import Any, Optional

from engines.network_engine.interfaces import NetworkInterfaceManager
from engines.network_engine.gateway import GatewayManager
from engines.network_engine.subnet import SubnetManager


class NetworkCommandError(RuntimeError):
    """Raised when a network command fails."""


class NetworkCommand:
    """Provides read-only local network information."""

    def __init__(
        self,
        interface_manager: Optional[NetworkInterfaceManager] = None,
        gateway_manager: Optional[GatewayManager] = None,
        subnet_manager: Optional[SubnetManager] = None,
    ) -> None:
        self.interface_manager = (
            interface_manager or NetworkInterfaceManager()
        )
        self.gateway_manager = gateway_manager or GatewayManager()
        self.subnet_manager = subnet_manager or SubnetManager()

    @staticmethod
    def _serialize(value: Any) -> Any:
        """Convert common Python objects into printable values."""
        if hasattr(value, "to_dict"):
            return value.to_dict()

        if hasattr(value, "__dict__"):
            return vars(value)

        if isinstance(value, (list, tuple)):
            return [NetworkCommand._serialize(item) for item in value]

        return str(value)

    def get_interfaces(self) -> list[Any]:
        """Return information about local network interfaces."""
        try:
            manager = self.interface_manager

            if hasattr(manager, "get_interfaces"):
                result = manager.get_interfaces()
            elif hasattr(manager, "discover"):
                result = manager.discover()
            else:
                raise NetworkCommandError(
                    "Interface manager has no supported query method."
                )

            return list(result or [])

        except NetworkCommandError:
            raise
        except Exception as exc:
            raise NetworkCommandError(
                f"Unable to retrieve interfaces: {exc}"
            ) from exc

    def get_gateways(self) -> Any:
        """Return locally configured gateways."""
        try:
            manager = self.gateway_manager

            if hasattr(manager, "get_gateways"):
                return manager.get_gateways()

            if hasattr(manager, "get_default_gateway"):
                return manager.get_default_gateway()

            if hasattr(manager, "detect"):
                return manager.detect()

            raise NetworkCommandError(
                "Gateway manager has no supported query method."
            )

        except NetworkCommandError:
            raise
        except Exception as exc:
            raise NetworkCommandError(
                f"Unable to retrieve gateways: {exc}"
            ) from exc

    def analyze_subnet(self, network: str) -> Any:
        """Analyze a supplied IPv4 or IPv6 subnet."""
        try:
            manager = self.subnet_manager

            if hasattr(manager, "analyze"):
                return manager.analyze(network)

            if hasattr(manager, "get_subnet_info"):
                return manager.get_subnet_info(network)

            if hasattr(manager, "inspect"):
                return manager.inspect(network)

            raise NetworkCommandError(
                "Subnet manager has no supported analysis method."
            )

        except NetworkCommandError:
            raise
        except Exception as exc:
            raise NetworkCommandError(
                f"Unable to analyze subnet: {exc}"
            ) from exc

    def get_network_summary(self) -> dict[str, Any]:
        """Collect a read-only summary of local network information."""
        return {
            "interfaces": self._serialize(self.get_interfaces()),
            "gateways": self._serialize(self.get_gateways()),
        }

    def display_interfaces(self) -> None:
        """Print local interface information."""
        interfaces = self.get_interfaces()

        if not interfaces:
            print("No network interfaces found.")
            return

        print("\nNETWORK INTERFACES")
        print("-" * 50)

        for interface in interfaces:
            data = self._serialize(interface)

            if isinstance(data, dict):
                for key, value in data.items():
                    print(f"{key}: {value}")
            else:
                print(data)

            print("-" * 50)

    def display_gateways(self) -> None:
        """Print locally configured gateways."""
        gateways = self._serialize(self.get_gateways())

        print("\nNETWORK GATEWAYS")
        print("-" * 50)
        print(json.dumps(gateways, indent=2, ensure_ascii=False))
        print("-" * 50)

    def display_summary(self) -> None:
        """Print a complete local network summary."""
        summary = self.get_network_summary()

        print("\nNETSHADOW - NETWORK SUMMARY")
        print("=" * 50)
        print(json.dumps(summary, indent=2, ensure_ascii=False))
        print("=" * 50)


NetworkCommands = NetworkCommand
NetworkManagerCommand = NetworkCommand

__all__ = [
    "NetworkCommandError",
    "NetworkCommand",
    "NetworkCommands",
    "NetworkManagerCommand",
]
