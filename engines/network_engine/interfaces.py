
"""
NETSHADOW - Network Interface Manager

Identifica as interfaces de rede locais.
Não envia pacotes nem realiza operações de descoberta remota.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import asdict, dataclass, field
from typing import Any, Optional


try:
    import psutil
except ImportError:
    psutil = None


@dataclass(frozen=True)
class InterfaceAddress:
    """Representa um endereço associado a uma interface."""

    address: str
    family: str
    netmask: Optional[str] = None
    broadcast: Optional[str] = None
    point_to_point: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class NetworkInterface:
    """Informação de uma interface de rede local."""

    name: str
    index: Optional[int] = None
    is_up: bool = False
    mtu: Optional[int] = None
    speed_mbps: Optional[float] = None
    mac_address: Optional[str] = None
    addresses: list[InterfaceAddress] = field(default_factory=list)
    source: str = "system"

    @property
    def ipv4_addresses(self) -> list[str]:
        return [
            item.address
            for item in self.addresses
            if item.family == "IPv4"
        ]

    @property
    def ipv6_addresses(self) -> list[str]:
        return [
            item.address
            for item in self.addresses
            if item.family == "IPv6"
        ]

    @property
    def is_active(self) -> bool:
        return self.is_up

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "index": self.index,
            "is_up": self.is_up,
            "mtu": self.mtu,
            "speed_mbps": self.speed_mbps,
            "mac_address": self.mac_address,
            "addresses": [
                address.to_dict()
                for address in self.addresses
            ],
            "ipv4_addresses": self.ipv4_addresses,
            "ipv6_addresses": self.ipv6_addresses,
            "is_active": self.is_active,
            "source": self.source,
        }


class NetworkInterfaceManager:
    """Consulta as interfaces de rede do sistema local."""

    def __init__(self) -> None:
        self._interfaces: list[NetworkInterface] = []

    @staticmethod
    def _family_name(family: Any) -> Optional[str]:
        if family == socket.AF_INET:
            return "IPv4"

        if family == socket.AF_INET6:
            return "IPv6"

        if psutil is not None:
            if family == getattr(psutil, "AF_LINK", object()):
                return "MAC"

        return None

    @staticmethod
    def _valid_ip(value: Optional[str]) -> Optional[str]:
        if not value:
            return None

        try:
            return str(ipaddress.ip_address(value.split("%")[0]))
        except ValueError:
            return None

    @staticmethod
    def _valid_mac(value: Optional[str]) -> Optional[str]:
        if not value:
            return None

        normalized = value.strip().replace("-", ":").upper()

        parts = normalized.split(":")
        if len(parts) != 6:
            return None

        try:
            if not all(
                len(part) == 2 and int(part, 16) >= 0
                for part in parts
            ):
                return None
        except ValueError:
            return None

        return normalized

    def _get_system_interfaces(self) -> list[NetworkInterface]:
        """Obtém interfaces e endereços através do psutil."""

        if psutil is None:
            return []

        try:
            addresses = psutil.net_if_addrs()
            statistics = psutil.net_if_stats()
        except (OSError, RuntimeError):
            return []

        try:
            indexes = dict(socket.if_nameindex())
        except (OSError, AttributeError):
            indexes = {}

        result: list[NetworkInterface] = []

        for name, entries in addresses.items():
            stats = statistics.get(name)

            interface = NetworkInterface(
                name=name,
                index=indexes.get(name),
                is_up=bool(stats.isup) if stats else False,
                mtu=getattr(stats, "mtu", None) if stats else None,
                speed_mbps=(
                    float(stats.speed)
                    if stats and getattr(stats, "speed", 0) > 0
                    else None
                ),
                source="psutil",
            )

            for entry in entries:
                family = self._family_name(entry.family)

                if family == "MAC":
                    interface.mac_address = (
                        self._valid_mac(entry.address)
                    )
                    continue

                if family not in ("IPv4", "IPv6"):
                    continue

                address = self._valid_ip(entry.address)
                if address is None:
                    continue

                interface.addresses.append(
                    InterfaceAddress(
                        address=address,
                        family=family,
                        netmask=entry.netmask,
                        broadcast=entry.broadcast,
                        point_to_point=entry.ptp,
                    )
                )

            result.append(interface)

        return result

    def _get_fallback_interfaces(self) -> list[NetworkInterface]:
        """
        Fallback com a biblioteca standard.

        Permite identificar nomes e índices, mas não garante
        informação sobre endereços ou estado das interfaces.
        """

        try:
            system_interfaces = socket.if_nameindex()
        except (OSError, AttributeError):
            system_interfaces = []

        return [
            NetworkInterface(
                name=name,
                index=index,
                is_up=False,
                source="socket",
            )
            for index, name in system_interfaces
        ]

    def get_interfaces(
        self,
        refresh: bool = True,
    ) -> list[NetworkInterface]:
        """Devolve todas as interfaces locais conhecidas."""

        if not refresh and self._interfaces:
            return list(self._interfaces)

        interfaces = self._get_system_interfaces()

        if not interfaces:
            interfaces = self._get_fallback_interfaces()

        self._interfaces = interfaces
        return list(self._interfaces)

    def get_interface(
        self,
        name: str,
    ) -> Optional[NetworkInterface]:
        """Procura uma interface pelo nome."""

        if not isinstance(name, str) or not name.strip():
            return None

        normalized = name.strip().casefold()

        return next(
            (
                interface
                for interface in self.get_interfaces()
                if interface.name.casefold() == normalized
            ),
            None,
        )

    def get_active_interfaces(self) -> list[NetworkInterface]:
        """Devolve apenas interfaces que o sistema indica como ativas."""

        return [
            interface
            for interface in self.get_interfaces()
            if interface.is_up
        ]

    def get_status(self) -> dict[str, Any]:
        """Devolve um resumo do estado do gestor."""

        interfaces = self.get_interfaces()

        return {
            "available": bool(interfaces),
            "total_interfaces": len(interfaces),
            "active_interfaces": sum(
                1 for item in interfaces if item.is_up
            ),
            "psutil_available": psutil is not None,
            "interfaces": [
                item.to_dict() for item in interfaces
            ],
        }


# Compatibilidade com nomes alternativos.

# Compatibilidade com nomes utilizados noutros módulos.
NetworkInterfaces = NetworkInterfaceManager
InterfaceManager = NetworkInterfaceManager

__all__ = [
    "InterfaceAddress",
    "NetworkInterface",
    "NetworkInterfaceManager",
    "NetworkInterfaces",
    "InterfaceManager",
]
