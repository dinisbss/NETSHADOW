
"""
NETSHADOW - Network Information Manager

Centraliza informação de rede obtida localmente.
Não realiza scans nem envia pacotes.
"""

from __future__ import annotations

import ipaddress
import platform
import socket
from datetime import datetime, timezone
from typing import Any, Optional

from engines.network_engine.interfaces import (
    NetworkInterfaceManager,
)
from engines.network_engine.gateway import (
    GatewayManager,
)
from engines.network_engine.subnet import (
    SubnetManager,
)


class NetworkInfoError(RuntimeError):
    """Erro base do gestor de informação de rede."""


class NetworkInfoManager:
    """Reúne informação local sobre a configuração de rede."""

    def __init__(self) -> None:
        self.interfaces = NetworkInterfaceManager()
        self.gateways = GatewayManager()
        self.subnets = SubnetManager()

    @staticmethod
    def get_hostname() -> str:
        """Obtém o nome do computador."""

        try:
            return socket.gethostname()
        except OSError:
            return "unknown"

    @staticmethod
    def get_fqdn() -> str:
        """Obtém o nome de domínio completo, se disponível."""

        try:
            return socket.getfqdn()
        except OSError:
            return "unknown"

    @staticmethod
    def _get_local_addresses() -> list[str]:
        """Obtém endereços locais sem realizar descoberta remota."""

        addresses: set[str] = set()

        try:
            hostname = socket.gethostname()
            records = socket.getaddrinfo(
                hostname,
                None,
                type=socket.SOCK_STREAM,
            )

            for record in records:
                address = record[4][0].split("%")[0]

                try:
                    parsed = ipaddress.ip_address(address)
                except ValueError:
                    continue

                if parsed.is_loopback or parsed.is_unspecified:
                    continue

                addresses.add(str(parsed))

        except OSError:
            pass

        return sorted(
            addresses,
            key=lambda item: (
                ipaddress.ip_address(item).version,
                int(ipaddress.ip_address(item)),
            ),
        )

    def get_interface_summary(self) -> dict[str, Any]:
        """Obtém um resumo das interfaces."""

        interfaces = self.interfaces.get_interfaces()

        return {
            "total": len(interfaces),
            "active": sum(
                1 for item in interfaces if item.is_up
            ),
            "interfaces": [
                item.to_dict() for item in interfaces
            ],
        }

    def get_gateway_summary(self) -> dict[str, Any]:
        """Obtém as gateways disponíveis."""

        gateways = self.gateways.get_gateways()

        return {
            "total": len(gateways),
            "ipv4": [
                item.to_dict()
                for item in gateways
                if item.family == "IPv4"
            ],
            "ipv6": [
                item.to_dict()
                for item in gateways
                if item.family == "IPv6"
            ],
        }

    def get_address_summary(self) -> dict[str, Any]:
        """Organiza os endereços locais por versão IP."""

        addresses = self._get_local_addresses()

        return {
            "ipv4": [
                address
                for address in addresses
                if ipaddress.ip_address(address).version == 4
            ],
            "ipv6": [
                address
                for address in addresses
                if ipaddress.ip_address(address).version == 6
            ],
        }

    def analyze_network(
        self,
        network: str,
    ) -> dict[str, Any]:
        """Analisa uma subnet indicada pelo utilizador."""

        try:
            result = self.subnets.analyze(network)
        except (ValueError, RuntimeError) as exc:
            raise NetworkInfoError(
                f"Não foi possível analisar a rede: {exc}"
            ) from exc

        return result.to_dict()

    def get_network_info(self) -> dict[str, Any]:
        """Obtém o relatório completo da configuração local."""

        interface_summary = self.get_interface_summary()
        gateway_summary = self.get_gateway_summary()
        address_summary = self.get_address_summary()

        return {
            "hostname": self.get_hostname(),
            "fqdn": self.get_fqdn(),
            "platform": platform.system(),
            "architecture": platform.machine(),
            "timestamp": datetime.now(
                timezone.utc
            ).isoformat(),
            "addresses": address_summary,
            "interfaces": interface_summary,
            "gateways": gateway_summary,
            "status": {
                "has_interfaces": (
                    interface_summary["total"] > 0
                ),
                "has_active_interfaces": (
                    interface_summary["active"] > 0
                ),
                "has_gateway": gateway_summary["total"] > 0,
                "has_ipv4": bool(address_summary["ipv4"]),
                "has_ipv6": bool(address_summary["ipv6"]),
            },
        }

    def get_status(self) -> dict[str, Any]:
        """Devolve o estado do gestor."""

        return {
            "available": True,
            "hostname": self.get_hostname(),
            "platform": platform.system(),
            "components": {
                "interfaces": True,
                "gateways": True,
                "subnets": True,
            },
        }


# Compatibilidade com nomes alternativos.

# Compatibilidade com nomes utilizados noutros módulos.
NetworkInfo = NetworkInfoManager
NetworkInformation = NetworkInfoManager
NetworkInfoCollector = NetworkInfoManager

__all__ = [
    "NetworkInfoError",
    "NetworkInfoManager",
    "NetworkInfo",
    "NetworkInformation",
    "NetworkInfoCollector",
]

