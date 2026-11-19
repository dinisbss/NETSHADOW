
"""
NETSHADOW - Subnet Manager

Operações locais de validação e análise de subnets IPv4 e IPv6.
Não realiza comunicação de rede.
"""

from __future__ import annotations

import ipaddress
from dataclasses import asdict, dataclass
from typing import Any, Optional, Union


IPAddress = Union[
    ipaddress.IPv4Address,
    ipaddress.IPv6Address,
]

IPNetwork = Union[
    ipaddress.IPv4Network,
    ipaddress.IPv6Network,
]


class SubnetError(ValueError):
    """Erro base das operações de subnet."""


class InvalidSubnetError(SubnetError):
    """Subnet inválida."""


class SubnetTooLargeError(SubnetError):
    """Subnet superior ao limite permitido."""


@dataclass(frozen=True)
class SubnetInfo:
    """Informação calculada sobre uma subnet."""

    network_address: str
    netmask: str
    prefix_length: int
    broadcast_address: Optional[str]
    first_address: Optional[str]
    last_address: Optional[str]
    total_addresses: int
    usable_addresses: int
    ip_version: int
    is_private: bool
    is_global: bool

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class SubnetManager:
    """Valida e analisa redes IP localmente."""

    def __init__(self, max_addresses: int = 65536) -> None:
        if (
            isinstance(max_addresses, bool)
            or not isinstance(max_addresses, int)
            or max_addresses < 1
        ):
            raise ValueError(
                "max_addresses deve ser um inteiro positivo."
            )

        self.max_addresses = max_addresses

    @staticmethod
    def parse_network(
        network: str,
        strict: bool = False,
    ) -> IPNetwork:
        """Converte uma string numa rede IPv4 ou IPv6."""

        if not isinstance(network, str) or not network.strip():
            raise InvalidSubnetError(
                "A rede tem de ser uma string não vazia."
            )

        try:
            return ipaddress.ip_network(
                network.strip(),
                strict=strict,
            )
        except ValueError as exc:
            raise InvalidSubnetError(
                f"Rede inválida: {network}"
            ) from exc

    @staticmethod
    def parse_address(address: str) -> IPAddress:
        """Valida e converte um endereço IP."""

        if not isinstance(address, str) or not address.strip():
            raise ValueError(
                "O endereço IP tem de ser uma string não vazia."
            )

        try:
            return ipaddress.ip_address(address.strip())
        except ValueError as exc:
            raise ValueError(
                f"Endereço IP inválido: {address}"
            ) from exc

    def validate_network(
        self,
        network: str,
        strict: bool = False,
    ) -> bool:
        """Indica se a rede é válida e respeita o limite."""

        parsed = self.parse_network(network, strict)

        if parsed.num_addresses > self.max_addresses:
            raise SubnetTooLargeError(
                "A rede excede o limite de endereços permitido."
            )

        return True

    def analyze(
        self,
        network: str,
        strict: bool = False,
    ) -> SubnetInfo:
        """Calcula informação detalhada sobre uma subnet."""

        parsed = self.parse_network(network, strict)

        if parsed.num_addresses > self.max_addresses:
            raise SubnetTooLargeError(
                "A rede excede o limite de endereços permitido."
            )

        if parsed.version == 4:
            netmask = str(parsed.netmask)
            broadcast = str(parsed.broadcast_address)

            if parsed.prefixlen <= 30:
                first = str(parsed.network_address + 1)
                last = str(parsed.broadcast_address - 1)
                usable = parsed.num_addresses - 2
            elif parsed.prefixlen == 31:
                first = str(parsed.network_address)
                last = str(parsed.broadcast_address)
                usable = 2
            else:
                first = str(parsed.network_address)
                last = str(parsed.network_address)
                usable = 1

        else:
            netmask = str(parsed.netmask)
            broadcast = None
            first = (
                str(parsed.network_address + 1)
                if parsed.num_addresses > 1
                else str(parsed.network_address)
            )
            last = str(parsed[-1])
            usable = max(parsed.num_addresses - 1, 0)

        return SubnetInfo(
            network_address=str(parsed.network_address),
            netmask=netmask,
            prefix_length=parsed.prefixlen,
            broadcast_address=broadcast,
            first_address=first,
            last_address=last,
            total_addresses=parsed.num_addresses,
            usable_addresses=usable,
            ip_version=parsed.version,
            is_private=parsed.is_private,
            is_global=parsed.is_global,
        )

    def contains(
        self,
        network: str,
        address: str,
    ) -> bool:
        """Verifica se um endereço pertence à rede."""

        parsed_network = self.parse_network(network)
        parsed_address = self.parse_address(address)

        if parsed_network.version != parsed_address.version:
            return False

        return parsed_address in parsed_network

    def get_network(
        self,
        address: str,
        prefix_length: int,
    ) -> str:
        """Calcula a rede correspondente a um IP e prefixo."""

        parsed = self.parse_address(address)

        if (
            isinstance(prefix_length, bool)
            or not isinstance(prefix_length, int)
        ):
            raise ValueError("Prefixo inválido.")

        max_prefix = 32 if parsed.version == 4 else 128

        if not 0 <= prefix_length <= max_prefix:
            raise ValueError("Prefixo fora dos limites permitidos.")

        return str(
            ipaddress.ip_network(
                f"{parsed}/{prefix_length}",
                strict=False,
            )
        )

    def get_status(self) -> dict[str, Any]:
        return {
            "available": True,
            "max_addresses": self.max_addresses,
            "supported_versions": [4, 6],
        }


# Compatibilidade com nomes alternativos.
SubnetAnalyzer = SubnetManager

__all__ = [
    "SubnetError",
    "InvalidSubnetError",
    "SubnetTooLargeError",
    "SubnetInfo",
    "SubnetManager",
    "SubnetAnalyzer",
]
