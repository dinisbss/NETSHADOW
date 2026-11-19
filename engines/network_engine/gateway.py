
"""
NETSHADOW - Gateway Manager

Identificação local das gateways predefinidas.
Não altera rotas nem envia tráfego de rede.
"""

from __future__ import annotations

import ipaddress
import platform
import re
import subprocess
from dataclasses import asdict, dataclass
from typing import Any, Optional


try:
    import psutil
except ImportError:
    psutil = None


class GatewayError(RuntimeError):
    """Erro base do gestor de gateways."""


@dataclass(frozen=True)
class GatewayInfo:
    """Informação de uma gateway predefinida."""

    address: str
    interface: Optional[str] = None
    family: str = "IPv4"
    source: str = "system"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class GatewayManager:
    """Consulta as gateways configuradas no sistema local."""

    def __init__(self, timeout: float = 3.0) -> None:
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or timeout <= 0
        ):
            raise ValueError("timeout tem de ser positivo.")

        self.timeout = float(timeout)
        self._gateways: list[GatewayInfo] = []

    @staticmethod
    def _validate_address(address: str) -> Optional[str]:
        try:
            return str(ipaddress.ip_address(address.strip()))
        except (ValueError, AttributeError):
            return None

    def _from_psutil(self) -> list[GatewayInfo]:
        """Obtém gateways através da biblioteca psutil."""

        if psutil is None:
            return []

        try:
            gateways = psutil.net_if_addrs()
            del gateways  # Não é necessário consultar endereços aqui.

            stats = psutil.net_if_stats()
            del stats

            route_data = psutil.net_if_addrs()
            del route_data

            # psutil não disponibiliza diretamente a tabela de rotas.
            # A leitura é feita pelo mecanismo nativo do sistema.
            return []

        except (OSError, RuntimeError):
            return []

    def _run_readonly_command(
        self,
        arguments: list[str],
    ) -> Optional[str]:
        """Executa apenas comandos locais de consulta."""

        try:
            result = subprocess.run(
                arguments,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
                shell=False,
            )
        except (
            OSError,
            subprocess.SubprocessError,
        ):
            return None

        if result.returncode != 0:
            return None

        return result.stdout

    def _parse_windows(self) -> list[GatewayInfo]:
        """Lê a configuração de rotas IPv4 do Windows."""

        output = self._run_readonly_command(
            ["route", "print", "-4"]
        )

        if not output:
            return []

        result = []

        for line in output.splitlines():
            parts = line.split()

            if len(parts) < 5:
                continue

            if parts[0] != "0.0.0.0":
                continue

            if parts[1] != "0.0.0.0":
                continue

            gateway = self._validate_address(parts[2])

            if gateway is None or gateway == "0.0.0.0":
                continue

            result.append(
                GatewayInfo(
                    address=gateway,
                    interface=parts[3],
                    family="IPv4",
                    source="windows_route",
                )
            )

        return result

    def _parse_linux(self) -> list[GatewayInfo]:
        """Lê gateways através do comando ip route."""

        output = self._run_readonly_command(
            ["ip", "route", "show", "default"]
        )

        if not output:
            return []

        result = []

        for line in output.splitlines():
            parts = line.split()

            if not parts or parts[0] != "default":
                continue

            gateway = None
            interface = None

            for index, part in enumerate(parts[:-1]):
                if part == "via":
                    gateway = parts[index + 1]
                elif part == "dev":
                    interface = parts[index + 1]

            if gateway is None:
                continue

            gateway = self._validate_address(gateway)

            if gateway is None:
                continue

            family = (
                "IPv6"
                if ipaddress.ip_address(gateway).version == 6
                else "IPv4"
            )

            result.append(
                GatewayInfo(
                    address=gateway,
                    interface=interface,
                    family=family,
                    source="linux_ip_route",
                )
            )

        return result

    def _parse_macos(self) -> list[GatewayInfo]:
        """Lê a gateway IPv4 no macOS."""

        output = self._run_readonly_command(
            ["route", "-n", "get", "default"]
        )

        if not output:
            return []

        for line in output.splitlines():
            match = re.match(
                r"\s*gateway:\s*(\S+)",
                line,
                re.IGNORECASE,
            )

            if match:
                gateway = self._validate_address(match.group(1))

                if gateway:
                    return [
                        GatewayInfo(
                            address=gateway,
                            family="IPv4",
                            source="macos_route",
                        )
                    ]

        return []

    def get_gateways(
        self,
        refresh: bool = True,
    ) -> list[GatewayInfo]:
        """Devolve as gateways configuradas no sistema."""

        if not refresh and self._gateways:
            return list(self._gateways)

        system = platform.system().lower()

        if system == "windows":
            gateways = self._parse_windows()
        elif system == "linux":
            gateways = self._parse_linux()
        elif system == "darwin":
            gateways = self._parse_macos()
        else:
            gateways = []

        self._gateways = gateways
        return list(self._gateways)

    def get_default_gateway(
        self,
        family: str = "IPv4",
    ) -> Optional[GatewayInfo]:
        """Obtém a primeira gateway da família indicada."""

        normalized = family.upper()

        if normalized not in ("IPV4", "IPV6"):
            raise ValueError("A família deve ser IPv4 ou IPv6.")

        expected = normalized.title()

        return next(
            (
                gateway
                for gateway in self.get_gateways()
                if gateway.family == expected
            ),
            None,
        )

    def get_status(self) -> dict[str, Any]:
        gateways = self.get_gateways()

        return {
            "available": bool(gateways),
            "system": platform.system(),
            "psutil_available": psutil is not None,
            "total_gateways": len(gateways),
            "gateways": [
                gateway.to_dict()
                for gateway in gateways
            ],
        }


# Compatibilidade com nomes alternativos.

# Compatibilidade com nomes utilizados noutros módulos.
DefaultGatewayManager = GatewayManager
GatewayDetector = GatewayManager

__all__ = [
    "GatewayError",
    "GatewayInfo",
    "GatewayManager",
    "DefaultGatewayManager",
    "GatewayDetector",
]
