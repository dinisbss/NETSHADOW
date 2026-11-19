
"""
NETSHADOW - ARP Discovery

Consulta exclusivamente a tabela ARP local do sistema.
Não envia pacotes ARP nem realiza descoberta ativa.
"""

from __future__ import annotations

import ipaddress
import platform
import re
import subprocess
from dataclasses import asdict, dataclass
from typing import Any, Optional


class ARPDiscoveryError(RuntimeError):
    """Erro base da consulta ARP."""


@dataclass(frozen=True)
class ARPEntry:
    """Representa uma entrada encontrada na tabela ARP."""

    ip_address: str
    mac_address: str
    interface: Optional[str] = None
    entry_type: Optional[str] = None
    source: str = "local_arp_table"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ARPDiscovery:
    """Consulta a tabela ARP existente no computador local."""

    def __init__(self, timeout: float = 3.0) -> None:
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or timeout <= 0
        ):
            raise ValueError("timeout tem de ser positivo.")

        self.timeout = float(timeout)
        self._entries: list[ARPEntry] = []

    @staticmethod
    def _validate_ip(value: str) -> Optional[str]:
        try:
            address = ipaddress.ip_address(value.strip())

            if address.version != 4:
                return None

            return str(address)

        except ValueError:
            return None

    @staticmethod
    def _validate_mac(value: str) -> Optional[str]:
        normalized = value.strip().replace("-", ":").upper()

        if not re.fullmatch(
            r"(?:[0-9A-F]{2}:){5}[0-9A-F]{2}",
            normalized,
        ):
            return None

        return normalized

    def _run_command(self, arguments: list[str]) -> Optional[str]:
        """Executa um comando local de leitura, sem shell."""

        try:
            result = subprocess.run(
                arguments,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
                shell=False,
            )
        except (OSError, subprocess.SubprocessError):
            return None

        if result.returncode != 0:
            return None

        return result.stdout

    def _parse_windows(self, output: str) -> list[ARPEntry]:
        entries = []

        for line in output.splitlines():
            parts = line.split()

            if len(parts) < 3:
                continue

            ip_address = self._validate_ip(parts[0])
            mac_address = self._validate_mac(parts[1])

            if ip_address is None or mac_address is None:
                continue

            entry_type = parts[2].lower()

            entries.append(
                ARPEntry(
                    ip_address=ip_address,
                    mac_address=mac_address,
                    entry_type=entry_type,
                )
            )

        return entries

    def _parse_linux(self, output: str) -> list[ARPEntry]:
        entries = []

        for line in output.splitlines():
            parts = line.split()

            if not parts:
                continue

            ip_address = self._validate_ip(parts[0])

            if ip_address is None:
                continue

            mac_match = re.search(
                r"\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b",
                line,
            )

            if not mac_match:
                continue

            mac_address = self._validate_mac(mac_match.group(0))

            if mac_address is None:
                continue

            interface = None

            dev_match = re.search(
                r"\bdev\s+(\S+)",
                line,
            )

            if dev_match:
                interface = dev_match.group(1)

            entries.append(
                ARPEntry(
                    ip_address=ip_address,
                    mac_address=mac_address,
                    interface=interface,
                )
            )

        return entries

    def get_entries(
        self,
        refresh: bool = True,
    ) -> list[ARPEntry]:
        """Consulta e devolve as entradas ARP locais."""

        if not refresh and self._entries:
            return list(self._entries)

        system = platform.system().lower()

        if system == "windows":
            output = self._run_command(
                ["arp", "-a"]
            )

            entries = (
                self._parse_windows(output)
                if output
                else []
            )

        elif system == "linux":
            output = self._run_command(
                ["ip", "-4", "neigh", "show"]
            )

            entries = (
                self._parse_linux(output)
                if output
                else []
            )

        else:
            entries = []

        unique = {
            (
                entry.ip_address,
                entry.mac_address,
                entry.interface,
            ): entry
            for entry in entries
        }

        self._entries = list(unique.values())

        return list(self._entries)

    def get_by_ip(self, ip_address: str) -> Optional[ARPEntry]:
        """Procura uma entrada pelo endereço IPv4."""

        validated = self._validate_ip(ip_address)

        if validated is None:
            raise ValueError("Endereço IPv4 inválido.")

        return next(
            (
                entry
                for entry in self.get_entries()
                if entry.ip_address == validated
            ),
            None,
        )

    def get_status(self) -> dict[str, Any]:
        """Devolve o estado da consulta ARP."""

        entries = self.get_entries()

        return {
            "available": True,
            "platform": platform.system(),
            "total_entries": len(entries),
            "source": "local_arp_table",
            "active_discovery": False,
        }


# Compatibilidade com nomes alternativos.
ARPDiscoveryEngine = ARPDiscovery
ARPDiscoveryManager = ARPDiscovery

__all__ = [
    "ARPDiscoveryError",
    "ARPEntry",
    "ARPDiscovery",
    "ARPDiscoveryEngine",
    "ARPDiscoveryManager",
]
