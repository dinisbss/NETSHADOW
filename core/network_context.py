
"""
NETSHADOW - Network Context Manager

Gere o contexto da rede ou dispositivo selecionado.
Não executa operações de rede.
"""

from __future__ import annotations

import ipaddress
import threading

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional


class NetworkContextError(ValueError):
    """Erro relacionado com o contexto de rede."""


@dataclass(frozen=True)
class NetworkContext:
    """Representa o contexto atualmente selecionado."""

    target: str
    is_network: bool
    selected_at: datetime
    version: int = 1

    @property
    def is_device(self) -> bool:
        return not self.is_network

    @property
    def network(self) -> Optional[str]:
        return self.target if self.is_network else None

    @property
    def device(self) -> Optional[str]:
        return None if self.is_network else self.target

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "is_network": self.is_network,
            "is_device": self.is_device,
            "selected_at": self.selected_at.isoformat(),
            "version": self.version,
        }


class NetworkContextManager:
    """Gere o contexto de rede da aplicação."""

    def __init__(self) -> None:
        self._context: Optional[NetworkContext] = None
        self._lock = threading.RLock()

    @staticmethod
    def _validate_target(target: str) -> str:
        if not isinstance(target, str):
            raise NetworkContextError("O alvo tem de ser texto.")

        target = target.strip()

        if not target:
            raise NetworkContextError("O alvo não pode estar vazio.")

        if len(target) > 253:
            raise NetworkContextError("O alvo excede o tamanho permitido.")

        return target

    @staticmethod
    def _parse_network(target: str):
        try:
            return ipaddress.ip_network(target, strict=False)
        except ValueError:
            return None

    @staticmethod
    def _parse_ip(target: str):
        try:
            return ipaddress.ip_address(target)
        except ValueError:
            return None

    def select_network(self, target: str) -> NetworkContext:
        """Seleciona uma rede IPv4 ou IPv6."""

        target = self._validate_target(target)
        network = self._parse_network(target)

        if network is None:
            raise NetworkContextError(
                "O alvo indicado não é uma rede IPv4 ou IPv6 válida."
            )

        with self._lock:
            self._context = NetworkContext(
                target=str(network),
                is_network=True,
                selected_at=datetime.now(timezone.utc),
            )

            return self._context

    def select_device(self, target: str) -> NetworkContext:
        """Seleciona um dispositivo através do seu endereço IP."""

        target = self._validate_target(target)
        address = self._parse_ip(target)

        if address is None:
            raise NetworkContextError(
                "O dispositivo tem de possuir um endereço IP válido."
            )

        with self._lock:
            self._context = NetworkContext(
                target=str(address),
                is_network=False,
                selected_at=datetime.now(timezone.utc),
            )

            return self._context

    def set_context(
        self,
        target: str,
        is_network: bool = True,
    ) -> NetworkContext:
        """Define o contexto através do tipo indicado."""

        if not isinstance(is_network, bool):
            raise NetworkContextError(
                "is_network tem de ser True ou False."
            )

        if is_network:
            return self.select_network(target)

        return self.select_device(target)

    def get_context(self) -> Optional[NetworkContext]:
        """Devolve o contexto atual."""

        with self._lock:
            return self._context

    def has_context(self) -> bool:
        """Indica se existe um contexto selecionado."""

        with self._lock:
            return self._context is not None

    def clear_context(self) -> None:
        """Remove o contexto atual."""

        with self._lock:
            self._context = None

    def get_status(self) -> dict:
        """Devolve o estado atual do gestor."""

        with self._lock:
            if self._context is None:
                return {
                    "active": False,
                    "context": None,
                }

            return {
                "active": True,
                "context": self._context.to_dict(),
            }


# Compatibilidade com nomes alternativos.
NetworkContextType = NetworkContext
