
"""
NETSHADOW - Port States

Centraliza os estados e a interpretação dos resultados
de auditorias TCP e UDP.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional


class PortStateError(ValueError):
    """Erro base dos estados de portas."""


class PortProtocol(str, Enum):
    TCP = "tcp"
    UDP = "udp"


class PortState(str, Enum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    OPEN_FILTERED = "open|filtered"
    CLOSED_FILTERED = "closed|filtered"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class PortStateInfo:
    protocol: PortProtocol
    state: PortState
    description: str
    conclusive: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "protocol": self.protocol.value,
            "state": self.state.value,
            "description": self.description,
            "conclusive": self.conclusive,
        }


class PortStateManager:
    """Valida e interpreta estados TCP e UDP."""

    DESCRIPTIONS = {
        PortState.OPEN: "A porta foi identificada como aberta.",
        PortState.CLOSED: "A porta foi identificada como fechada.",
        PortState.FILTERED: "O estado está condicionado por filtragem.",
        PortState.OPEN_FILTERED: (
            "Não foi possível distinguir entre aberta e filtrada."
        ),
        PortState.CLOSED_FILTERED: (
            "Não foi possível distinguir entre fechada e filtrada."
        ),
        PortState.UNKNOWN: "Não existe informação suficiente.",
    }

    TCP_STATES = {
        PortState.OPEN,
        PortState.CLOSED,
        PortState.FILTERED,
        PortState.UNKNOWN,
    }

    UDP_STATES = {
        PortState.OPEN,
        PortState.CLOSED,
        PortState.FILTERED,
        PortState.OPEN_FILTERED,
        PortState.UNKNOWN,
    }

    def normalize_protocol(
        self,
        protocol: PortProtocol | str,
    ) -> PortProtocol:
        try:
            return PortProtocol(protocol)
        except ValueError as exc:
            raise PortStateError(
                f"Protocolo inválido: {protocol}"
            ) from exc

    def normalize_state(
        self,
        state: PortState | str,
    ) -> PortState:
        try:
            return PortState(state)
        except ValueError as exc:
            raise PortStateError(
                f"Estado de porta inválido: {state}"
            ) from exc

    def get_state_info(
        self,
        protocol: PortProtocol | str,
        state: PortState | str,
    ) -> PortStateInfo:
        protocol = self.normalize_protocol(protocol)
        state = self.normalize_state(state)

        allowed = (
            self.TCP_STATES
            if protocol == PortProtocol.TCP
            else self.UDP_STATES
        )

        if state not in allowed:
            raise PortStateError(
                f"O estado {state.value} não é válido para "
                f"o protocolo {protocol.value.upper()}."
            )

        return PortStateInfo(
            protocol=protocol,
            state=state,
            description=self.DESCRIPTIONS[state],
            conclusive=state in {
                PortState.OPEN,
                PortState.CLOSED,
            },
        )

    def is_open(
        self,
        state: PortState | str,
    ) -> bool:
        return self.normalize_state(state) == PortState.OPEN

    def is_closed(
        self,
        state: PortState | str,
    ) -> bool:
        return self.normalize_state(state) == PortState.CLOSED

    def is_filtered(
        self,
        state: PortState | str,
    ) -> bool:
        return self.normalize_state(state) in {
            PortState.FILTERED,
            PortState.OPEN_FILTERED,
            PortState.CLOSED_FILTERED,
        }

    def is_conclusive(
        self,
        state: PortState | str,
    ) -> bool:
        return self.normalize_state(state) in {
            PortState.OPEN,
            PortState.CLOSED,
        }

    def get_all_states(
        self,
        protocol: Optional[PortProtocol | str] = None,
    ) -> list[PortStateInfo]:
        if protocol is None:
            protocols = list(PortProtocol)
        else:
            protocols = [self.normalize_protocol(protocol)]

        results = []

        for current_protocol in protocols:
            allowed = (
                self.TCP_STATES
                if current_protocol == PortProtocol.TCP
                else self.UDP_STATES
            )

            for state in PortState:
                if state in allowed:
                    results.append(
                        self.get_state_info(
                            current_protocol,
                            state,
                        )
                    )

        return results

    def get_status(self) -> dict[str, Any]:
        return {
            "available": True,
            "supported_protocols": [
                protocol.value for protocol in PortProtocol
            ],
            "supported_states": [
                state.value for state in PortState
            ],
            "active_scanning": False,
        }


# Aliases de compatibilidade.
PortStates = PortStateManager
PortStateAnalyzer = PortStateManager
PortStatus = PortState

__all__ = [
    "PortStateError",
    "PortProtocol",
    "PortState",
    "PortStatus",
    "PortStateInfo",
    "PortStateManager",
    "PortStates",
    "PortStateAnalyzer",
]
