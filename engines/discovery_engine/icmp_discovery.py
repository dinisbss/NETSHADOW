
"""
NETSHADOW - ICMP Discovery

Validação e gestão de resultados ICMP.
Não envia pacotes nem executa sondagens automaticamente.
"""

from __future__ import annotations

import ipaddress
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


class ICMPError(RuntimeError):
    """Erro base do módulo ICMP."""


class ICMPStatus(str, Enum):
    REACHABLE = "reachable"
    UNREACHABLE = "unreachable"
    TIMEOUT = "timeout"
    ERROR = "error"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class ICMPResult:
    """Resultado de uma verificação ICMP."""

    address: str
    status: ICMPStatus
    latency_ms: Optional[float] = None
    timestamp: str = ""
    message: Optional[str] = None

    @property
    def is_reachable(self) -> bool:
        return self.status == ICMPStatus.REACHABLE

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        return data


class ICMPDiscovery:
    """Valida e gere resultados de verificações ICMP."""

    def __init__(self) -> None:
        self._results: list[ICMPResult] = []

    @staticmethod
    def validate_address(address: str) -> str:
        """Valida e normaliza um endereço IP."""

        if not isinstance(address, str) or not address.strip():
            raise ValueError("Endereço IP inválido.")

        try:
            return str(ipaddress.ip_address(address.strip()))
        except ValueError as exc:
            raise ValueError(
                f"Endereço IP inválido: {address}"
            ) from exc

    def record_result(
        self,
        address: str,
        status: ICMPStatus | str,
        latency_ms: Optional[float] = None,
        message: Optional[str] = None,
    ) -> ICMPResult:
        """Regista um resultado recebido de uma fonte externa."""

        normalized_address = self.validate_address(address)

        try:
            normalized_status = ICMPStatus(status)
        except ValueError as exc:
            raise ValueError("Estado ICMP inválido.") from exc

        if latency_ms is not None:
            if (
                isinstance(latency_ms, bool)
                or not isinstance(latency_ms, (int, float))
                or latency_ms < 0
            ):
                raise ValueError("Latência inválida.")

            latency_ms = float(latency_ms)

        if message is not None and not isinstance(message, str):
            raise ValueError("message tem de ser texto.")

        result = ICMPResult(
            address=normalized_address,
            status=normalized_status,
            latency_ms=latency_ms,
            timestamp=datetime.now(
                timezone.utc
            ).isoformat(),
            message=message,
        )

        self._results.append(result)
        return result

    def get_results(self) -> list[ICMPResult]:
        """Devolve os resultados registados."""

        return list(self._results)

    def get_results_by_status(
        self,
        status: ICMPStatus | str,
    ) -> list[ICMPResult]:
        """Filtra resultados pelo estado."""

        normalized_status = ICMPStatus(status)

        return [
            result
            for result in self._results
            if result.status == normalized_status
        ]

    def clear_results(self) -> None:
        """Limpa os resultados em memória."""

        self._results.clear()

    def get_summary(self) -> dict[str, Any]:
        """Calcula estatísticas dos resultados registados."""

        total = len(self._results)

        reachable = sum(
            result.is_reachable
            for result in self._results
        )

        latencies = [
            result.latency_ms
            for result in self._results
            if result.latency_ms is not None
        ]

        return {
            "total": total,
            "reachable": reachable,
            "unreachable": total - reachable,
            "average_latency_ms": (
                sum(latencies) / len(latencies)
                if latencies else None
            ),
            "results": [
                result.to_dict()
                for result in self._results
            ],
        }

    def get_status(self) -> dict[str, Any]:
        return {
            "available": True,
            "active_probing": False,
            "recorded_results": len(self._results),
            "supported_versions": [4, 6],
        }


# Compatibilidade com nomes alternativos.
ICMPDiscoveryEngine = ICMPDiscovery
ICMPDiscoveryManager = ICMPDiscovery

__all__ = [
    "ICMPError",
    "ICMPStatus",
    "ICMPResult",
    "ICMPDiscovery",
    "ICMPDiscoveryEngine",
    "ICMPDiscoveryManager",
]
