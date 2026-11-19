
"""
NETSHADOW - TCP Audit

Registo e análise passiva de resultados de auditorias TCP.
Não estabelece ligações nem executa varrimentos.
"""

from __future__ import annotations

import ipaddress
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
from threading import RLock
from typing import Any, Optional


class TCPAuditError(ValueError):
    """Erro base do módulo TCP Audit."""


class TCPPortState(str, Enum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class TCPAuditResult:
    target: str
    port: int
    state: TCPPortState
    timestamp: str
    service: Optional[str] = None
    source: str = "external_authorized_audit"

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["state"] = self.state.value
        return data


class TCPAudit:
    """Armazena e analisa resultados de auditorias TCP autorizadas."""

    MIN_PORT = 1
    MAX_PORT = 65535

    def __init__(self) -> None:
        self._results: list[TCPAuditResult] = []
        self._lock = RLock()

    @staticmethod
    def validate_target(target: str) -> str:
        if not isinstance(target, str):
            raise TCPAuditError("O destino tem de ser texto.")

        try:
            return str(ipaddress.ip_address(target.strip()))
        except ValueError as exc:
            raise TCPAuditError("Endereço IP inválido.") from exc

    @classmethod
    def validate_port(cls, port: int) -> int:
        if isinstance(port, bool) or not isinstance(port, int):
            raise TCPAuditError("A porta tem de ser um número inteiro.")

        if not cls.MIN_PORT <= port <= cls.MAX_PORT:
            raise TCPAuditError("A porta tem de estar entre 1 e 65535.")

        return port

    @staticmethod
    def _validate_service(service: Optional[str]) -> Optional[str]:
        if service is None:
            return None

        if not isinstance(service, str):
            raise TCPAuditError("O serviço tem de ser texto.")

        service = service.strip()

        if len(service) > 100:
            raise TCPAuditError("Nome do serviço demasiado longo.")

        return service or None

    def record_result(
        self,
        target: str,
        port: int,
        state: TCPPortState | str,
        service: Optional[str] = None,
        authorized: bool = False,
        source: str = "external_authorized_audit",
    ) -> TCPAuditResult:
        """Regista um resultado recebido de uma auditoria autorizada."""

        if authorized is not True:
            raise TCPAuditError(
                "É necessária autorização explícita para registar a auditoria."
            )

        target = self.validate_target(target)
        port = self.validate_port(port)
        service = self._validate_service(service)

        try:
            state = TCPPortState(state)
        except ValueError as exc:
            raise TCPAuditError("Estado TCP inválido.") from exc

        if not isinstance(source, str) or not source.strip():
            raise TCPAuditError("A origem do resultado é obrigatória.")

        result = TCPAuditResult(
            target=target,
            port=port,
            state=state,
            timestamp=datetime.now(timezone.utc).isoformat(),
            service=service,
            source=source.strip(),
        )

        with self._lock:
            self._results.append(result)

        return result

    def get_results(
        self,
        target: Optional[str] = None,
        state: Optional[TCPPortState | str] = None,
    ) -> list[TCPAuditResult]:
        with self._lock:
            results = list(self._results)

        if target is not None:
            target = self.validate_target(target)
            results = [
                item for item in results
                if item.target == target
            ]

        if state is not None:
            try:
                state = TCPPortState(state)
            except ValueError as exc:
                raise TCPAuditError("Estado TCP inválido.") from exc

            results = [
                item for item in results
                if item.state == state
            ]

        return results

    def get_summary(self) -> dict[str, Any]:
        with self._lock:
            results = list(self._results)

        counts = {
            state.value: sum(
                result.state == state for result in results
            )
            for state in TCPPortState
        }

        return {
            "total": len(results),
            "states": counts,
            "unique_targets": len({
                result.target for result in results
            }),
            "unique_ports": len({
                result.port for result in results
            }),
        }

    def clear_results(self) -> None:
        with self._lock:
            self._results.clear()

    def get_status(self) -> dict[str, Any]:
        return {
            "available": True,
            "mode": "passive_result_analysis",
            "active_connections": False,
            "recorded_results": len(self._results),
        }


# Aliases de compatibilidade.
TCPAuditEngine = TCPAudit
TCPPortAudit = TCPAudit
PortState = TCPPortState

__all__ = [
    "TCPAuditError",
    "TCPPortState",
    "PortState",
    "TCPAuditResult",
    "TCPAudit",
    "TCPAuditEngine",
    "TCPPortAudit",
]
