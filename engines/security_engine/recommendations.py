
"""
NETSHADOW - Security Recommendations

Geração de recomendações defensivas a partir de findings
e avaliações de risco existentes.

Não executa alterações nos sistemas analisados.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
from threading import RLock
from typing import Any, Optional
from uuid import uuid4


class RecommendationError(ValueError):
    """Erro base do sistema de recomendações."""


class RecommendationPriority(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class SecurityRecommendation:
    recommendation_id: str
    target: str
    title: str
    description: str
    action: str
    priority: RecommendationPriority
    source_finding: Optional[str]
    category: str
    created_at: str

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["priority"] = self.priority.value
        return result


class SecurityRecommendations:
    """Gera, organiza e consulta recomendações defensivas."""

    PRIORITY_MAP = {
        "info": RecommendationPriority.LOW,
        "low": RecommendationPriority.LOW,
        "medium": RecommendationPriority.MEDIUM,
        "high": RecommendationPriority.HIGH,
        "critical": RecommendationPriority.CRITICAL,
    }

    RULES = {
        "SERVICE_TELNET": {
            "title": "Rever utilização de Telnet",
            "description": (
                "Foi identificado um serviço Telnet. "
                "Este protocolo não protege adequadamente "
                "as comunicações."
            ),
            "action": (
                "Avalia a necessidade do serviço e considera "
                "substituí-lo por uma alternativa cifrada."
            ),
            "category": "network_service",
        },
        "SERVICE_FTP": {
            "title": "Rever utilização de FTP",
            "description": (
                "Foi identificado FTP, que pode transmitir "
                "informação sem cifragem."
            ),
            "action": (
                "Considera uma alternativa com transferência cifrada."
            ),
            "category": "network_service",
        },
        "TLS_LEGACY_VERSION": {
            "title": "Atualizar configuração TLS",
            "description": (
                "Foi identificada uma versão TLS antiga."
            ),
            "action": (
                "Avalia a compatibilidade e configura TLS 1.2 "
                "ou TLS 1.3."
            ),
            "category": "encryption",
        },
        "TLS_INVALID_CERTIFICATE": {
            "title": "Verificar certificado TLS",
            "description": (
                "O certificado foi identificado como inválido."
            ),
            "action": (
                "Confirma a validade, a cadeia de confiança "
                "e a configuração do certificado."
            ),
            "category": "certificate",
        },
        "TLS_HOSTNAME_MISMATCH": {
            "title": "Corrigir correspondência do certificado",
            "description": (
                "O hostname não corresponde ao certificado."
            ),
            "action": (
                "Confirma o nome do serviço e o certificado "
                "associado."
            ),
            "category": "certificate",
        },
        "DEVICE_INVALID_IP": {
            "title": "Corrigir dados de inventário",
            "description": (
                "Foi encontrado um endereço IP inválido "
                "nos metadados."
            ),
            "action": (
                "Confirma o endereço e atualiza o inventário."
            ),
            "category": "asset_inventory",
        },
        "DEVICE_NO_HOSTNAME": {
            "title": "Completar identificação do dispositivo",
            "description": (
                "O hostname do dispositivo é desconhecido."
            ),
            "action": (
                "Atualiza o inventário com um hostname verificado."
            ),
            "category": "asset_inventory",
        },
        "DEVICE_NO_OS": {
            "title": "Identificar sistema operativo",
            "description": (
                "Não existe informação confirmada sobre "
                "o sistema operativo."
            ),
            "action": (
                "Completa o inventário com informação "
                "fornecida por uma fonte autorizada."
            ),
            "category": "asset_inventory",
        },
    }

    def __init__(self) -> None:
        self._recommendations: dict[
            str, SecurityRecommendation
        ] = {}
        self._lock = RLock()

    @staticmethod
    def _validate_target(target: str) -> str:
        if not isinstance(target, str):
            raise RecommendationError(
                "O destino tem de ser texto."
            )

        target = target.strip()

        if not target or len(target) > 253:
            raise RecommendationError(
                "Destino inválido."
            )

        if any(ord(char) < 32 for char in target):
            raise RecommendationError(
                "Destino contém caracteres inválidos."
            )

        return target

    @staticmethod
    def _normalize_finding(finding: Any) -> dict[str, Any]:
        if hasattr(finding, "to_dict"):
            finding = finding.to_dict()
        elif hasattr(finding, "__dataclass_fields__"):
            finding = asdict(finding)

        if not isinstance(finding, dict):
            raise RecommendationError(
                "Finding inválido."
            )

        check_id = finding.get("check_id", "")

        if not isinstance(check_id, str):
            raise RecommendationError(
                "Identificador de finding inválido."
            )

        severity = finding.get("severity", "medium")

        if isinstance(severity, Enum):
            severity = severity.value

        if not isinstance(severity, str):
            raise RecommendationError(
                "Gravidade inválida."
            )

        severity = severity.lower().strip()

        if severity not in SecurityRecommendations.PRIORITY_MAP:
            raise RecommendationError(
                "Gravidade desconhecida."
            )

        return {
            **finding,
            "check_id": check_id.strip().upper(),
            "severity": severity,
        }

    def _create_recommendation(
        self,
        target: str,
        rule: dict[str, str],
        priority: RecommendationPriority,
        source_finding: Optional[str],
    ) -> SecurityRecommendation:
        recommendation = SecurityRecommendation(
            recommendation_id=str(uuid4()),
            target=target,
            title=rule["title"],
            description=rule["description"],
            action=rule["action"],
            priority=priority,
            source_finding=source_finding,
            category=rule["category"],
            created_at=datetime.now(timezone.utc).isoformat(),
        )

        with self._lock:
            self._recommendations[
                recommendation.recommendation_id
            ] = recommendation

        return recommendation

    def generate_from_finding(
        self,
        target: str,
        finding: Any,
    ) -> Optional[SecurityRecommendation]:
        """Gera uma recomendação para um finding conhecido."""

        target = self._validate_target(target)
        normalized = self._normalize_finding(finding)

        check_id = normalized["check_id"]
        rule = self.RULES.get(check_id)

        if rule is None:
            return None

        priority = self.PRIORITY_MAP[
            normalized["severity"]
        ]

        source_id = normalized.get("finding_id")

        if source_id is not None and not isinstance(source_id, str):
            source_id = str(source_id)

        return self._create_recommendation(
            target=target,
            rule=rule,
            priority=priority,
            source_finding=source_id,
        )

    def generate_from_findings(
        self,
        target: str,
        findings: list[Any],
    ) -> list[SecurityRecommendation]:
        if not isinstance(findings, list):
            raise RecommendationError(
                "findings tem de ser uma lista."
            )

        if len(findings) > 10000:
            raise RecommendationError(
                "Demasiados findings."
            )

        results = []

        for finding in findings:
            recommendation = self.generate_from_finding(
                target,
                finding,
            )

            if recommendation is not None:
                results.append(recommendation)

        return results

    def get_recommendation(
        self,
        recommendation_id: str,
    ) -> Optional[SecurityRecommendation]:
        with self._lock:
            return self._recommendations.get(recommendation_id)

    def get_all(
        self,
        target: Optional[str] = None,
        priority: Optional[RecommendationPriority] = None,
    ) -> list[SecurityRecommendation]:
        with self._lock:
            results = list(self._recommendations.values())

        if target is not None:
            target = self._validate_target(target)
            results = [
                item for item in results
                if item.target == target
            ]

        if priority is not None:
            if isinstance(priority, str):
                try:
                    priority = RecommendationPriority(priority.lower())
                except ValueError as exc:
                    raise RecommendationError(
                        "Prioridade inválida."
                    ) from exc

            results = [
                item for item in results
                if item.priority == priority
            ]

        return sorted(
            results,
            key=lambda item: list(
                RecommendationPriority
            ).index(item.priority),
            reverse=True,
        )

    def delete(self, recommendation_id: str) -> bool:
        with self._lock:
            return self._recommendations.pop(
                recommendation_id,
                None,
            ) is not None

    def clear(self) -> None:
        with self._lock:
            self._recommendations.clear()

    def get_summary(self) -> dict[str, Any]:
        with self._lock:
            items = list(self._recommendations.values())

        priorities = {
            priority.value: sum(
                item.priority == priority
                for item in items
            )
            for priority in RecommendationPriority
        }

        categories: dict[str, int] = {}

        for item in items:
            categories[item.category] = (
                categories.get(item.category, 0) + 1
            )

        return {
            "total_recommendations": len(items),
            "priorities": priorities,
            "categories": categories,
        }

    def get_status(self) -> dict[str, Any]:
        with self._lock:
            total = len(self._recommendations)

        return {
            "available": True,
            "mode": "defensive_recommendations",
            "automatic_changes": False,
            "total_recommendations": total,
        }




RecommendationEngine = SecurityRecommendations
SecurityRecommendationEngine = SecurityRecommendations
Recommendations = SecurityRecommendations

__all__ = [
    "RecommendationError",
    "RecommendationPriority",
    "SecurityRecommendation",
    "SecurityRecommendations",
    "RecommendationEngine",
    "SecurityRecommendationEngine",
    "Recommendations",
]
