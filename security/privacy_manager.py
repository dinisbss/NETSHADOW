
"""
NETSHADOW - Privacy Manager

Ferramentas de minimização, anonimização e proteção
de dados utilizados pela plataforma.

Este módulo não substitui controlos de acesso, encriptação
ou políticas de retenção aplicadas à base de dados.
"""

from __future__ import annotations

import copy
import ipaddress
import math
import re
import threading
import time

from dataclasses import dataclass, field
from typing import Any, List, Optional, Set


class PrivacyError(Exception):
    """Erro nas operações de privacidade."""


@dataclass
class PrivacyPolicy:
    anonymize_ips: bool = True
    anonymize_macs: bool = True
    redact_sensitive_text: bool = True
    remove_private_fields: bool = True
    retention_seconds: int = 86400

    private_fields: set = field(default_factory=lambda: {
        "password",
        "passwd",
        "secret",
        "token",
        "api_key",
        "authorization",
        "email",
        "phone",
        "personal_data",
    })


class PrivacyManager:
    """Aplica políticas de privacidade aos dados."""

    MAX_EVENTS = 5000
    MAX_TEXT_LENGTH = 100000
    MAX_DEPTH = 20
    MAX_ITEMS = 10000
    MAX_KEY_LENGTH = 256

    SENSITIVE_PATTERNS = [
        (
            re.compile(
                r"""(?i)\b(password|passwd|secret|token|api_key|authorization)"""
                r"""\b\s*[:=]\s*("[^"]*"|'[^']*'|[^\s,;]+)"""
            ),
            r"\1=[REDACTED]",
        ),
        (
            re.compile(
                r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b"
            ),
            "[EMAIL_REDACTED]",
        ),
        (
            re.compile(
                r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+"
            ),
            "Bearer [REDACTED]",
        ),
    ]

    def __init__(
        self,
        policy: Optional[PrivacyPolicy] = None,
    ):
        selected_policy = (
            policy if policy is not None else PrivacyPolicy()
        )

        self._validate_policy(selected_policy)

        # Evita alterações externas à política interna.
        self._policy = self._copy_policy(selected_policy)

        self._events: List[dict] = []
        self._lock = threading.RLock()

    @property
    def policy(self) -> PrivacyPolicy:
        """Devolve uma cópia da política atual."""

        with self._lock:
            return self._copy_policy(self._policy)

    @policy.setter
    def policy(self, policy: PrivacyPolicy) -> None:
        self._validate_policy(policy)

        with self._lock:
            self._policy = self._copy_policy(policy)

    @staticmethod
    def _copy_policy(policy: PrivacyPolicy) -> PrivacyPolicy:
        return PrivacyPolicy(
            anonymize_ips=policy.anonymize_ips,
            anonymize_macs=policy.anonymize_macs,
            redact_sensitive_text=policy.redact_sensitive_text,
            remove_private_fields=policy.remove_private_fields,
            retention_seconds=policy.retention_seconds,
            private_fields={
                item.lower()
                for item in policy.private_fields
            },
        )

    @staticmethod
    def _validate_policy(policy: PrivacyPolicy) -> None:
        if not isinstance(policy, PrivacyPolicy):
            raise PrivacyError(
                "Política de privacidade inválida."
            )

        boolean_fields = (
            "anonymize_ips",
            "anonymize_macs",
            "redact_sensitive_text",
            "remove_private_fields",
        )

        for attribute in boolean_fields:
            if not isinstance(getattr(policy, attribute), bool):
                raise PrivacyError(
                    f"Opção de política inválida: {attribute}."
                )

        if (
            isinstance(policy.retention_seconds, bool)
            or not isinstance(policy.retention_seconds, int)
            or not 60 <= policy.retention_seconds <= 31536000
        ):
            raise PrivacyError(
                "Período de retenção inválido."
            )

        if not isinstance(policy.private_fields, set):
            raise PrivacyError(
                "Campos privados inválidos."
            )

        if len(policy.private_fields) > 256:
            raise PrivacyError(
                "Demasiados campos privados."
            )

        for field_name in policy.private_fields:
            if (
                not isinstance(field_name, str)
                or not field_name
                or len(field_name) > 64
                or any(ord(char) < 32 for char in field_name)
            ):
                raise PrivacyError(
                    "Nome de campo privado inválido."
                )

    def anonymize_ip(self, value: str) -> str:
        if not isinstance(value, str):
            raise PrivacyError(
                "Endereço IP inválido."
            )

        try:
            address = ipaddress.ip_address(value.strip())

            if isinstance(address, ipaddress.IPv4Address):
                network = ipaddress.ip_network(
                    f"{address}/24",
                    strict=False,
                )
            else:
                network = ipaddress.ip_network(
                    f"{address}/48",
                    strict=False,
                )

            return str(network)

        except ValueError as exc:
            raise PrivacyError(
                "Endereço IP inválido."
            ) from exc

    def anonymize_mac(self, value: str) -> str:
        if not isinstance(value, str):
            raise PrivacyError(
                "Endereço MAC inválido."
            )

        normalized = re.sub(
            r"[^0-9a-fA-F]",
            "",
            value,
        )

        if not re.fullmatch(
            r"[0-9a-fA-F]{12}",
            normalized,
        ):
            raise PrivacyError(
                "Endereço MAC inválido."
            )

        # Preserva apenas os primeiros 24 bits.
        return normalized[:6].upper() + ":XX:XX:XX"

    def redact_text(self, text: str) -> str:
        if not isinstance(text, str):
            raise PrivacyError(
                "Texto inválido."
            )

        if len(text) > self.MAX_TEXT_LENGTH:
            raise PrivacyError(
                "Texto demasiado longo."
            )

        result = text

        for pattern, replacement in self.SENSITIVE_PATTERNS:
            result = pattern.sub(replacement, result)

        return result

    def sanitize_data(self, data: Any) -> Any:
        """
        Cria uma cópia sanitizada de estruturas simples.

        Aceita apenas dicionários, listas, tuplos e tipos
        primitivos. Não utiliza pickle nem objetos arbitrários.
        """

        budget = [self.MAX_ITEMS]

        return self._sanitize_data(
            data=data,
            depth=0,
            budget=budget,
        )

    def _sanitize_data(
        self,
        data: Any,
        depth: int,
        budget: List[int],
    ) -> Any:

        if depth > self.MAX_DEPTH:
            raise PrivacyError(
                "Profundidade máxima dos dados excedida."
            )

        budget[0] -= 1

        if budget[0] < 0:
            raise PrivacyError(
                "Limite de elementos dos dados excedido."
            )

        if isinstance(data, dict):
            if len(data) > self.MAX_ITEMS:
                raise PrivacyError(
                    "Dicionário demasiado grande."
                )

            result = {}

            private_fields = self._policy.private_fields

            for key, value in data.items():
                if (
                    not isinstance(key, str)
                    or not key
                    or len(key) > self.MAX_KEY_LENGTH
                    or any(ord(char) < 32 for char in key)
                ):
                    raise PrivacyError(
                        "Chave de dados inválida."
                    )

                if (
                    self._policy.remove_private_fields
                    and key.casefold() in private_fields
                ):
                    continue

                result[key] = self._sanitize_data(
                    value,
                    depth + 1,
                    budget,
                )

            return result

        if isinstance(data, list):
            if len(data) > self.MAX_ITEMS:
                raise PrivacyError(
                    "Lista demasiado grande."
                )

            return [
                self._sanitize_data(
                    item,
                    depth + 1,
                    budget,
                )
                for item in data
            ]

        if isinstance(data, tuple):
            if len(data) > self.MAX_ITEMS:
                raise PrivacyError(
                    "Tuplo demasiado grande."
                )

            return tuple(
                self._sanitize_data(
                    item,
                    depth + 1,
                    budget,
                )
                for item in data
            )

        if isinstance(data, str):
            if len(data) > self.MAX_TEXT_LENGTH:
                raise PrivacyError(
                    "Texto demasiado longo."
                )

            if self._policy.redact_sensitive_text:
                return self.redact_text(data)

            return data

        if isinstance(data, float):
            if not math.isfinite(data):
                raise PrivacyError(
                    "Valor numérico não finito."
                )

            return data

        if isinstance(data, int):
            if data.bit_length() > 4096:
                raise PrivacyError(
                    "Valor inteiro demasiado grande."
                )

            return data

        if data is None or isinstance(data, bool):
            return data

        raise PrivacyError(
            f"Tipo de dados não suportado: {type(data).__name__}"
        )

    def sanitize_network_record(self, record: dict) -> dict:
        if not isinstance(record, dict):
            raise PrivacyError(
                "Registo de rede inválido."
            )

        result = self.sanitize_data(record)

        if self._policy.anonymize_ips:
            for key in ("ip", "ip_address", "address"):
                value = result.get(key)

                if isinstance(value, str):
                    result[key] = self.anonymize_ip(value)

        if self._policy.anonymize_macs:
            for key in ("mac", "mac_address"):
                value = result.get(key)

                if isinstance(value, str):
                    result[key] = self.anonymize_mac(value)

        self._record_event(
            "NETWORK_RECORD_SANITIZED"
        )

        return result

    def minimize_fields(
        self,
        data: dict,
        allowed_fields: set,
    ) -> dict:

        if not isinstance(data, dict):
            raise PrivacyError(
                "Dados inválidos."
            )

        if not isinstance(allowed_fields, set):
            raise PrivacyError(
                "Lista de campos inválida."
            )

        for item in allowed_fields:
            if (
                not isinstance(item, str)
                or not item
                or len(item) > self.MAX_KEY_LENGTH
            ):
                raise PrivacyError(
                    "Nome de campo inválido."
                )

        for key in data:
            if not isinstance(key, str):
                raise PrivacyError(
                    "Chave de dados inválida."
                )

        result = {
            key: value
            for key, value in data.items()
            if key in allowed_fields
        }

        sanitized = self.sanitize_data(result)

        self._record_event(
            "DATA_MINIMIZED"
        )

        return sanitized

    def should_retain(self, created_at: float) -> bool:
        if (
            isinstance(created_at, bool)
            or not isinstance(created_at, (int, float))
            or not math.isfinite(created_at)
            or created_at < 0
        ):
            raise PrivacyError(
                "Data de criação inválida."
            )

        now = time.time()

        if created_at > now:
            raise PrivacyError(
                "A data de criação não pode estar no futuro."
            )

        age = now - created_at

        return age <= self._policy.retention_seconds

    def _record_event(self, event: str) -> None:
        with self._lock:
            if len(self._events) >= self.MAX_EVENTS:
                self._events.pop(0)

            self._events.append({
                "event": event,
                "timestamp": time.time(),
            })

    def get_events(self) -> List[dict]:
        with self._lock:
            return copy.deepcopy(self._events)

    def get_summary(self) -> dict:
        with self._lock:
            return {
                "anonymize_ips": self._policy.anonymize_ips,
                "anonymize_macs": self._policy.anonymize_macs,
                "redact_sensitive_text": (
                    self._policy.redact_sensitive_text
                ),
                "remove_private_fields": (
                    self._policy.remove_private_fields
                ),
                "retention_seconds": (
                    self._policy.retention_seconds
                ),
                "events_recorded": len(self._events),
            }

    def clear_events(self) -> None:
        with self._lock:
            self._events.clear()


__all__ = [
    "PrivacyError",
    "PrivacyPolicy",
    "PrivacyManager",
]
