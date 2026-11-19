
"""
NETSHADOW - Secrets Manager

Gestão temporária de informação sensível.
Os segredos são mantidos apenas em memória.
"""

from __future__ import annotations

import re
import threading

from typing import Optional


class SecretsManager:
    """Armazena e protege segredos durante a execução."""

    MAX_SECRETS = 500
    MAX_SECRET_LENGTH = 4096
    MAX_NAME_LENGTH = 128
    MASK = "********"

    def __init__(self):
        self._secrets: dict[str, str] = {}
        self._lock = threading.RLock()

    @classmethod
    def _validate_name(cls, name: str) -> str:
        if not isinstance(name, str):
            raise ValueError("Identificador inválido.")

        name = name.strip()

        if (
            not name
            or len(name) > cls.MAX_NAME_LENGTH
            or not re.fullmatch(r"[A-Za-z0-9_.-]+", name)
        ):
            raise ValueError("Formato de identificador inválido.")

        return name

    @classmethod
    def _validate_secret(cls, secret: str) -> str:
        if not isinstance(secret, str):
            raise ValueError("O segredo tem de ser texto.")

        if not secret or len(secret) > cls.MAX_SECRET_LENGTH:
            raise ValueError("Comprimento de segredo inválido.")

        if any(ord(char) < 32 and char not in "\t\n" for char in secret):
            raise ValueError("O segredo contém caracteres de controlo.")

        if "\x00" in secret:
            raise ValueError("O segredo contém caracteres inválidos.")

        return secret

    def set_secret(self, name: str, secret: str) -> None:
        """Regista ou substitui um segredo em memória."""

        name = self._validate_name(name)
        secret = self._validate_secret(secret)

        with self._lock:
            if name not in self._secrets:
                if len(self._secrets) >= self.MAX_SECRETS:
                    raise RuntimeError("Limite de segredos atingido.")

            self._secrets[name] = secret

    def get_secret(self, name: str) -> Optional[str]:
        """Recupera um segredo pelo identificador."""

        name = self._validate_name(name)

        with self._lock:
            return self._secrets.get(name)

    def has_secret(self, name: str) -> bool:
        name = self._validate_name(name)

        with self._lock:
            return name in self._secrets

    def remove_secret(self, name: str) -> bool:
        name = self._validate_name(name)

        with self._lock:
            return self._secrets.pop(name, None) is not None

    def mask_secret(self, value: str) -> str:
        """
        Mascara segredos registados num texto.

        Segredos com menos de 4 caracteres não são substituídos
        automaticamente para evitar mascaragem excessiva.
        """

        if not isinstance(value, str):
            raise ValueError("O texto tem de ser uma string.")

        with self._lock:
            secrets = sorted(
                (
                    secret
                    for secret in self._secrets.values()
                    if len(secret) >= 4
                ),
                key=len,
                reverse=True,
            )

            for secret in secrets:
                value = value.replace(secret, self.MASK)

        return value

    def get_masked_secret(self, name: str) -> Optional[str]:
        name = self._validate_name(name)

        with self._lock:
            if name not in self._secrets:
                return None

            return self.MASK

    def list_secret_names(self) -> list[str]:
        """Devolve apenas identificadores, nunca os valores."""

        with self._lock:
            return sorted(self._secrets.keys())

    def get_summary(self) -> dict:
        with self._lock:
            return {
                "total_secrets": len(self._secrets),
                "maximum_secrets": self.MAX_SECRETS,
                "storage": "MEMORY_ONLY",
                "values_exposed": False,
            }

    def clear(self) -> None:
        """Remove todas as referências aos segredos."""

        with self._lock:
            self._secrets.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._secrets)

    def __contains__(self, name: str) -> bool:
        if not isinstance(name, str):
            return False

        try:
            name = self._validate_name(name)
        except ValueError:
            return False

        with self._lock:
            return name in self._secrets


__all__ = ["SecretsManager"]
