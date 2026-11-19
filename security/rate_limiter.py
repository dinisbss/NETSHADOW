

"""
NETSHADOW - Rate Limiter

Controlo local da frequência de operações.
Implementa uma janela temporal deslizante em memória.
"""

from __future__ import annotations

import math
import threading
import time

from collections import deque
from dataclasses import dataclass
from typing import Deque


class RateLimitError(Exception):
    """Erro relacionado com limites de frequência."""


@dataclass(frozen=True)
class RateLimitResult:
    allowed: bool
    remaining: int
    retry_after: float
    limit: int
    window_seconds: float


class RateLimiter:
    """Implementa limites de frequência em memória."""

    DEFAULT_LIMIT = 10
    DEFAULT_WINDOW = 60.0

    MAX_IDENTIFIERS = 10000
    MAX_LIMIT = 1000
    MAX_WINDOW = 3600.0
    MAX_IDENTIFIER_LENGTH = 128

    def __init__(self):
        self._requests: dict[str, Deque[float]] = {}
        self._lock = threading.RLock()

        self._allowed_count = 0
        self._blocked_count = 0

    @classmethod
    def _validate_identifier(cls, identifier: str) -> str:
        if not isinstance(identifier, str):
            raise RateLimitError(
                "Identificador inválido."
            )

        identifier = identifier.strip()

        if (
            not identifier
            or len(identifier) > cls.MAX_IDENTIFIER_LENGTH
        ):
            raise RateLimitError(
                "Identificador inválido."
            )

        if any(
            ord(char) < 32 or ord(char) == 127
            for char in identifier
        ):
            raise RateLimitError(
                "Identificador contém caracteres inválidos."
            )

        return identifier

    @classmethod
    def _validate_limits(
        cls,
        limit: int,
        window_seconds: float,
    ) -> None:

        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= cls.MAX_LIMIT
        ):
            raise RateLimitError(
                "Limite inválido."
            )

        if (
            isinstance(window_seconds, bool)
            or not isinstance(window_seconds, (int, float))
            or not math.isfinite(window_seconds)
            or not 0 < window_seconds <= cls.MAX_WINDOW
        ):
            raise RateLimitError(
                "Janela temporal inválida."
            )

    def _cleanup_empty(self) -> int:
        """Remove identificadores sem pedidos ativos."""

        empty = [
            key
            for key, requests in self._requests.items()
            if not requests
        ]

        for key in empty:
            del self._requests[key]

        return len(empty)

    def _cleanup_expired(self, now: float) -> int:
        """Remove pedidos antigos e identificadores vazios."""

        removed = 0

        for identifier in list(self._requests):
            requests = self._requests[identifier]

            while requests and now - requests[0] > self.MAX_WINDOW:
                requests.popleft()

            if not requests:
                del self._requests[identifier]
                removed += 1

        return removed

    def check(
        self,
        identifier: str,
        limit: int = DEFAULT_LIMIT,
        window_seconds: float = DEFAULT_WINDOW,
    ) -> RateLimitResult:
        """Verifica se uma operação pode prosseguir."""

        identifier = self._validate_identifier(identifier)

        self._validate_limits(
            limit,
            window_seconds,
        )

        now = time.monotonic()
        cutoff = now - float(window_seconds)

        with self._lock:
            if identifier not in self._requests:
                if len(self._requests) >= self.MAX_IDENTIFIERS:
                    self._cleanup_expired(now)

                if len(self._requests) >= self.MAX_IDENTIFIERS:
                    raise RateLimitError(
                        "Limite de identificadores atingido."
                    )

                self._requests[identifier] = deque()

            requests = self._requests[identifier]

            while requests and requests[0] <= cutoff:
                requests.popleft()

            if len(requests) >= limit:
                retry_after = max(
                    0.0,
                    requests[0] + float(window_seconds) - now,
                )

                self._blocked_count += 1

                return RateLimitResult(
                    allowed=False,
                    remaining=0,
                    retry_after=retry_after,
                    limit=limit,
                    window_seconds=float(window_seconds),
                )

            requests.append(now)
            self._allowed_count += 1

            return RateLimitResult(
                allowed=True,
                remaining=max(0, limit - len(requests)),
                retry_after=0.0,
                limit=limit,
                window_seconds=float(window_seconds),
            )

    def allow(self, identifier: str) -> bool:
        """Interface simplificada para verificar uma operação."""

        return self.check(identifier).allowed

    def reset_identifier(self, identifier: str) -> bool:
        identifier = self._validate_identifier(identifier)

        with self._lock:
            return self._requests.pop(
                identifier,
                None,
            ) is not None

    def cleanup(self, max_age: float = DEFAULT_WINDOW) -> int:
        """Remove pedidos antigos e identificadores inativos."""

        if (
            isinstance(max_age, bool)
            or not isinstance(max_age, (int, float))
            or not math.isfinite(max_age)
            or not 0 < max_age <= self.MAX_WINDOW
        ):
            raise RateLimitError(
                "Idade máxima inválida."
            )

        cutoff = time.monotonic() - float(max_age)
        removed = 0

        with self._lock:
            for identifier in list(self._requests):
                requests = self._requests[identifier]

                while requests and requests[0] <= cutoff:
                    requests.popleft()

                if not requests:
                    del self._requests[identifier]
                    removed += 1

        return removed

    def get_summary(self) -> dict:
        with self._lock:
            return {
                "tracked_identifiers": len(self._requests),
                "allowed_operations": self._allowed_count,
                "blocked_operations": self._blocked_count,
                "total_operations": (
                    self._allowed_count + self._blocked_count
                ),
                "maximum_identifiers": self.MAX_IDENTIFIERS,
            }

    def reset(self) -> None:
        """Limpa todos os identificadores e estatísticas."""

        with self._lock:
            self._requests.clear()
            self._allowed_count = 0
            self._blocked_count = 0


__all__ = [
    "RateLimiter",
    "RateLimitError",
    "RateLimitResult",
]
