
"""
NETSHADOW - Sandbox Manager

Gestão de sessões e políticas de isolamento lógico.

Nota:
Este módulo não cria isolamento ao nível do sistema operativo.
Não executa código arbitrário nem substitui containers,
processos restritos ou mecanismos de sandbox do SO.
"""

from __future__ import annotations

import math
import re
import threading
import time
import uuid

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


class SandboxError(Exception):
    """Erro na gestão de sessões isoladas."""


class SandboxState(str, Enum):
    CREATED = "CREATED"
    ACTIVE = "ACTIVE"
    BLOCKED = "BLOCKED"
    CLOSED = "CLOSED"
    EXPIRED = "EXPIRED"


@dataclass
class SandboxPolicy:
    timeout_seconds: float = 300.0
    memory_limit_mb: int = 256
    max_operations: int = 100

    allowed_operations: set = field(
        default_factory=lambda: {
            "network_info",
            "device_info",
            "read_history",
            "analyze_findings",
            "generate_report",
        }
    )


@dataclass
class SandboxSession:
    session_id: str
    name: str
    state: SandboxState
    created_at: float
    expires_at: float
    policy: SandboxPolicy
    operations_count: int = 0
    events: List[dict] = field(default_factory=list)


class SandboxManager:
    """Controla sessões de execução lógica isoladas."""

    MAX_SESSIONS = 100
    MAX_EVENTS_PER_SESSION = 500
    MAX_NAME_LENGTH = 128
    MAX_OPERATION_LENGTH = 64

    VALID_OPERATION_PATTERN = re.compile(
        r"^[a-z][a-z0-9_]{0,63}$"
    )

    def __init__(self):
        self._sessions: Dict[str, SandboxSession] = {}
        self._lock = threading.RLock()

    @staticmethod
    def _validate_name(name: str) -> str:
        if not isinstance(name, str):
            raise SandboxError(
                "Nome de sessão inválido."
            )

        name = name.strip()

        if not name or len(name) > SandboxManager.MAX_NAME_LENGTH:
            raise SandboxError(
                "Nome de sessão inválido."
            )

        if any(
            ord(char) < 32 or ord(char) == 127
            for char in name
        ):
            raise SandboxError(
                "Nome contém caracteres inválidos."
            )

        return name

    @staticmethod
    def _validate_policy(policy: SandboxPolicy) -> None:
        if not isinstance(policy, SandboxPolicy):
            raise SandboxError(
                "Política inválida."
            )

        if (
            isinstance(policy.timeout_seconds, bool)
            or not isinstance(policy.timeout_seconds, (int, float))
            or not math.isfinite(policy.timeout_seconds)
            or not 1 <= policy.timeout_seconds <= 3600
        ):
            raise SandboxError(
                "Timeout inválido."
            )

        if (
            isinstance(policy.memory_limit_mb, bool)
            or not isinstance(policy.memory_limit_mb, int)
            or not 16 <= policy.memory_limit_mb <= 4096
        ):
            raise SandboxError(
                "Limite de memória inválido."
            )

        if (
            isinstance(policy.max_operations, bool)
            or not isinstance(policy.max_operations, int)
            or not 1 <= policy.max_operations <= 10000
        ):
            raise SandboxError(
                "Limite de operações inválido."
            )

        if not isinstance(policy.allowed_operations, set):
            raise SandboxError(
                "Lista de operações inválida."
            )

        if len(policy.allowed_operations) > 100:
            raise SandboxError(
                "Demasiadas operações na política."
            )

        for operation in policy.allowed_operations:
            if (
                not isinstance(operation, str)
                or not SandboxManager.VALID_OPERATION_PATTERN.fullmatch(
                    operation
                )
            ):
                raise SandboxError(
                    "Operação inválida na política."
                )

    @staticmethod
    def _copy_policy(policy: SandboxPolicy) -> SandboxPolicy:
        return SandboxPolicy(
            timeout_seconds=float(policy.timeout_seconds),
            memory_limit_mb=policy.memory_limit_mb,
            max_operations=policy.max_operations,
            allowed_operations=set(policy.allowed_operations),
        )

    @staticmethod
    def _copy_session(session: SandboxSession) -> SandboxSession:
        return SandboxSession(
            session_id=session.session_id,
            name=session.name,
            state=session.state,
            created_at=session.created_at,
            expires_at=session.expires_at,
            policy=SandboxManager._copy_policy(session.policy),
            operations_count=session.operations_count,
            events=[
                event.copy()
                for event in session.events
            ],
        )

    def create_session(
        self,
        name: str,
        policy: Optional[SandboxPolicy] = None,
    ) -> SandboxSession:

        name = self._validate_name(name)

        if policy is None:
            policy = SandboxPolicy()

        self._validate_policy(policy)

        # A sessão recebe uma cópia independente da política.
        policy = self._copy_policy(policy)

        with self._lock:
            self._cleanup_expired()

            if len(self._sessions) >= self.MAX_SESSIONS:
                raise SandboxError(
                    "Limite de sessões atingido."
                )

            now = time.monotonic()

            session = SandboxSession(
                session_id=str(uuid.uuid4()),
                name=name,
                state=SandboxState.CREATED,
                created_at=now,
                expires_at=now + policy.timeout_seconds,
                policy=policy,
            )

            self._sessions[session.session_id] = session

            self._record(
                session,
                "SESSION_CREATED",
                "Sessão criada.",
            )

            return self._copy_session(session)

    def start_session(self, session_id: str) -> bool:
        with self._lock:
            session = self._get_session(session_id)

            if session is None:
                return False

            if session.state != SandboxState.CREATED:
                return False

            if self._is_expired(session):
                session.state = SandboxState.EXPIRED

                self._record(
                    session,
                    "SESSION_EXPIRED",
                    "Sessão expirada antes do início.",
                )

                return False

            session.state = SandboxState.ACTIVE

            self._record(
                session,
                "SESSION_STARTED",
                "Sessão iniciada.",
            )

            return True

    def authorize_operation(
        self,
        session_id: str,
        operation: str,
    ) -> bool:

        if (
            not isinstance(operation, str)
            or not self.VALID_OPERATION_PATTERN.fullmatch(
                operation.strip().lower()
            )
        ):
            return False

        operation = operation.strip().lower()

        with self._lock:
            session = self._get_session(session_id)

            if session is None:
                return False

            if session.state != SandboxState.ACTIVE:
                return False

            if self._is_expired(session):
                session.state = SandboxState.EXPIRED

                self._record(
                    session,
                    "SESSION_EXPIRED",
                    "A sessão ultrapassou o tempo permitido.",
                )

                return False

            if operation not in session.policy.allowed_operations:
                self._record(
                    session,
                    "OPERATION_BLOCKED",
                    "Operação não permitida pela política.",
                )

                return False

            if session.operations_count >= session.policy.max_operations:
                session.state = SandboxState.BLOCKED

                self._record(
                    session,
                    "LIMIT_REACHED",
                    "Limite de operações atingido.",
                )

                return False

            session.operations_count += 1

            self._record(
                session,
                "OPERATION_AUTHORIZED",
                "Operação aprovada pela política local.",
            )

            return True

    def close_session(self, session_id: str) -> bool:
        with self._lock:
            session = self._get_session(session_id)

            if session is None:
                return False

            if session.state in {
                SandboxState.CLOSED,
                SandboxState.EXPIRED,
            }:
                return False

            session.state = SandboxState.CLOSED

            self._record(
                session,
                "SESSION_CLOSED",
                "Sessão encerrada.",
            )

            return True

    def _get_session(
        self,
        session_id: str,
    ) -> Optional[SandboxSession]:

        if not isinstance(session_id, str):
            return None

        session = self._sessions.get(session_id)

        if session is None:
            return None

        if (
            session.state in {
                SandboxState.CREATED,
                SandboxState.ACTIVE,
            }
            and self._is_expired(session)
        ):
            session.state = SandboxState.EXPIRED

            self._record(
                session,
                "SESSION_EXPIRED",
                "A sessão ultrapassou o tempo permitido.",
            )

        return session

    @staticmethod
    def _is_expired(session: SandboxSession) -> bool:
        return time.monotonic() >= session.expires_at

    def _record(
        self,
        session: SandboxSession,
        event: str,
        message: str,
    ) -> None:

        if len(session.events) >= self.MAX_EVENTS_PER_SESSION:
            session.events.pop(0)

        session.events.append({
            "timestamp": time.time(),
            "event": event,
            "message": message,
        })

    def _cleanup_expired(self) -> int:
        count = 0

        for session in self._sessions.values():
            if (
                session.state in {
                    SandboxState.CREATED,
                    SandboxState.ACTIVE,
                }
                and self._is_expired(session)
            ):
                session.state = SandboxState.EXPIRED

                self._record(
                    session,
                    "SESSION_EXPIRED",
                    "A sessão ultrapassou o tempo permitido.",
                )

                count += 1

        return count

    def cleanup_expired(self) -> int:
        with self._lock:
            return self._cleanup_expired()

    def get_session(self, session_id: str):
        with self._lock:
            session = self._get_session(session_id)

            if session is None:
                return None

            return self._copy_session(session)

    def get_summary(self) -> dict:
        with self._lock:
            self._cleanup_expired()

            counts = {
                state.value: 0
                for state in SandboxState
            }

            for session in self._sessions.values():
                counts[session.state.value] += 1

            return {
                "total_sessions": len(self._sessions),
                "maximum_sessions": self.MAX_SESSIONS,
                "states": counts,
            }

    def clear(self) -> None:
        with self._lock:
            self._sessions.clear()


__all__ = [
    "SandboxManager",
    "SandboxPolicy",
    "SandboxSession",
    "SandboxState",
    "SandboxError",
]
