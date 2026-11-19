
"""
NETSHADOW - Audit Logger

Registo estruturado de eventos de auditoria.
"""

from __future__ import annotations

import json
import logging
import math
import os
import re
import stat
import threading

from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from uuid import uuid4


class AuditLoggerError(Exception):
    """Erro no sistema de auditoria."""


class AuditLogger:
    MAX_EVENT_LENGTH = 8192
    MAX_EVENTS_PER_FILE = 10000
    MAX_ROTATED_FILES = 5
    MAX_READ_BYTES = 50 * 1024 * 1024

    VALID_LEVELS = {
        "INFO",
        "WARNING",
        "ERROR",
        "CRITICAL",
    }

    SENSITIVE_KEYS = {
        "password",
        "passwd",
        "token",
        "secret",
        "api_key",
        "apikey",
        "authorization",
        "credential",
        "credentials",
        "private_key",
        "access_token",
        "refresh_token",
        "client_secret",
    }

    def __init__(self, log_directory):
        try:
            original = Path(log_directory).expanduser()

            if original.is_symlink():
                raise AuditLoggerError(
                    "O diretório de auditoria não pode ser uma ligação simbólica."
                )

            original.mkdir(
                parents=True,
                exist_ok=True,
            )

            self.log_directory = original.resolve()

            if not self.log_directory.is_dir():
                raise AuditLoggerError(
                    "Diretório de auditoria inválido."
                )

            if os.name == "posix":
                os.chmod(self.log_directory, 0o700)

            self.log_file = (
                self.log_directory / "security_audit.jsonl"
            )

            self._lock = threading.RLock()
            self._event_count = self._count_existing_events()

            self.logger = logging.getLogger(
                "NETSHADOW.AUDIT"
            )

        except AuditLoggerError:
            raise
        except (OSError, ValueError, TypeError) as exc:
            raise AuditLoggerError(
                "Não foi possível inicializar o sistema de auditoria."
            ) from exc

    @staticmethod
    def _timestamp() -> str:
        return datetime.now(timezone.utc).isoformat()

    def _validate_log_file(self, path: Path) -> None:
        if path.is_symlink():
            raise AuditLoggerError(
                "Ligações simbólicas não são permitidas nos registos."
            )

        try:
            resolved = path.resolve(strict=False)
            resolved.relative_to(self.log_directory)
        except (ValueError, OSError, RuntimeError) as exc:
            raise AuditLoggerError(
                "Ficheiro fora do diretório autorizado."
            ) from exc

        if path.exists() and not path.is_file():
            raise AuditLoggerError(
                "O destino não é um ficheiro regular."
            )

    def _count_existing_events(self) -> int:
        if not self.log_file.exists():
            return 0

        self._validate_log_file(self.log_file)

        try:
            if self.log_file.stat().st_size > self.MAX_READ_BYTES:
                raise AuditLoggerError(
                    "O histórico excede o tamanho permitido."
                )

            with self.log_file.open(
                "r",
                encoding="utf-8",
            ) as file:
                return sum(1 for line in file if line.strip())

        except UnicodeDecodeError as exc:
            raise AuditLoggerError(
                "O histórico de auditoria não contém UTF-8 válido."
            ) from exc
        except OSError as exc:
            raise AuditLoggerError(
                "Não foi possível verificar o histórico."
            ) from exc

    @classmethod
    def _sanitize(cls, value: Any, depth: int = 0) -> Any:
        if depth > 5:
            return "[MAX_DEPTH]"

        if value is None or isinstance(value, bool):
            return value

        if isinstance(value, int):
            return value if value.bit_length() <= 256 else "[INTEGER_TOO_LARGE]"

        if isinstance(value, float):
            return value if math.isfinite(value) else "[INVALID_NUMBER]"

        if isinstance(value, str):
            value = re.sub(
                r"(?i)\b(password|passwd|token|secret|api_key|apikey|authorization)"
                r"\s*[:=]\s*[^\s,;]+",
                r"\1=[REDACTED]",
                value,
            )

            return value[:2048]

        if isinstance(value, dict):
            sanitized = {}

            for key, item in list(value.items())[:50]:
                safe_key = str(key)[:128]
                normalized_key = re.sub(
                    r"[^a-z0-9]",
                    "",
                    safe_key.lower(),
                )

                sensitive = (
                    normalized_key in {
                        re.sub(r"[^a-z0-9]", "", name)
                        for name in cls.SENSITIVE_KEYS
                    }
                )

                sanitized[safe_key] = (
                    "[REDACTED]"
                    if sensitive
                    else cls._sanitize(item, depth + 1)
                )

            return sanitized

        if isinstance(value, (list, tuple)):
            return [
                cls._sanitize(item, depth + 1)
                for item in value[:50]
            ]

        return "[UNSUPPORTED_TYPE]"

    def _rotate_if_needed(self) -> None:
        if self._event_count < self.MAX_EVENTS_PER_FILE:
            return

        self._validate_log_file(self.log_file)

        for index in range(
            self.MAX_ROTATED_FILES,
            0,
            -1,
        ):
            source = self.log_directory / (
                f"security_audit.{index}.jsonl"
            )

            self._validate_log_file(source)

            if index == self.MAX_ROTATED_FILES:
                source.unlink(missing_ok=True)
                continue

            destination = self.log_directory / (
                f"security_audit.{index + 1}.jsonl"
            )

            self._validate_log_file(destination)

            if source.exists():
                os.replace(source, destination)

        destination = (
            self.log_directory / "security_audit.1.jsonl"
        )

        self._validate_log_file(destination)

        if self.log_file.exists():
            os.replace(self.log_file, destination)

        self._event_count = 0

    def log_event(
        self,
        event_type: str,
        level: str = "INFO",
        details: Optional[dict] = None,
        target: Optional[str] = None,
    ) -> dict:

        if (
            not isinstance(event_type, str)
            or not re.fullmatch(
                r"[A-Za-z0-9_.-]{1,100}",
                event_type,
            )
        ):
            raise AuditLoggerError(
                "Tipo de evento inválido."
            )

        if (
            not isinstance(level, str)
            or level.upper() not in self.VALID_LEVELS
        ):
            raise AuditLoggerError(
                "Nível de evento inválido."
            )

        if details is not None and not isinstance(details, dict):
            raise AuditLoggerError(
                "Detalhes inválidos."
            )

        if target is not None:
            if not isinstance(target, str):
                raise AuditLoggerError(
                    "Destino do evento inválido."
                )

            target = target[:256]

        event = {
            "event_id": str(uuid4()),
            "timestamp": self._timestamp(),
            "event_type": event_type,
            "level": level.upper(),
            "target": target,
            "details": self._sanitize(details or {}),
        }

        try:
            serialized = json.dumps(
                event,
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
            )

            if len(serialized.encode("utf-8")) > self.MAX_EVENT_LENGTH:
                raise AuditLoggerError(
                    "Evento demasiado grande."
                )

            with self._lock:
                self._rotate_if_needed()

                self._validate_log_file(self.log_file)

                flags = (
                    os.O_APPEND
                    | os.O_CREAT
                    | os.O_WRONLY
                )

                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW

                descriptor = os.open(
                    self.log_file,
                    flags,
                    0o600,
                )

                try:
                    file_stat = os.fstat(descriptor)

                    if not stat.S_ISREG(file_stat.st_mode):
                        raise AuditLoggerError(
                            "O destino não é um ficheiro regular."
                        )

                    with os.fdopen(
                        descriptor,
                        "a",
                        encoding="utf-8",
                    ) as file:
                        descriptor = -1

                        file.write(serialized + "\n")
                        file.flush()
                        os.fsync(file.fileno())

                finally:
                    if descriptor >= 0:
                        os.close(descriptor)

                self._event_count += 1

            self.logger.log(
                getattr(logging, level.upper()),
                "Audit event: %s",
                event_type,
            )

            return event

        except AuditLoggerError:
            raise
        except (OSError, ValueError, TypeError) as exc:
            raise AuditLoggerError(
                "Não foi possível registar o evento."
            ) from exc

    def read_events(self, limit: int = 100) -> list:
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= 1000
        ):
            raise AuditLoggerError(
                "Limite de leitura inválido."
            )

        with self._lock:
            if not self.log_file.exists():
                return []

            self._validate_log_file(self.log_file)

            try:
                if self.log_file.stat().st_size > self.MAX_READ_BYTES:
                    raise AuditLoggerError(
                        "O histórico excede o tamanho permitido."
                    )

                events = deque(maxlen=limit)

                with self.log_file.open(
                    "r",
                    encoding="utf-8",
                ) as file:
                    for line in file:
                        if not line.strip():
                            continue

                        try:
                            event = json.loads(line)

                            if isinstance(event, dict):
                                events.append(event)

                        except json.JSONDecodeError:
                            continue

                return list(events)

            except AuditLoggerError:
                raise
            except (OSError, UnicodeDecodeError) as exc:
                raise AuditLoggerError(
                    "Não foi possível ler o histórico."
                ) from exc

    def get_summary(self) -> dict:
        events = self.read_events(limit=1000)

        return {
            "events_read": len(events),
            "log_file": self.log_file.name,
            "format": "JSONL",
            "maximum_events_per_file": self.MAX_EVENTS_PER_FILE,
            "maximum_rotated_files": self.MAX_ROTATED_FILES,
        }


__all__ = [
    "AuditLogger",
    "AuditLoggerError",
]
