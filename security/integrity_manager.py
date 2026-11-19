
"""
NETSHADOW - Integrity Manager

Verificação de integridade através de SHA-256.
"""

import hashlib
import hmac
import os
import threading

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional


class IntegrityError(Exception):
    """Erro durante uma operação de integridade."""


@dataclass
class IntegrityRecord:
    file_path: str
    sha256: str
    file_size: int
    created_at: str


@dataclass
class IntegrityResult:
    file_path: str
    status: str
    expected_hash: Optional[str]
    actual_hash: Optional[str]
    checked_at: str


class IntegrityManager:
    """Gere referências e verificações de integridade."""

    CHUNK_SIZE = 1024 * 1024
    MAX_FILE_SIZE = 100 * 1024 * 1024
    MAX_RECORDS = 10000

    def __init__(self):
        self._records: Dict[str, IntegrityRecord] = {}
        self._lock = threading.RLock()

    @staticmethod
    def _timestamp() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _validate_path(file_path) -> Path:
        if not isinstance(file_path, (str, Path)):
            raise IntegrityError("Caminho inválido.")

        path = Path(file_path)

        if not path.exists():
            raise IntegrityError("Ficheiro não encontrado.")

        if path.is_symlink() or not path.is_file():
            raise IntegrityError("É necessário um ficheiro regular.")

        return path.resolve(strict=True)

    def calculate_hash(self, file_path: str) -> str:
        """Calcula SHA-256 sem carregar o ficheiro inteiro na memória."""

        path = self._validate_path(file_path)

        try:
            initial_stat = path.stat()

            if initial_stat.st_size > self.MAX_FILE_SIZE:
                raise IntegrityError("Ficheiro demasiado grande.")

            digest = hashlib.sha256()
            total_size = 0

            with path.open("rb") as file:
                while True:
                    chunk = file.read(self.CHUNK_SIZE)

                    if not chunk:
                        break

                    total_size += len(chunk)

                    if total_size > self.MAX_FILE_SIZE:
                        raise IntegrityError(
                            "O ficheiro excedeu o limite permitido."
                        )

                    digest.update(chunk)

            final_stat = path.stat()

            if (
                initial_stat.st_size != final_stat.st_size
                or initial_stat.st_mtime_ns != final_stat.st_mtime_ns
            ):
                raise IntegrityError(
                    "O ficheiro foi alterado durante a leitura."
                )

            return digest.hexdigest()

        except OSError as exc:
            raise IntegrityError(
                "Não foi possível calcular o hash."
            ) from exc

    def register_file(self, file_path: str) -> IntegrityRecord:
        """Cria uma referência de integridade para um ficheiro."""

        path = self._validate_path(file_path)
        digest = self.calculate_hash(str(path))
        stat = path.stat()

        key = str(path)

        with self._lock:
            if (
                key not in self._records
                and len(self._records) >= self.MAX_RECORDS
            ):
                raise IntegrityError(
                    "Limite de referências atingido."
                )

            record = IntegrityRecord(
                file_path=key,
                sha256=digest,
                file_size=stat.st_size,
                created_at=self._timestamp(),
            )

            self._records[key] = record

        return record

    def verify_file(self, file_path: str) -> IntegrityResult:
        """Compara o hash atual com a referência registada."""

        try:
            path = self._validate_path(file_path)
            key = str(path)
        except IntegrityError:
            key = str(file_path)

            with self._lock:
                record = self._records.get(key)

            if record is None:
                raise

            return IntegrityResult(
                file_path=key,
                status="MISSING",
                expected_hash=record.sha256,
                actual_hash=None,
                checked_at=self._timestamp(),
            )

        with self._lock:
            record = self._records.get(key)

        if record is None:
            raise IntegrityError(
                "Ficheiro sem referência de integridade."
            )

        actual_hash = self.calculate_hash(key)

        if hmac.compare_digest(record.sha256, actual_hash):
            status = "UNCHANGED"
        else:
            status = "MODIFIED"

        return IntegrityResult(
            file_path=key,
            status=status,
            expected_hash=record.sha256,
            actual_hash=actual_hash,
            checked_at=self._timestamp(),
        )

    def verify_all(self) -> List[IntegrityResult]:
        """Verifica todas as referências registadas."""

        with self._lock:
            paths = list(self._records.keys())

        results = []

        for path in paths:
            try:
                results.append(self.verify_file(path))
            except IntegrityError:
                results.append(
                    IntegrityResult(
                        file_path=path,
                        status="ERROR",
                        expected_hash=self._records[path].sha256,
                        actual_hash=None,
                        checked_at=self._timestamp(),
                    )
                )

        return results

    def get_record(
        self,
        file_path: str,
    ) -> Optional[IntegrityRecord]:

        try:
            key = str(Path(file_path).resolve(strict=False))
        except (TypeError, ValueError, OSError):
            return None

        with self._lock:
            return self._records.get(key)

    def remove_record(self, file_path: str) -> bool:
        try:
            key = str(Path(file_path).resolve(strict=False))
        except (TypeError, ValueError, OSError):
            return False

        with self._lock:
            return self._records.pop(key, None) is not None

    def get_summary(self) -> dict:
        with self._lock:
            return {
                "registered_files": len(self._records),
                "maximum_records": self.MAX_RECORDS,
                "algorithm": "SHA-256",
            }

    def clear(self) -> None:
        with self._lock:
            self._records.clear()
