
"""
NETSHADOW - Recovery Manager

Gestão de backups, verificação de integridade
e recuperação controlada de ficheiros.

Não executa ficheiros nem comandos durante a recuperação.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import stat
import threading
import time
import uuid

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional


class RecoveryError(Exception):
    """Erro nas operações de recuperação."""


@dataclass
class BackupRecord:
    backup_id: str
    original_name: str
    backup_path: str
    sha256: str
    size_bytes: int
    created_at: float


class RecoveryManager:
    MAX_FILE_SIZE = 100 * 1024 * 1024
    MAX_BACKUPS = 500
    CHUNK_SIZE = 1024 * 1024

    def __init__(self, backup_dir: Path):
        try:
            supplied_path = Path(backup_dir)

            if supplied_path.is_symlink():
                raise RecoveryError(
                    "O diretório de backups não pode ser um link simbólico."
                )

            supplied_path.mkdir(parents=True, exist_ok=True)

            if supplied_path.is_symlink():
                raise RecoveryError(
                    "Diretório de backups inválido."
                )

            self.backup_dir = supplied_path.resolve(strict=True)

            if not self.backup_dir.is_dir():
                raise RecoveryError(
                    "O caminho de backups não é um diretório."
                )

        except RecoveryError:
            raise
        except (OSError, ValueError, TypeError) as exc:
            raise RecoveryError(
                "Não foi possível preparar o diretório de backups."
            ) from exc

        self._records: Dict[str, BackupRecord] = {}
        self._lock = threading.RLock()

    @staticmethod
    def _copy_record(record: BackupRecord) -> BackupRecord:
        return BackupRecord(
            backup_id=record.backup_id,
            original_name=record.original_name,
            backup_path=record.backup_path,
            sha256=record.sha256,
            size_bytes=record.size_bytes,
            created_at=record.created_at,
        )

    @staticmethod
    def _calculate_hash(file_path: Path) -> str:
        digest = hashlib.sha256()

        with file_path.open("rb") as file:
            while True:
                chunk = file.read(RecoveryManager.CHUNK_SIZE)

                if not chunk:
                    break

                digest.update(chunk)

        return digest.hexdigest()

    def _copy_limited(
        self,
        source,
        destination,
        expected_size: Optional[int] = None,
    ) -> int:
        total = 0

        while True:
            chunk = source.read(self.CHUNK_SIZE)

            if not chunk:
                break

            total += len(chunk)

            if total > self.MAX_FILE_SIZE:
                raise RecoveryError(
                    "Ficheiro ultrapassa o limite permitido."
                )

            destination.write(chunk)

        if expected_size is not None and total != expected_size:
            raise RecoveryError(
                "O tamanho do ficheiro mudou durante a operação."
            )

        return total

    def _validate_source(self, source: Path) -> Path:
        try:
            source = Path(source)

            if source.is_symlink():
                raise RecoveryError(
                    "Links simbólicos não são permitidos."
                )

            resolved = source.resolve(strict=True)

            if not resolved.is_file():
                raise RecoveryError(
                    "A origem não é um ficheiro."
                )

            if resolved.stat().st_size > self.MAX_FILE_SIZE:
                raise RecoveryError(
                    "Ficheiro demasiado grande."
                )

            return resolved

        except RecoveryError:
            raise
        except (OSError, ValueError, TypeError, RuntimeError) as exc:
            raise RecoveryError(
                "Ficheiro de origem inválido."
            ) from exc

    def _get_backup_path(self, record: BackupRecord) -> Path:
        try:
            path = Path(record.backup_path)

            if path.parent != self.backup_dir:
                raise RecoveryError(
                    "Caminho de backup inválido."
                )

            if path.is_symlink() or not path.is_file():
                raise RecoveryError(
                    "Ficheiro de backup inválido."
                )

            if path.resolve(strict=True).parent != self.backup_dir:
                raise RecoveryError(
                    "Backup fora do diretório permitido."
                )

            return path

        except RecoveryError:
            raise
        except (OSError, ValueError, RuntimeError) as exc:
            raise RecoveryError(
                "Não foi possível validar o backup."
            ) from exc

    def create_backup(self, source: Path) -> BackupRecord:
        source = self._validate_source(source)

        with self._lock:
            if len(self._records) >= self.MAX_BACKUPS:
                raise RecoveryError(
                    "Limite de backups atingido."
                )

            backup_id = str(uuid.uuid4())

            destination = self.backup_dir / f"{backup_id}.backup"
            temporary = self.backup_dir / f".{backup_id}.tmp"

            try:
                with source.open("rb") as src:
                    source_stat = os.fstat(src.fileno())

                    if not stat.S_ISREG(source_stat.st_mode):
                        raise RecoveryError(
                            "A origem não é um ficheiro regular."
                        )

                    if source_stat.st_size > self.MAX_FILE_SIZE:
                        raise RecoveryError(
                            "Ficheiro demasiado grande."
                        )

                    with temporary.open("xb") as dst:
                        copied_size = self._copy_limited(
                            src,
                            dst,
                            expected_size=source_stat.st_size,
                        )

                        dst.flush()
                        os.fsync(dst.fileno())

                    final_stat = os.fstat(src.fileno())

                    if (
                        final_stat.st_size != source_stat.st_size
                        or final_stat.st_mtime_ns != source_stat.st_mtime_ns
                    ):
                        raise RecoveryError(
                            "A origem foi alterada durante o backup."
                        )

                backup_hash = self._calculate_hash(temporary)

                os.replace(temporary, destination)

                record = BackupRecord(
                    backup_id=backup_id,
                    original_name=source.name,
                    backup_path=str(destination),
                    sha256=backup_hash,
                    size_bytes=copied_size,
                    created_at=time.time(),
                )

                self._records[backup_id] = record

                return self._copy_record(record)

            except RecoveryError:
                temporary.unlink(missing_ok=True)
                raise

            except OSError as exc:
                temporary.unlink(missing_ok=True)

                raise RecoveryError(
                    "Não foi possível criar o backup."
                ) from exc

    def verify_backup(self, backup_id: str) -> bool:
        if not isinstance(backup_id, str):
            raise RecoveryError("Identificador de backup inválido.")

        with self._lock:
            record = self._records.get(backup_id)

            if record is None:
                raise RecoveryError(
                    "Backup não encontrado."
                )

            try:
                path = self._get_backup_path(record)

                if path.stat().st_size != record.size_bytes:
                    return False

                return self._calculate_hash(path) == record.sha256

            except RecoveryError:
                return False
            except OSError:
                return False

    def restore_backup(
        self,
        backup_id: str,
        destination: Path,
        overwrite: bool = False,
    ) -> Path:

        if not isinstance(overwrite, bool):
            raise RecoveryError(
                "Opção de substituição inválida."
            )

        if not isinstance(backup_id, str):
            raise RecoveryError(
                "Identificador de backup inválido."
            )

        with self._lock:
            record = self._records.get(backup_id)

            if record is None:
                raise RecoveryError(
                    "Backup não encontrado."
                )

            backup_path = self._get_backup_path(record)

            if not self.verify_backup(backup_id):
                raise RecoveryError(
                    "Integridade do backup inválida."
                )

            try:
                destination = Path(destination)

                if destination.is_symlink():
                    raise RecoveryError(
                        "O destino não pode ser um link simbólico."
                    )

                destination.parent.mkdir(
                    parents=True,
                    exist_ok=True,
                )

                parent = destination.parent.resolve(strict=True)
                destination = parent / destination.name

                if destination.is_symlink():
                    raise RecoveryError(
                        "O destino não pode ser um link simbólico."
                    )

                if destination.exists() and not overwrite:
                    raise RecoveryError(
                        "O destino já existe. "
                        "Substituição não autorizada."
                    )

                if destination.resolve() == backup_path.resolve():
                    raise RecoveryError(
                        "Destino inválido."
                    )

                temporary = destination.with_name(
                    f".{destination.name}.{uuid.uuid4().hex}.tmp"
                )

                try:
                    with backup_path.open("rb") as src:
                        with temporary.open("xb") as dst:
                            copied_size = self._copy_limited(
                                src,
                                dst,
                                expected_size=record.size_bytes,
                            )

                            dst.flush()
                            os.fsync(dst.fileno())

                    if copied_size != record.size_bytes:
                        raise RecoveryError(
                            "Tamanho do ficheiro restaurado inválido."
                        )

                    if self._calculate_hash(temporary) != record.sha256:
                        raise RecoveryError(
                            "Falha na verificação do ficheiro restaurado."
                        )

                    if destination.is_symlink():
                        raise RecoveryError(
                            "O destino tornou-se um link simbólico."
                        )

                    if destination.exists() and not overwrite:
                        raise RecoveryError(
                            "O destino foi criado durante a recuperação."
                        )

                    os.replace(temporary, destination)

                    return destination

                except Exception:
                    temporary.unlink(missing_ok=True)
                    raise

            except RecoveryError:
                raise

            except OSError as exc:
                raise RecoveryError(
                    "Falha ao restaurar o backup."
                ) from exc

    def delete_backup(self, backup_id: str) -> bool:
        if not isinstance(backup_id, str):
            return False

        with self._lock:
            record = self._records.get(backup_id)

            if record is None:
                return False

            path = self._get_backup_path(record)

            try:
                path.unlink()
                del self._records[backup_id]
                return True

            except OSError as exc:
                raise RecoveryError(
                    "Não foi possível eliminar o backup."
                ) from exc

    def list_backups(self) -> List[BackupRecord]:
        with self._lock:
            return [
                self._copy_record(record)
                for record in self._records.values()
            ]

    def get_summary(self) -> dict:
        with self._lock:
            total_size = sum(
                record.size_bytes
                for record in self._records.values()
            )

            return {
                "total_backups": len(self._records),
                "total_size_bytes": total_size,
                "maximum_backups": self.MAX_BACKUPS,
                "maximum_file_size": self.MAX_FILE_SIZE,
            }


__all__ = [
    "RecoveryManager",
    "RecoveryError",
    "BackupRecord",
]
