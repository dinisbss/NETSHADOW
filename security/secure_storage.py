
"""
NETSHADOW - Secure Storage

Armazenamento local controlado e protegido.
Inclui validação de caminhos, limites de tamanho,
escrita atómica e permissões restritas.
"""

from __future__ import annotations

import json
import os
import tempfile
import threading

from pathlib import Path, PureWindowsPath
from typing import Any


class SecureStorageError(Exception):
    """Erro de armazenamento seguro."""


class SecureStorage:
    MAX_FILE_SIZE = 5 * 1024 * 1024
    MAX_FILES = 10000
    MAX_FILENAME_LENGTH = 4096

    def __init__(self, base_directory):
        try:
            original_path = Path(base_directory).expanduser()

            if original_path.is_symlink():
                raise SecureStorageError(
                    "O diretório-base não pode ser uma ligação simbólica."
                )

            self.base_directory = original_path.resolve()

            self.base_directory.mkdir(
                parents=True,
                exist_ok=True,
            )

            if (
                self.base_directory.is_symlink()
                or not self.base_directory.is_dir()
            ):
                raise SecureStorageError(
                    "Diretório-base inválido."
                )

            if os.name == "posix":
                os.chmod(self.base_directory, 0o700)

        except SecureStorageError:
            raise
        except (OSError, TypeError, ValueError) as exc:
            raise SecureStorageError(
                "Não foi possível inicializar o armazenamento."
            ) from exc

        self._lock = threading.RLock()

    def _validate_path(self, filename: str) -> Path:
        if not isinstance(filename, str):
            raise SecureStorageError(
                "Nome de ficheiro inválido."
            )

        filename = filename.strip()

        if (
            not filename
            or len(filename) > self.MAX_FILENAME_LENGTH
            or "\x00" in filename
            or "\\" in filename
        ):
            raise SecureStorageError(
                "Nome de ficheiro inválido."
            )

        relative = Path(filename)
        windows_path = PureWindowsPath(filename)

        if (
            relative.is_absolute()
            or windows_path.is_absolute()
            or windows_path.drive
            or windows_path.root
        ):
            raise SecureStorageError(
                "Não são permitidos caminhos absolutos."
            )

        if ".." in relative.parts or ".." in windows_path.parts:
            raise SecureStorageError(
                "Caminho fora do diretório autorizado."
            )

        if not relative.parts:
            raise SecureStorageError(
                "Caminho vazio."
            )

        candidate = self.base_directory / relative

        try:
            resolved = candidate.resolve(strict=False)
            resolved.relative_to(self.base_directory)
        except (ValueError, OSError, RuntimeError) as exc:
            raise SecureStorageError(
                "Caminho não autorizado."
            ) from exc

        current = self.base_directory

        for part in relative.parts:
            current = current / part

            if current.is_symlink():
                raise SecureStorageError(
                    "Ligações simbólicas não são permitidas."
                )

        return candidate

    def _ensure_parent(self, path: Path) -> None:
        try:
            parent = path.parent

            parent.mkdir(
                parents=True,
                exist_ok=True,
            )

            resolved = parent.resolve()
            resolved.relative_to(self.base_directory)

            current = self.base_directory

            for part in parent.relative_to(
                self.base_directory
            ).parts:
                current = current / part

                if current.is_symlink():
                    raise SecureStorageError(
                        "Diretório simbólico não permitido."
                    )

                if not current.is_dir():
                    raise SecureStorageError(
                        "Componente do caminho não é um diretório."
                    )

            if os.name == "posix":
                os.chmod(parent, 0o700)

        except SecureStorageError:
            raise
        except (OSError, ValueError, RuntimeError) as exc:
            raise SecureStorageError(
                "Não foi possível preparar o diretório."
            ) from exc

    def _count_files(self) -> int:
        count = 0

        for root, directories, files in os.walk(
            self.base_directory,
            followlinks=False,
        ):
            directories[:] = [
                name
                for name in directories
                if not (Path(root) / name).is_symlink()
            ]

            for filename in files:
                item = Path(root) / filename

                if item.is_file() and not item.is_symlink():
                    count += 1

                    if count >= self.MAX_FILES:
                        return count

        return count

    def write_bytes(
        self,
        filename: str,
        data: bytes,
    ) -> Path:

        if not isinstance(data, bytes):
            raise SecureStorageError(
                "Os dados têm de ser bytes."
            )

        if len(data) > self.MAX_FILE_SIZE:
            raise SecureStorageError(
                "O ficheiro excede o tamanho permitido."
            )

        path = self._validate_path(filename)

        with self._lock:
            self._ensure_parent(path)

            if path.is_symlink():
                raise SecureStorageError(
                    "Não são permitidas ligações simbólicas."
                )

            if path.exists() and not path.is_file():
                raise SecureStorageError(
                    "O destino não é um ficheiro regular."
                )

            if not path.exists():
                if self._count_files() >= self.MAX_FILES:
                    raise SecureStorageError(
                        "Limite de ficheiros atingido."
                    )

            temp_path = None

            try:
                with tempfile.NamedTemporaryFile(
                    mode="wb",
                    dir=path.parent,
                    prefix=".netshadow-",
                    suffix=".tmp",
                    delete=False,
                ) as temp_file:

                    temp_path = Path(temp_file.name)

                    if os.name == "posix":
                        os.chmod(temp_path, 0o600)

                    temp_file.write(data)
                    temp_file.flush()
                    os.fsync(temp_file.fileno())

                if path.is_symlink():
                    raise SecureStorageError(
                        "Destino alterado durante a operação."
                    )

                os.replace(temp_path, path)
                temp_path = None

                return path

            except SecureStorageError:
                raise

            except OSError as exc:
                raise SecureStorageError(
                    "Não foi possível guardar o ficheiro."
                ) from exc

            finally:
                if temp_path is not None:
                    try:
                        temp_path.unlink(missing_ok=True)
                    except OSError:
                        pass

    def read_bytes(self, filename: str) -> bytes:
        path = self._validate_path(filename)

        with self._lock:
            if path.is_symlink():
                raise SecureStorageError(
                    "Não são permitidas ligações simbólicas."
                )

            if not path.exists() or not path.is_file():
                raise SecureStorageError(
                    "Ficheiro não encontrado."
                )

            try:
                with path.open("rb") as file:
                    data = file.read(
                        self.MAX_FILE_SIZE + 1
                    )

                if len(data) > self.MAX_FILE_SIZE:
                    raise SecureStorageError(
                        "O ficheiro excede o tamanho permitido."
                    )

                return data

            except SecureStorageError:
                raise

            except OSError as exc:
                raise SecureStorageError(
                    "Não foi possível ler o ficheiro."
                ) from exc

    def write_json(
        self,
        filename: str,
        data: Any,
    ) -> Path:

        try:
            serialized = json.dumps(
                data,
                ensure_ascii=False,
                indent=2,
                allow_nan=False,
            ).encode("utf-8")

        except (TypeError, ValueError, RecursionError) as exc:
            raise SecureStorageError(
                "Os dados não podem ser convertidos para JSON."
            ) from exc

        return self.write_bytes(filename, serialized)

    def read_json(self, filename: str) -> Any:
        try:
            raw = self.read_bytes(filename)

            return json.loads(
                raw.decode("utf-8")
            )

        except SecureStorageError:
            raise

        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
            RecursionError,
        ) as exc:
            raise SecureStorageError(
                "O ficheiro JSON é inválido."
            ) from exc

    def delete(self, filename: str) -> bool:
        path = self._validate_path(filename)

        with self._lock:
            if path.is_symlink():
                raise SecureStorageError(
                    "Não são permitidas ligações simbólicas."
                )

            if not path.exists():
                return False

            if not path.is_file():
                raise SecureStorageError(
                    "O destino não é um ficheiro regular autorizado."
                )

            try:
                path.unlink()
                return True

            except OSError as exc:
                raise SecureStorageError(
                    "Não foi possível eliminar o ficheiro."
                ) from exc

    def exists(self, filename: str) -> bool:
        path = self._validate_path(filename)

        with self._lock:
            return (
                path.is_file()
                and not path.is_symlink()
            )


__all__ = [
    "SecureStorage",
    "SecureStorageError",
]
