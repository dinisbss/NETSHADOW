
from __future__ import annotations

import json
import os
import tempfile

from dataclasses import asdict, is_dataclass
from datetime import date, datetime
from enum import Enum
from pathlib import Path
from typing import Any, Optional


class JSONExportError(Exception):
    """Erro durante a exportação JSON."""


class JSONExporter:
    """Exportador de relatórios JSON."""

    def __init__(
        self,
        output_directory: Optional[str | Path] = None,
        indent: int = 4,
    ):
        if not isinstance(indent, int) or isinstance(indent, bool) or indent < 0:
            raise JSONExportError("O indent deve ser um inteiro não negativo.")

        self.output_directory = Path(
            output_directory or Path.cwd() / "reports" / "generated"
        ).expanduser().resolve()

        self.indent = indent

    @staticmethod
    def _serialize(value: Any) -> Any:
        """Converte objetos Python em estruturas compatíveis com JSON."""

        if is_dataclass(value) and not isinstance(value, type):
            return JSONExporter._serialize(asdict(value))

        if isinstance(value, dict):
            return {
                str(key): JSONExporter._serialize(item)
                for key, item in value.items()
            }

        if isinstance(value, (list, tuple, set)):
            return [
                JSONExporter._serialize(item)
                for item in value
            ]

        if isinstance(value, Enum):
            return value.value

        if isinstance(value, (datetime, date)):
            return value.isoformat()

        if isinstance(value, Path):
            return str(value)

        if isinstance(value, bytes):
            return value.hex()

        if value is None or isinstance(value, (str, int, float, bool)):
            return value

        if hasattr(value, "to_dict") and callable(value.to_dict):
            return JSONExporter._serialize(value.to_dict())

        raise JSONExportError(
            f"Tipo de dados não suportado: {type(value).__name__}"
        )

    def serialize(self, data: Any) -> str:
        """Converte dados para uma string JSON."""
        try:
            normalized = self._serialize(data)

            return json.dumps(
                normalized,
                ensure_ascii=False,
                indent=self.indent,
                allow_nan=False,
            )

        except (TypeError, ValueError) as exc:
            raise JSONExportError(
                f"Não foi possível converter os dados: {exc}"
            ) from exc

    def export(
        self,
        data: Any,
        filename: str,
        overwrite: bool = False,
    ) -> Path:
        """Exporta dados para um ficheiro JSON."""

        if not isinstance(filename, str) or not filename.strip():
            raise JSONExportError("O nome do ficheiro é obrigatório.")

        if Path(filename).name != filename or filename in {".", ".."}:
            raise JSONExportError("Nome de ficheiro inválido.")

        if not filename.lower().endswith(".json"):
            filename += ".json"

        content = self.serialize(data)

        try:
            self.output_directory.mkdir(
                parents=True,
                exist_ok=True,
            )

            destination = self.output_directory / filename

            if destination.is_symlink():
                raise JSONExportError(
                    "Não é permitido exportar para um link simbólico."
                )

            if destination.exists() and not overwrite:
                raise JSONExportError(
                    f"O ficheiro já existe: {destination}"
                )

            descriptor, temporary_name = tempfile.mkstemp(
                prefix=".netshadow_",
                suffix=".tmp",
                dir=self.output_directory,
            )

            temporary_path = Path(temporary_name)

            try:
                with os.fdopen(
                    descriptor,
                    "w",
                    encoding="utf-8",
                    newline="\n",
                ) as file:
                    file.write(content)
                    file.write("\n")
                    file.flush()
                    os.fsync(file.fileno())

                if destination.exists() and not overwrite:
                    raise JSONExportError(
                        f"O ficheiro já existe: {destination}"
                    )

                os.replace(temporary_path, destination)

            finally:
                if temporary_path.exists():
                    temporary_path.unlink()

            return destination

        except JSONExportError:
            raise

        except OSError as exc:
            raise JSONExportError(
                f"Falha ao guardar o relatório: {exc}"
            ) from exc

    def export_data(
        self,
        data: Any,
        filename: str,
        overwrite: bool = False,
    ) -> Path:
        return self.export(data, filename, overwrite)

    def export_report(
        self,
        report: Any,
        filename: str,
        overwrite: bool = False,
    ) -> Path:
        return self.export(report, filename, overwrite)


# Compatibilidade com nomes alternativos.
JSONReportExporter = JSONExporter
JsonExporter = JSONExporter
JSONReportExport = JSONExporter

__all__ = [
    "JSONExportError",
    "JSONExporter",
    "JSONReportExporter",
    "JsonExporter",
    "JSONReportExport",
]
