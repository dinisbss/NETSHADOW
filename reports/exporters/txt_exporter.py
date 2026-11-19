
from __future__ import annotations

import os
import tempfile

from dataclasses import asdict, is_dataclass
from datetime import date, datetime
from enum import Enum
from pathlib import Path
from typing import Any, Optional


class TXTExportError(Exception):
    """Erro durante a exportação TXT."""


class TXTExporter:
    """Exportador de relatórios de texto do NETSHADOW."""

    def __init__(
        self,
        output_directory: Optional[str | Path] = None,
        title: str = "NETSHADOW - Network Intelligence Report",
    ):
        self.output_directory = Path(
            output_directory or Path.cwd() / "reports" / "generated"
        ).expanduser().resolve()

        self.title = str(title)

    @classmethod
    def _serialize(cls, value: Any) -> Any:
        if is_dataclass(value) and not isinstance(value, type):
            return cls._serialize(asdict(value))

        if isinstance(value, dict):
            return {
                str(key): cls._serialize(item)
                for key, item in value.items()
            }

        if isinstance(value, (list, tuple, set)):
            return [cls._serialize(item) for item in value]

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
            return cls._serialize(value.to_dict())

        raise TXTExportError(
            f"Tipo não suportado: {type(value).__name__}"
        )

    @staticmethod
    def _format_value(value: Any, level: int = 0) -> list[str]:
        """Formata valores em linhas de texto."""
        indent = "    " * level

        if isinstance(value, dict):
            lines = []

            for key, item in value.items():
                if isinstance(item, (dict, list)):
                    lines.append(f"{indent}{key}:")
                    lines.extend(
                        TXTExporter._format_value(item, level + 1)
                    )
                else:
                    lines.append(
                        f"{indent}{key}: {item if item is not None else '—'}"
                    )

            return lines

        if isinstance(value, list):
            if not value:
                return [f"{indent}(sem resultados)"]

            lines = []

            for index, item in enumerate(value, start=1):
                lines.append(f"{indent}[{index}]")

                if isinstance(item, (dict, list)):
                    lines.extend(
                        TXTExporter._format_value(item, level + 1)
                    )
                else:
                    lines.append(f"{indent}    {item}")

            return lines

        return [f"{indent}{value}"]

    def render(self, data: Any) -> str:
        """Gera o relatório completo em texto."""
        normalized = self._serialize(data)

        lines = [
            "=" * 72,
            self.title.center(72),
            "=" * 72,
            "NETSHADOW - Network Intelligence & Security Auditing",
            f"Gerado em: {datetime.now().astimezone().isoformat(timespec='seconds')}",
            "",
        ]

        if isinstance(normalized, dict):
            for section, content in normalized.items():
                lines.extend([
                    "-" * 72,
                    str(section).upper(),
                    "-" * 72,
                ])
                lines.extend(self._format_value(content))
                lines.append("")
        else:
            lines.extend([
                "-" * 72,
                "RESULTADOS",
                "-" * 72,
            ])
            lines.extend(self._format_value(normalized))

        lines.extend([
            "",
            "=" * 72,
            "FIM DO RELATÓRIO",
            "=" * 72,
        ])

        return "\n".join(lines) + "\n"

    def export(
        self,
        data: Any,
        filename: str,
        overwrite: bool = False,
    ) -> Path:
        """Guarda o relatório TXT no disco."""

        if not isinstance(filename, str) or not filename.strip():
            raise TXTExportError("O nome do ficheiro é obrigatório.")

        if Path(filename).name != filename or filename in {".", ".."}:
            raise TXTExportError("Nome de ficheiro inválido.")

        if not filename.lower().endswith(".txt"):
            filename += ".txt"

        content = self.render(data)

        try:
            self.output_directory.mkdir(
                parents=True,
                exist_ok=True,
            )

            destination = self.output_directory / filename

            if destination.is_symlink():
                raise TXTExportError(
                    "Não é permitido exportar para um link simbólico."
                )

            if destination.exists() and not overwrite:
                raise TXTExportError(
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
                    file.flush()
                    os.fsync(file.fileno())

                if destination.exists() and not overwrite:
                    raise TXTExportError(
                        f"O ficheiro já existe: {destination}"
                    )

                os.replace(temporary_path, destination)

            finally:
                if temporary_path.exists():
                    temporary_path.unlink()

            return destination

        except TXTExportError:
            raise

        except OSError as exc:
            raise TXTExportError(
                f"Falha ao guardar o relatório: {exc}"
            ) from exc

    def export_report(
        self,
        report: Any,
        filename: str,
        overwrite: bool = False,
    ) -> Path:
        return self.export(report, filename, overwrite)


TextExporter = TXTExporter
TXTReportExporter = TXTExporter
TxtExporter = TXTExporter

__all__ = [
    "TXTExportError",
    "TXTExporter",
    "TextExporter",
    "TXTReportExporter",
    "TxtExporter",
]
