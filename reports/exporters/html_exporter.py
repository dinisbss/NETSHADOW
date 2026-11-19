
from __future__ import annotations

import html
import json
import os
import tempfile

from dataclasses import asdict, is_dataclass
from datetime import date, datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Optional


class HTMLExportError(Exception):
    """Erro durante a exportação HTML."""


class HTMLExporter:
    """Gera relatórios HTML locais do NETSHADOW."""

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

        raise HTMLExportError(
            f"Tipo de dados não suportado: {type(value).__name__}"
        )

    @staticmethod
    def _escape(value: Any) -> str:
        if value is None:
            return "—"
        if isinstance(value, (dict, list)):
            value = json.dumps(value, ensure_ascii=False, indent=2)
        return html.escape(str(value), quote=True)

    @staticmethod
    def _risk_class(value: Any) -> str:
        normalized = str(value).strip().lower()

        allowed = {
            "critical": "critical",
            "critico": "critical",
            "crítico": "critical",
            "high": "high",
            "alto": "high",
            "medium": "medium",
            "medio": "medium",
            "médio": "medium",
            "low": "low",
            "baixo": "low",
            "info": "info",
            "informational": "info",
        }

        return allowed.get(normalized, "neutral")

    def _render_table(self, rows: list[Any]) -> str:
        if not rows:
            return "<p class='empty'>Sem resultados disponíveis.</p>"

        if not isinstance(rows[0], dict):
            rows = [
                item if isinstance(item, dict) else {"Resultado": item}
                for item in rows
            ]

        columns = list(dict.fromkeys(
            key for row in rows for key in row.keys()
        ))

        header = "".join(
            f"<th>{self._escape(column)}</th>"
            for column in columns
        )

        body = []

        for row in rows:
            cells = []

            for column in columns:
                value = row.get(column)

                if str(column).lower() in {
                    "risk", "severity", "priority", "gravidade"
                }:
                    risk_class = self._risk_class(value)
                    cells.append(
                        f"<td><span class='risk {risk_class}'>"
                        f"{self._escape(value)}</span></td>"
                    )
                else:
                    cells.append(
                        f"<td>{self._escape(value)}</td>"
                    )

            body.append("<tr>" + "".join(cells) + "</tr>")

        return (
            "<div class='table-container'><table>"
            f"<thead><tr>{header}</tr></thead>"
            f"<tbody>{''.join(body)}</tbody>"
            "</table></div>"
        )

    def render(self, data: Any) -> str:
        """Produz o documento HTML completo."""

        normalized = self._serialize(data)

        if isinstance(normalized, dict):
            sections = normalized
        else:
            sections = {"Resultados": normalized}

        generated_at = datetime.now(timezone.utc).isoformat(
            timespec="seconds"
        )

        summary = {
            "Secções": len(sections),
            "Dispositivos": len(
                sections.get("devices", [])
            ) if isinstance(sections.get("devices", []), list) else 0,
            "Findings": len(
                sections.get("findings", [])
            ) if isinstance(sections.get("findings", []), list) else 0,
        }

        cards = "".join(
            f"<div class='card'><span>{self._escape(key)}</span>"
            f"<strong>{self._escape(value)}</strong></div>"
            for key, value in summary.items()
        )

        content = []

        for name, value in sections.items():
            section_title = self._escape(name)

            if isinstance(value, list):
                section_content = self._render_table(value)
            elif isinstance(value, dict):
                section_content = self._render_table([
                    {"Campo": key, "Valor": item}
                    for key, item in value.items()
                ])
            else:
                section_content = (
                    f"<p>{self._escape(value)}</p>"
                )

            content.append(
                f"<section><h2>{section_title}</h2>"
                f"{section_content}</section>"
            )

        return f"""<!DOCTYPE html>
<html lang="pt-PT">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="generator" content="NETSHADOW">
<title>{self._escape(self.title)}</title>
<style>
:root {{
    color-scheme: dark;
    font-family: Arial, sans-serif;
    background: #10151d;
    color: #e6edf3;
}}
* {{ box-sizing: border-box; }}
body {{
    margin: 0;
    padding: 30px;
    background: #10151d;
}}
main {{ max-width: 1150px; margin: auto; }}
header {{
    padding: 28px;
    background: #192330;
    border: 1px solid #2c3b4c;
    border-radius: 12px;
    margin-bottom: 25px;
}}
h1 {{ color: #55d6be; margin: 0 0 10px; }}
h2 {{ color: #55d6be; font-size: 19px; }}
.muted, .empty {{ color: #9baabd; }}
.cards {{
    display: grid;
    grid-template-columns: repeat(auto-fit,minmax(160px,1fr));
    gap: 14px;
    margin-bottom: 25px;
}}
.card {{
    background: #192330;
    border: 1px solid #2c3b4c;
    padding: 20px;
    border-radius: 10px;
}}
.card span {{ display: block; color: #9baabd; }}
.card strong {{ display: block; font-size: 25px; margin-top: 8px; }}
section {{
    background: #192330;
    border: 1px solid #2c3b4c;
    padding: 20px;
    border-radius: 10px;
    margin-bottom: 18px;
}}
.table-container {{ overflow-x: auto; }}
table {{ width: 100%; border-collapse: collapse; }}
th, td {{
    padding: 12px;
    text-align: left;
    border-bottom: 1px solid #2c3b4c;
    vertical-align: top;
    white-space: pre-wrap;
}}
th {{ color: #55d6be; }}
.risk {{ font-weight: bold; }}
.critical {{ color: #ff6262; }}
.high {{ color: #ff9b62; }}
.medium {{ color: #f4ce67; }}
.low {{ color: #70d6a1; }}
.info {{ color: #75baff; }}
.neutral {{ color: #c4ccd5; }}
footer {{
    color: #9baabd;
    text-align: center;
    margin-top: 30px;
    font-size: 12px;
}}
@media(max-width:600px) {{
    body {{ padding: 12px; }}
    header, section {{ padding: 16px; }}
}}
</style>
</head>
<body>
<main>
<header>
<h1>NETSHADOW</h1>
<p>Network Intelligence &amp; Security Auditing</p>
<p class="muted">{self._escape(self.title)}</p>
<p class="muted">Gerado em: {self._escape(generated_at)}</p>
</header>
<div class="cards">{cards}</div>
{''.join(content)}
<footer>NETSHADOW — Relatório gerado localmente</footer>
</main>
</body>
</html>
"""

    def export(
        self,
        data: Any,
        filename: str,
        overwrite: bool = False,
    ) -> Path:
        """Guarda o relatório HTML no disco."""

        if not isinstance(filename, str) or not filename.strip():
            raise HTMLExportError("O nome do ficheiro é obrigatório.")

        if Path(filename).name != filename or filename in {".", ".."}:
            raise HTMLExportError("Nome de ficheiro inválido.")

        if not filename.lower().endswith(".html"):
            filename += ".html"

        content = self.render(data)

        try:
            self.output_directory.mkdir(
                parents=True,
                exist_ok=True,
            )

            destination = self.output_directory / filename

            if destination.is_symlink():
                raise HTMLExportError(
                    "Não é permitido exportar para um link simbólico."
                )

            if destination.exists() and not overwrite:
                raise HTMLExportError(
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
                    raise HTMLExportError(
                        f"O ficheiro já existe: {destination}"
                    )

                os.replace(temporary_path, destination)

            finally:
                if temporary_path.exists():
                    temporary_path.unlink()

            return destination

        except HTMLExportError:
            raise
        except OSError as exc:
            raise HTMLExportError(
                f"Falha ao guardar o relatório: {exc}"
            ) from exc

    def export_report(
        self,
        report: Any,
        filename: str,
        overwrite: bool = False,
    ) -> Path:
        return self.export(report, filename, overwrite)


HTMLReportExporter = HTMLExporter
HtmlExporter = HTMLExporter

__all__ = [
    "HTMLExportError",
    "HTMLExporter",
    "HTMLReportExporter",
    "HtmlExporter",
]
