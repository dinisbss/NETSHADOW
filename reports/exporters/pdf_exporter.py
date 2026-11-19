
from __future__ import annotations

import os
import tempfile

from dataclasses import asdict, is_dataclass
from datetime import date, datetime
from enum import Enum
from pathlib import Path
from typing import Any, Optional

try:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_LEFT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        SimpleDocTemplate,
        Paragraph,
        Spacer,
        Table,
        TableStyle,
        PageBreak,
        KeepTogether,
    )
except ImportError as exc:
    raise ImportError(
        "ReportLab não está instalado. Executa: "
        "py -m pip install reportlab"
    ) from exc


class PDFExportError(Exception):
    """Erro durante a exportação PDF."""


class PDFExporter:
    """Exportador de relatórios PDF do NETSHADOW."""

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

        raise PDFExportError(
            f"Tipo não suportado: {type(value).__name__}"
        )

    @staticmethod
    def _escape(value: Any) -> str:
        text = "—" if value is None else str(value)

        return (
            text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#x27;")
            .replace("\n", "<br/>")
        )

    @staticmethod
    def _risk_color(value: Any):
        normalized = str(value).strip().lower()

        mapping = {
            "critical": colors.HexColor("#b91c1c"),
            "critico": colors.HexColor("#b91c1c"),
            "crítico": colors.HexColor("#b91c1c"),
            "high": colors.HexColor("#ea580c"),
            "alto": colors.HexColor("#ea580c"),
            "medium": colors.HexColor("#ca8a04"),
            "medio": colors.HexColor("#ca8a04"),
            "médio": colors.HexColor("#ca8a04"),
            "low": colors.HexColor("#15803d"),
            "baixo": colors.HexColor("#15803d"),
            "info": colors.HexColor("#2563eb"),
        }

        return mapping.get(normalized, colors.HexColor("#334155"))

    def _create_styles(self):
        styles = getSampleStyleSheet()

        styles.add(ParagraphStyle(
            name="NetShadowTitle",
            parent=styles["Title"],
            fontSize=22,
            leading=28,
            textColor=colors.HexColor("#0f766e"),
            alignment=TA_CENTER,
            spaceAfter=12,
        ))

        styles.add(ParagraphStyle(
            name="NetShadowSubtitle",
            parent=styles["Normal"],
            fontSize=9,
            textColor=colors.HexColor("#64748b"),
            alignment=TA_CENTER,
            spaceAfter=20,
        ))

        styles.add(ParagraphStyle(
            name="NetShadowSection",
            parent=styles["Heading2"],
            fontSize=14,
            leading=18,
            textColor=colors.HexColor("#0f766e"),
            spaceBefore=14,
            spaceAfter=9,
        ))

        styles.add(ParagraphStyle(
            name="NetShadowBody",
            parent=styles["BodyText"],
            fontSize=8,
            leading=12,
            alignment=TA_LEFT,
            wordWrap="CJK",
        ))

        styles.add(ParagraphStyle(
            name="NetShadowCell",
            parent=styles["BodyText"],
            fontSize=7,
            leading=9,
            wordWrap="CJK",
        ))

        styles.add(ParagraphStyle(
            name="NetShadowHeader",
            parent=styles["BodyText"],
            fontSize=7,
            leading=9,
            textColor=colors.white,
        ))

        return styles

    def _make_table(self, rows: list, styles) -> Table:
        if not rows:
            return Table([
                [Paragraph("Sem resultados disponíveis.", styles["NetShadowBody"])]
            ])

        if not isinstance(rows[0], dict):
            rows = [
                item if isinstance(item, dict) else {"Resultado": item}
                for item in rows
            ]

        columns = list(dict.fromkeys(
            key for row in rows for key in row.keys()
        ))

        data = [[
            Paragraph(self._escape(column), styles["NetShadowHeader"])
            for column in columns
        ]]

        for row in rows:
            data.append([
                Paragraph(
                    self._escape(row.get(column)),
                    styles["NetShadowCell"],
                )
                for column in columns
            ])

        table = Table(
            data,
            repeatRows=1,
            hAlign="LEFT",
        )

        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f766e")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#cbd5e1")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [
                colors.white,
                colors.HexColor("#f1f5f9"),
            ]),
        ]))

        return table

    def _build_story(self, data: Any):
        styles = self._create_styles()
        normalized = self._serialize(data)

        sections = (
            normalized if isinstance(normalized, dict)
            else {"Resultados": normalized}
        )

        story = [
            Paragraph("NETSHADOW", styles["NetShadowTitle"]),
            Paragraph(
                self._escape(self.title),
                styles["NetShadowSubtitle"],
            ),
            Paragraph(
                "Network Intelligence &amp; Security Auditing",
                styles["NetShadowSubtitle"],
            ),
            Paragraph(
                "Gerado em: "
                + self._escape(datetime.now().astimezone().isoformat(
                    timespec="seconds"
                )),
                styles["NetShadowBody"],
            ),
            Spacer(1, 12),
        ]

        for section_name, content in sections.items():
            section = [
                Paragraph(
                    self._escape(section_name),
                    styles["NetShadowSection"],
                )
            ]

            if isinstance(content, list):
                section.append(self._make_table(content, styles))

            elif isinstance(content, dict):
                section.append(self._make_table([
                    {"Campo": key, "Valor": value}
                    for key, value in content.items()
                ], styles))

            else:
                section.append(
                    Paragraph(
                        self._escape(content),
                        styles["NetShadowBody"],
                    )
                )

            story.append(KeepTogether(section))
            story.append(Spacer(1, 8))

        return story

    @staticmethod
    def _draw_footer(canvas, document):
        canvas.saveState()

        canvas.setStrokeColor(colors.HexColor("#cbd5e1"))
        canvas.line(
            20 * mm,
            15 * mm,
            A4[0] - 20 * mm,
            15 * mm,
        )

        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#64748b"))

        canvas.drawString(
            20 * mm,
            10 * mm,
            "NETSHADOW - Relatório local",
        )

        canvas.drawRightString(
            A4[0] - 20 * mm,
            10 * mm,
            f"Página {document.page}",
        )

        canvas.restoreState()

    def export(
        self,
        data: Any,
        filename: str,
        overwrite: bool = False,
    ) -> Path:
        """Gera e guarda um relatório PDF."""

        if not isinstance(filename, str) or not filename.strip():
            raise PDFExportError("O nome do ficheiro é obrigatório.")

        if Path(filename).name != filename or filename in {".", ".."}:
            raise PDFExportError("Nome de ficheiro inválido.")

        if not filename.lower().endswith(".pdf"):
            filename += ".pdf"

        try:
            story = self._build_story(data)

            self.output_directory.mkdir(
                parents=True,
                exist_ok=True,
            )

            destination = self.output_directory / filename

            if destination.is_symlink():
                raise PDFExportError(
                    "Não é permitido exportar para um link simbólico."
                )

            if destination.exists() and not overwrite:
                raise PDFExportError(
                    f"O ficheiro já existe: {destination}"
                )

            descriptor, temporary_name = tempfile.mkstemp(
                prefix=".netshadow_",
                suffix=".pdf",
                dir=self.output_directory,
            )
            os.close(descriptor)

            temporary_path = Path(temporary_name)

            try:
                document = SimpleDocTemplate(
                    str(temporary_path),
                    pagesize=A4,
                    rightMargin=20 * mm,
                    leftMargin=20 * mm,
                    topMargin=20 * mm,
                    bottomMargin=22 * mm,
                    title=self.title,
                    author="NETSHADOW",
                )

                document.build(
                    story,
                    onFirstPage=self._draw_footer,
                    onLaterPages=self._draw_footer,
                )

                if destination.exists() and not overwrite:
                    raise PDFExportError(
                        f"O ficheiro já existe: {destination}"
                    )

                os.replace(temporary_path, destination)

            finally:
                if temporary_path.exists():
                    temporary_path.unlink()

            return destination

        except PDFExportError:
            raise

        except Exception as exc:
            raise PDFExportError(
                f"Falha ao gerar o PDF: {exc}"
            ) from exc

    def export_report(
        self,
        report: Any,
        filename: str,
        overwrite: bool = False,
    ) -> Path:
        return self.export(report, filename, overwrite)


PDFReportExporter = PDFExporter
PdfExporter = PDFExporter

__all__ = [
    "PDFExportError",
    "PDFExporter",
    "PDFReportExporter",
    "PdfExporter",
]
