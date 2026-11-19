
"""
NETSHADOW - Report Repository

Gestão dos relatórios armazenados na base de dados.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Optional

from database.database import DatabaseManager, DatabaseError


class ReportRepositoryError(RuntimeError):
    """Erro nas operações do repositório de relatórios."""


class ReportRepository:
    """Gere os metadados dos relatórios do NETSHADOW."""

    VALID_FORMATS = {
        "json",
        "html",
        "txt",
        "pdf",
    }

    def __init__(self, database: DatabaseManager) -> None:
        if not isinstance(database, DatabaseManager):
            raise TypeError("É necessário fornecer um DatabaseManager.")

        self.database = database
        self.database.connect()
        self.database.initialize()

    @staticmethod
    def _validate_id(report_id: int) -> None:
        if not isinstance(report_id, int) or report_id <= 0:
            raise ReportRepositoryError(
                "Identificador de relatório inválido."
            )

    @staticmethod
    def _validate_path(file_path: str) -> str:
        if not isinstance(file_path, str) or not file_path.strip():
            raise ReportRepositoryError(
                "O caminho do relatório não pode estar vazio."
            )

        path = Path(file_path.strip())

        if len(str(path)) > 1000:
            raise ReportRepositoryError(
                "O caminho do relatório é demasiado longo."
            )

        return str(path)

    @staticmethod
    def _to_dict(
        row: Optional[sqlite3.Row],
    ) -> Optional[dict]:
        return dict(row) if row is not None else None

    def create(
        self,
        file_path: str,
        format: str,
        scan_id: Optional[int] = None,
    ) -> dict:
        """Regista um relatório na base de dados."""
        file_path = self._validate_path(file_path)

        if not isinstance(format, str):
            raise ReportRepositoryError(
                "Formato de relatório inválido."
            )

        format = format.strip().lower()

        if format not in self.VALID_FORMATS:
            raise ReportRepositoryError(
                "Formato não suportado."
            )

        if scan_id is not None:
            self._validate_id(scan_id)

            if self.database.fetchone(
                "SELECT id FROM scans WHERE id = ?",
                (scan_id,),
            ) is None:
                raise ReportRepositoryError(
                    "A auditoria indicada não existe."
                )

        try:
            cursor = self.database.execute(
                """
                INSERT INTO reports (scan_id, file_path, format)
                VALUES (?, ?, ?)
                """,
                (scan_id, file_path, format),
            )

            result = self.get_by_id(cursor.lastrowid)

            if result is None:
                raise ReportRepositoryError(
                    "Não foi possível recuperar o relatório criado."
                )

            return result

        except DatabaseError as exc:
            raise ReportRepositoryError(
                f"Erro ao registar relatório: {exc}"
            ) from exc

    def get_by_id(self, report_id: int) -> Optional[dict]:
        """Consulta um relatório pelo identificador."""
        self._validate_id(report_id)

        try:
            row = self.database.fetchone(
                "SELECT * FROM reports WHERE id = ?",
                (report_id,),
            )
            return self._to_dict(row)

        except DatabaseError as exc:
            raise ReportRepositoryError(
                f"Erro ao consultar relatório: {exc}"
            ) from exc

    def get_all(
        self,
        format: Optional[str] = None,
        scan_id: Optional[int] = None,
        limit: int = 100,
    ) -> list[dict]:
        """Lista relatórios com filtros opcionais."""
        if not isinstance(limit, int) or not 1 <= limit <= 1000:
            raise ReportRepositoryError(
                "O limite deve estar entre 1 e 1000."
            )

        conditions = []
        parameters = []

        if format is not None:
            if not isinstance(format, str):
                raise ReportRepositoryError(
                    "Formato inválido."
                )

            format = format.strip().lower()

            if format not in self.VALID_FORMATS:
                raise ReportRepositoryError(
                    "Formato não suportado."
                )

            conditions.append("format = ?")
            parameters.append(format)

        if scan_id is not None:
            self._validate_id(scan_id)
            conditions.append("scan_id = ?")
            parameters.append(scan_id)

        query = "SELECT * FROM reports"

        if conditions:
            query += " WHERE " + " AND ".join(conditions)

        query += " ORDER BY id DESC LIMIT ?"
        parameters.append(limit)

        try:
            rows = self.database.fetchall(
                query,
                tuple(parameters),
            )
            return [dict(row) for row in rows]

        except DatabaseError as exc:
            raise ReportRepositoryError(
                f"Erro ao listar relatórios: {exc}"
            ) from exc

    def delete(self, report_id: int) -> bool:
        """Elimina os metadados de um relatório.

        Não elimina o ficheiro físico do disco.
        """
        self._validate_id(report_id)

        try:
            cursor = self.database.execute(
                "DELETE FROM reports WHERE id = ?",
                (report_id,),
            )
            return cursor.rowcount > 0

        except DatabaseError as exc:
            raise ReportRepositoryError(
                f"Erro ao eliminar relatório: {exc}"
            ) from exc

    def count(self, format: Optional[str] = None) -> int:
        """Conta os relatórios registados."""
        try:
            if format is None:
                row = self.database.fetchone(
                    "SELECT COUNT(*) AS total FROM reports"
                )
            else:
                if not isinstance(format, str):
                    raise ReportRepositoryError(
                        "Formato inválido."
                    )

                format = format.strip().lower()

                if format not in self.VALID_FORMATS:
                    raise ReportRepositoryError(
                        "Formato não suportado."
                    )

                row = self.database.fetchone(
                    """
                    SELECT COUNT(*) AS total
                    FROM reports
                    WHERE format = ?
                    """,
                    (format,),
                )

            return int(row["total"]) if row else 0

        except DatabaseError as exc:
            raise ReportRepositoryError(
                f"Erro ao contar relatórios: {exc}"
            ) from exc
