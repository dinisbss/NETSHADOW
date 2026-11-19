
"""
NETSHADOW - Findings Repository

Gestão das descobertas e observações de segurança.
"""

from __future__ import annotations

import sqlite3
from typing import Optional

from database.database import DatabaseManager, DatabaseError


class FindingsRepositoryError(RuntimeError):
    """Erro nas operações do repositório de descobertas."""


class FindingsRepository:
    """Gere as descobertas registadas pelo NETSHADOW."""

    VALID_SEVERITIES = {
        "info",
        "low",
        "medium",
        "high",
        "critical",
    }

    def __init__(self, database: DatabaseManager) -> None:
        if not isinstance(database, DatabaseManager):
            raise TypeError("É necessário fornecer um DatabaseManager.")

        self.database = database
        self.database.connect()
        self.database.initialize()

    @staticmethod
    def _validate_id(value: int, field: str) -> None:
        if not isinstance(value, int) or value <= 0:
            raise FindingsRepositoryError(
                f"Identificador de {field} inválido."
            )

    @staticmethod
    def _validate_text(
        value: str,
        field: str,
        maximum: int = 500,
    ) -> str:
        if not isinstance(value, str) or not value.strip():
            raise FindingsRepositoryError(
                f"O campo {field} não pode estar vazio."
            )

        value = value.strip()

        if len(value) > maximum:
            raise FindingsRepositoryError(
                f"O campo {field} excede {maximum} caracteres."
            )

        return value

    @staticmethod
    def _to_dict(
        row: Optional[sqlite3.Row],
    ) -> Optional[dict]:
        return dict(row) if row is not None else None

    def _validate_references(
        self,
        scan_id: Optional[int],
        device_id: Optional[int],
    ) -> None:
        if scan_id is not None:
            self._validate_id(scan_id, "auditoria")

            if self.database.fetchone(
                "SELECT id FROM scans WHERE id = ?",
                (scan_id,),
            ) is None:
                raise FindingsRepositoryError(
                    "A auditoria indicada não existe."
                )

        if device_id is not None:
            self._validate_id(device_id, "dispositivo")

            if self.database.fetchone(
                "SELECT id FROM devices WHERE id = ?",
                (device_id,),
            ) is None:
                raise FindingsRepositoryError(
                    "O dispositivo indicado não existe."
                )

    def create(
        self,
        title: str,
        severity: str = "info",
        description: Optional[str] = None,
        scan_id: Optional[int] = None,
        device_id: Optional[int] = None,
    ) -> dict:
        """Regista uma nova descoberta."""
        title = self._validate_text(title, "title", 255)

        if description is not None:
            description = self._validate_text(
                description,
                "description",
                5000,
            )

        if not isinstance(severity, str):
            raise FindingsRepositoryError(
                "Gravidade inválida."
            )

        severity = severity.strip().lower()

        if severity not in self.VALID_SEVERITIES:
            raise FindingsRepositoryError(
                "Gravidade não suportada."
            )

        self._validate_references(scan_id, device_id)

        try:
            cursor = self.database.execute(
                """
                INSERT INTO findings (
                    scan_id,
                    device_id,
                    title,
                    description,
                    severity
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    device_id,
                    title,
                    description,
                    severity,
                ),
            )

            result = self.get_by_id(cursor.lastrowid)

            if result is None:
                raise FindingsRepositoryError(
                    "Não foi possível recuperar a descoberta criada."
                )

            return result

        except DatabaseError as exc:
            raise FindingsRepositoryError(
                f"Erro ao registar descoberta: {exc}"
            ) from exc

    def get_by_id(self, finding_id: int) -> Optional[dict]:
        """Consulta uma descoberta pelo identificador."""
        self._validate_id(finding_id, "descoberta")

        try:
            row = self.database.fetchone(
                "SELECT * FROM findings WHERE id = ?",
                (finding_id,),
            )
            return self._to_dict(row)

        except DatabaseError as exc:
            raise FindingsRepositoryError(
                f"Erro ao consultar descoberta: {exc}"
            ) from exc

    def get_all(
        self,
        severity: Optional[str] = None,
        scan_id: Optional[int] = None,
        device_id: Optional[int] = None,
        limit: int = 100,
    ) -> list[dict]:
        """Lista descobertas com filtros opcionais."""
        if not isinstance(limit, int) or not 1 <= limit <= 1000:
            raise FindingsRepositoryError(
                "O limite deve estar entre 1 e 1000."
            )

        conditions = []
        parameters = []

        if severity is not None:
            if not isinstance(severity, str):
                raise FindingsRepositoryError(
                    "Gravidade inválida."
                )

            severity = severity.strip().lower()

            if severity not in self.VALID_SEVERITIES:
                raise FindingsRepositoryError(
                    "Gravidade não suportada."
                )

            conditions.append("severity = ?")
            parameters.append(severity)

        if scan_id is not None:
            self._validate_id(scan_id, "auditoria")
            conditions.append("scan_id = ?")
            parameters.append(scan_id)

        if device_id is not None:
            self._validate_id(device_id, "dispositivo")
            conditions.append("device_id = ?")
            parameters.append(device_id)

        query = "SELECT * FROM findings"

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
            raise FindingsRepositoryError(
                f"Erro ao listar descobertas: {exc}"
            ) from exc

    def update(
        self,
        finding_id: int,
        title: Optional[str] = None,
        description: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> Optional[dict]:
        """Atualiza uma descoberta existente."""
        self._validate_id(finding_id, "descoberta")

        current = self.get_by_id(finding_id)

        if current is None:
            return None

        new_title = (
            self._validate_text(title, "title", 255)
            if title is not None
            else current["title"]
        )

        new_description = (
            self._validate_text(
                description,
                "description",
                5000,
            )
            if description is not None
            else current["description"]
        )

        new_severity = (
            severity.strip().lower()
            if isinstance(severity, str)
            else current["severity"]
        )

        if severity is not None and not isinstance(severity, str):
            raise FindingsRepositoryError(
                "Gravidade inválida."
            )

        if new_severity not in self.VALID_SEVERITIES:
            raise FindingsRepositoryError(
                "Gravidade não suportada."
            )

        try:
            self.database.execute(
                """
                UPDATE findings
                SET title = ?,
                    description = ?,
                    severity = ?
                WHERE id = ?
                """,
                (
                    new_title,
                    new_description,
                    new_severity,
                    finding_id,
                ),
            )

            return self.get_by_id(finding_id)

        except DatabaseError as exc:
            raise FindingsRepositoryError(
                f"Erro ao atualizar descoberta: {exc}"
            ) from exc

    def delete(self, finding_id: int) -> bool:
        """Elimina uma descoberta."""
        self._validate_id(finding_id, "descoberta")

        try:
            cursor = self.database.execute(
                "DELETE FROM findings WHERE id = ?",
                (finding_id,),
            )
            return cursor.rowcount > 0

        except DatabaseError as exc:
            raise FindingsRepositoryError(
                f"Erro ao eliminar descoberta: {exc}"
            ) from exc

    def count(self, severity: Optional[str] = None) -> int:
        """Conta descobertas, opcionalmente por gravidade."""
        try:
            if severity is None:
                row = self.database.fetchone(
                    "SELECT COUNT(*) AS total FROM findings"
                )
            else:
                severity = severity.strip().lower()

                if severity not in self.VALID_SEVERITIES:
                    raise FindingsRepositoryError(
                        "Gravidade não suportada."
                    )

                row = self.database.fetchone(
                    """
                    SELECT COUNT(*) AS total
                    FROM findings
                    WHERE severity = ?
                    """,
                    (severity,),
                )

            return int(row["total"]) if row else 0

        except DatabaseError as exc:
            raise FindingsRepositoryError(
                f"Erro ao contar descobertas: {exc}"
            ) from exc
