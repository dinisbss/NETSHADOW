
"""
NETSHADOW - Scan Repository

Gestão do histórico de auditorias e respetivos estados.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from typing import Optional

from database.database import DatabaseManager, DatabaseError


class ScanRepositoryError(RuntimeError):
    """Erro nas operações do repositório de auditorias."""


class ScanRepository:
    """Gere os registos de auditorias na base de dados."""

    VALID_STATUSES = {
        "pending",
        "running",
        "completed",
        "failed",
        "cancelled",
    }

    VALID_SCAN_TYPES = {
        "discovery",
        "network",
        "device",
        "security",
        "ports",
        "services",
        "full",
        "manual",
    }

    def __init__(self, database: DatabaseManager) -> None:
        if not isinstance(database, DatabaseManager):
            raise TypeError("É necessário fornecer um DatabaseManager.")

        self.database = database
        self.database.connect()
        self.database.initialize()

    @staticmethod
    def _to_dict(row: Optional[sqlite3.Row]) -> Optional[dict]:
        return dict(row) if row is not None else None

    @staticmethod
    def _validate_id(scan_id: int) -> None:
        if not isinstance(scan_id, int) or scan_id <= 0:
            raise ScanRepositoryError(
                "Identificador de auditoria inválido."
            )

    def _validate_network(self, network_id: Optional[int]) -> None:
        if network_id is None:
            return

        if not isinstance(network_id, int) or network_id <= 0:
            raise ScanRepositoryError(
                "Identificador de rede inválido."
            )

        row = self.database.fetchone(
            "SELECT id FROM networks WHERE id = ?",
            (network_id,),
        )

        if row is None:
            raise ScanRepositoryError(
                "A rede indicada não existe."
            )

    def create(
        self,
        scan_type: str,
        network_id: Optional[int] = None,
    ) -> dict:
        """Cria um novo registo de auditoria."""
        if not isinstance(scan_type, str):
            raise ScanRepositoryError(
                "Tipo de auditoria inválido."
            )

        scan_type = scan_type.strip().lower()

        if scan_type not in self.VALID_SCAN_TYPES:
            raise ScanRepositoryError(
                f"Tipo de auditoria não suportado: {scan_type}"
            )

        self._validate_network(network_id)

        try:
            cursor = self.database.execute(
                """
                INSERT INTO scans (network_id, scan_type, status)
                VALUES (?, ?, 'pending')
                """,
                (network_id, scan_type),
            )

            result = self.get_by_id(cursor.lastrowid)

            if result is None:
                raise ScanRepositoryError(
                    "Não foi possível recuperar a auditoria criada."
                )

            return result

        except DatabaseError as exc:
            raise ScanRepositoryError(
                f"Erro ao criar auditoria: {exc}"
            ) from exc

    def get_by_id(self, scan_id: int) -> Optional[dict]:
        """Consulta uma auditoria pelo identificador."""
        self._validate_id(scan_id)

        try:
            row = self.database.fetchone(
                "SELECT * FROM scans WHERE id = ?",
                (scan_id,),
            )
            return self._to_dict(row)

        except DatabaseError as exc:
            raise ScanRepositoryError(
                f"Erro ao consultar auditoria: {exc}"
            ) from exc

    def get_all(
        self,
        status: Optional[str] = None,
        network_id: Optional[int] = None,
        limit: int = 100,
    ) -> list[dict]:
        """Lista auditorias com filtros opcionais."""
        if not isinstance(limit, int) or not 1 <= limit <= 1000:
            raise ScanRepositoryError(
                "O limite deve estar entre 1 e 1000."
            )

        conditions = []
        parameters = []

        if status is not None:
            status = status.strip().lower()

            if status not in self.VALID_STATUSES:
                raise ScanRepositoryError(
                    "Estado de auditoria inválido."
                )

            conditions.append("status = ?")
            parameters.append(status)

        if network_id is not None:
            self._validate_network(network_id)
            conditions.append("network_id = ?")
            parameters.append(network_id)

        query = "SELECT * FROM scans"

        if conditions:
            query += " WHERE " + " AND ".join(conditions)

        query += " ORDER BY id DESC LIMIT ?"
        parameters.append(limit)

        try:
            rows = self.database.fetchall(query, tuple(parameters))
            return [dict(row) for row in rows]

        except DatabaseError as exc:
            raise ScanRepositoryError(
                f"Erro ao listar auditorias: {exc}"
            ) from exc

    def start(self, scan_id: int) -> Optional[dict]:
        """Marca uma auditoria como iniciada."""
        return self._change_status(scan_id, "running")

    def complete(self, scan_id: int) -> Optional[dict]:
        """Marca uma auditoria como concluída."""
        return self._change_status(scan_id, "completed", finish=True)

    def fail(self, scan_id: int) -> Optional[dict]:
        """Marca uma auditoria como falhada."""
        return self._change_status(scan_id, "failed", finish=True)

    def cancel(self, scan_id: int) -> Optional[dict]:
        """Marca uma auditoria como cancelada."""
        return self._change_status(scan_id, "cancelled", finish=True)

    def _change_status(
        self,
        scan_id: int,
        new_status: str,
        finish: bool = False,
    ) -> Optional[dict]:
        self._validate_id(scan_id)

        current = self.get_by_id(scan_id)

        if current is None:
            return None

        allowed_transitions = {
            "pending": {"running", "cancelled", "failed"},
            "running": {"completed", "failed", "cancelled"},
            "completed": set(),
            "failed": set(),
            "cancelled": set(),
        }

        if new_status not in allowed_transitions[current["status"]]:
            raise ScanRepositoryError(
                f"Transição inválida: {current['status']} -> {new_status}"
            )

        try:
            if finish:
                self.database.execute(
                    """
                    UPDATE scans
                    SET status = ?, finished_at = ?
                    WHERE id = ?
                    """,
                    (
                        new_status,
                        datetime.now(timezone.utc).isoformat(),
                        scan_id,
                    ),
                )
            else:
                self.database.execute(
                    """
                    UPDATE scans
                    SET status = ?
                    WHERE id = ?
                    """,
                    (new_status, scan_id),
                )

            return self.get_by_id(scan_id)

        except DatabaseError as exc:
            raise ScanRepositoryError(
                f"Erro ao atualizar estado da auditoria: {exc}"
            ) from exc

    def delete(self, scan_id: int) -> bool:
        """Elimina um registo de auditoria."""
        self._validate_id(scan_id)

        try:
            cursor = self.database.execute(
                "DELETE FROM scans WHERE id = ?",
                (scan_id,),
            )
            return cursor.rowcount > 0

        except DatabaseError as exc:
            raise ScanRepositoryError(
                f"Erro ao eliminar auditoria: {exc}"
            ) from exc

    def count(self, status: Optional[str] = None) -> int:
        """Conta auditorias, opcionalmente por estado."""
        try:
            if status is None:
                row = self.database.fetchone(
                    "SELECT COUNT(*) AS total FROM scans"
                )
            else:
                status = status.strip().lower()

                if status not in self.VALID_STATUSES:
                    raise ScanRepositoryError(
                        "Estado de auditoria inválido."
                    )

                row = self.database.fetchone(
                    """
                    SELECT COUNT(*) AS total
                    FROM scans WHERE status = ?
                    """,
                    (status,),
                )

            return int(row["total"]) if row else 0

        except DatabaseError as exc:
            raise ScanRepositoryError(
                f"Erro ao contar auditorias: {exc}"
            ) from exc
