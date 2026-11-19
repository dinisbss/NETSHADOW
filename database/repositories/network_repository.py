
"""
NETSHADOW - Network Repository

Persistência de redes na base de dados.
Compatível com NetworkModel e consultas parametrizadas.
"""

from __future__ import annotations

import ipaddress
import sqlite3

from typing import Optional

from database.database import DatabaseManager, DatabaseError
from database.models import NetworkModel, ModelError


class NetworkRepositoryError(RuntimeError):
    """Erro nas operações do repositório de redes."""


class NetworkRepository:
    """Gere os registos de redes."""

    def __init__(self, database: DatabaseManager) -> None:
        if not isinstance(database, DatabaseManager):
            raise TypeError(
                "É necessário fornecer um DatabaseManager."
            )

        self.database = database
        self.database.connect()
        self.database.initialize()

    @staticmethod
    def _validate_network(value: str) -> str:
        if not isinstance(value, str):
            raise NetworkRepositoryError(
                "O endereço de rede tem de ser texto."
            )

        try:
            return str(
                ipaddress.ip_network(value, strict=False)
            )
        except ValueError as exc:
            raise NetworkRepositoryError(
                "Endereço de rede inválido."
            ) from exc

    @staticmethod
    def _validate_name(value: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise NetworkRepositoryError(
                "O nome da rede não pode estar vazio."
            )

        value = value.strip()

        if len(value) > 100:
            raise NetworkRepositoryError(
                "O nome da rede excede 100 caracteres."
            )

        return value

    @staticmethod
    def _to_model(
        row: Optional[sqlite3.Row],
    ) -> Optional[NetworkModel]:
        if row is None:
            return None

        data = dict(row)

        network = (
            data.get("network")
            or data.get("network_address")
        )

        if not network:
            raise NetworkRepositoryError(
                "O registo não contém um endereço de rede."
            )

        return NetworkModel(
            network=network,
            name=data["name"],
            description=data.get("description") or "",
            network_id=data["id"],
            created_at=data.get("created_at"),
            updated_at=data.get("updated_at")
            or data.get("created_at"),
        )

    def create(
        self,
        network: NetworkModel | str,
        network_address: Optional[str] = None,
    ) -> NetworkModel:
        """
        Cria uma rede.

        Aceita NetworkModel ou a forma antiga:
        create(name, network_address).
        """

        if isinstance(network, NetworkModel):
            model = network

        elif isinstance(network, str):
            if network_address is None:
                raise NetworkRepositoryError(
                    "O endereço da rede é obrigatório."
                )

            model = NetworkModel(
                network=network_address,
                name=network,
            )

        else:
            raise NetworkRepositoryError(
                "É necessário fornecer um NetworkModel."
            )

        try:
            cursor = self.database.execute(
                """
                INSERT INTO networks (
                    network,
                    network_address,
                    name,
                    description,
                    created_at,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    model.network,
                    model.network,
                    model.name,
                    model.description,
                    model.created_at,
                    model.updated_at,
                ),
            )

            result = self.get_by_id(cursor.lastrowid)

            if result is None:
                raise NetworkRepositoryError(
                    "Não foi possível recuperar a rede criada."
                )

            return result

        except DatabaseError as exc:
            raise NetworkRepositoryError(
                f"Erro ao registar rede: {exc}"
            ) from exc

        except sqlite3.Error as exc:
            raise NetworkRepositoryError(
                f"Erro SQLite ao registar rede: {exc}"
            ) from exc

    def get_by_id(
        self,
        network_id: int,
    ) -> Optional[NetworkModel]:
        """Procura uma rede pelo identificador."""

        if (
            not isinstance(network_id, int)
            or isinstance(network_id, bool)
            or network_id <= 0
        ):
            raise NetworkRepositoryError(
                "Identificador de rede inválido."
            )

        try:
            row = self.database.fetchone(
                "SELECT * FROM networks WHERE id = ?",
                (network_id,),
            )

            return self._to_model(row)

        except DatabaseError as exc:
            raise NetworkRepositoryError(
                f"Erro ao consultar rede: {exc}"
            ) from exc

    def get_by_address(
        self,
        network_address: str,
    ) -> Optional[NetworkModel]:
        """Procura uma rede pelo endereço."""

        network_address = self._validate_network(
            network_address
        )

        try:
            row = self.database.fetchone(
                """
                SELECT * FROM networks
                WHERE network = ? OR network_address = ?
                ORDER BY id DESC
                LIMIT 1
                """,
                (network_address, network_address),
            )

            return self._to_model(row)

        except DatabaseError as exc:
            raise NetworkRepositoryError(
                f"Erro ao consultar rede: {exc}"
            ) from exc

    def get_all(self) -> list[NetworkModel]:
        """Devolve todas as redes registadas."""

        try:
            rows = self.database.fetchall(
                "SELECT * FROM networks ORDER BY id DESC"
            )

            return [
                self._to_model(row)
                for row in rows
            ]

        except DatabaseError as exc:
            raise NetworkRepositoryError(
                f"Erro ao listar redes: {exc}"
            ) from exc

    def update(
        self,
        network_id: int,
        name: Optional[str] = None,
        network_address: Optional[str] = None,
        description: Optional[str] = None,
    ) -> Optional[NetworkModel]:
        """Atualiza uma rede."""

        current = self.get_by_id(network_id)

        if current is None:
            return None

        new_name = (
            self._validate_name(name)
            if name is not None
            else current.name
        )

        new_network = (
            self._validate_network(network_address)
            if network_address is not None
            else current.network
        )

        new_description = (
            description
            if description is not None
            else current.description
        )

        if not isinstance(new_description, str):
            raise NetworkRepositoryError(
                "A descrição tem de ser texto."
            )

        try:
            self.database.execute(
                """
                UPDATE networks
                SET network = ?,
                    network_address = ?,
                    name = ?,
                    description = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (
                    new_network,
                    new_network,
                    new_name,
                    new_description,
                    network_id,
                ),
            )

            return self.get_by_id(network_id)

        except DatabaseError as exc:
            raise NetworkRepositoryError(
                f"Erro ao atualizar rede: {exc}"
            ) from exc

    def delete(self, network_id: int) -> bool:
        """Elimina uma rede."""

        if (
            not isinstance(network_id, int)
            or isinstance(network_id, bool)
            or network_id <= 0
        ):
            raise NetworkRepositoryError(
                "Identificador de rede inválido."
            )

        try:
            cursor = self.database.execute(
                "DELETE FROM networks WHERE id = ?",
                (network_id,),
            )

            return cursor.rowcount > 0

        except DatabaseError as exc:
            raise NetworkRepositoryError(
                f"Erro ao eliminar rede: {exc}"
            ) from exc

    def count(self) -> int:
        """Conta as redes registadas."""

        try:
            row = self.database.fetchone(
                "SELECT COUNT(*) AS total FROM networks"
            )

            return int(row["total"]) if row else 0

        except DatabaseError as exc:
            raise NetworkRepositoryError(
                f"Erro ao contar redes: {exc}"
            ) from exc


__all__ = [
    "NetworkRepository",
    "NetworkRepositoryError",
]
