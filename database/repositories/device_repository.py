
"""
NETSHADOW - Device Repository

Gestão dos dispositivos registados na base de dados.
"""

from __future__ import annotations

import ipaddress
import re
import sqlite3
from typing import Optional

from database.database import DatabaseManager, DatabaseError


class DeviceRepositoryError(RuntimeError):
    """Erro nas operações do repositório de dispositivos."""


class DeviceRepository:
    """Gere os dispositivos conhecidos pelo NETSHADOW."""

    def __init__(self, database: DatabaseManager) -> None:
        if not isinstance(database, DatabaseManager):
            raise TypeError("É necessário fornecer um DatabaseManager.")

        self.database = database
        self.database.connect()
        self.database.initialize()

    @staticmethod
    def _validate_ip(ip_address: str) -> str:
        try:
            return str(ipaddress.ip_address(ip_address))
        except (ValueError, TypeError) as exc:
            raise DeviceRepositoryError(
                "Endereço IP inválido."
            ) from exc

    @staticmethod
    def _validate_mac(mac_address: Optional[str]) -> Optional[str]:
        if mac_address is None:
            return None

        pattern = r"^(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$"

        if not re.fullmatch(pattern, mac_address):
            raise DeviceRepositoryError("Endereço MAC inválido.")

        return mac_address.replace("-", ":").lower()

    @staticmethod
    def _validate_text(
        value: Optional[str],
        field: str,
        maximum: int = 255,
    ) -> Optional[str]:
        if value is None:
            return None

        if not isinstance(value, str):
            raise DeviceRepositoryError(
                f"O campo {field} tem de ser texto."
            )

        value = value.strip()

        if len(value) > maximum:
            raise DeviceRepositoryError(
                f"O campo {field} excede o limite permitido."
            )

        return value or None

    @staticmethod
    def _to_dict(row: Optional[sqlite3.Row]) -> Optional[dict]:
        return dict(row) if row is not None else None

    def create(
        self,
        ip_address: str,
        mac_address: Optional[str] = None,
        hostname: Optional[str] = None,
        vendor: Optional[str] = None,
        network_id: Optional[int] = None,
    ) -> dict:
        """Regista um dispositivo."""
        ip_address = self._validate_ip(ip_address)
        mac_address = self._validate_mac(mac_address)
        hostname = self._validate_text(hostname, "hostname")
        vendor = self._validate_text(vendor, "vendor")

        if network_id is not None:
            if not isinstance(network_id, int) or network_id <= 0:
                raise DeviceRepositoryError(
                    "Identificador de rede inválido."
                )

            if self.database.fetchone(
                "SELECT id FROM networks WHERE id = ?",
                (network_id,),
            ) is None:
                raise DeviceRepositoryError(
                    "A rede indicada não existe."
                )

        try:
            cursor = self.database.execute(
                """
                INSERT INTO devices (
                    ip_address,
                    mac_address,
                    hostname,
                    vendor,
                    network_id
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    ip_address,
                    mac_address,
                    hostname,
                    vendor,
                    network_id,
                ),
            )

            result = self.get_by_id(cursor.lastrowid)

            if result is None:
                raise DeviceRepositoryError(
                    "Não foi possível recuperar o dispositivo criado."
                )

            return result

        except DatabaseError as exc:
            raise DeviceRepositoryError(
                f"Erro ao registar dispositivo: {exc}"
            ) from exc

    def get_by_id(self, device_id: int) -> Optional[dict]:
        """Procura um dispositivo pelo identificador."""
        if not isinstance(device_id, int) or device_id <= 0:
            raise DeviceRepositoryError(
                "Identificador de dispositivo inválido."
            )

        try:
            row = self.database.fetchone(
                "SELECT * FROM devices WHERE id = ?",
                (device_id,),
            )
            return self._to_dict(row)

        except DatabaseError as exc:
            raise DeviceRepositoryError(
                f"Erro ao consultar dispositivo: {exc}"
            ) from exc

    def get_by_ip(self, ip_address: str) -> Optional[dict]:
        """Procura um dispositivo pelo endereço IP."""
        ip_address = self._validate_ip(ip_address)

        try:
            row = self.database.fetchone(
                """
                SELECT * FROM devices
                WHERE ip_address = ?
                ORDER BY id DESC
                LIMIT 1
                """,
                (ip_address,),
            )
            return self._to_dict(row)

        except DatabaseError as exc:
            raise DeviceRepositoryError(
                f"Erro ao consultar dispositivo: {exc}"
            ) from exc

    def get_by_mac(self, mac_address: str) -> Optional[dict]:
        """Procura um dispositivo pelo endereço MAC."""
        mac_address = self._validate_mac(mac_address)

        if mac_address is None:
            return None

        try:
            row = self.database.fetchone(
                """
                SELECT * FROM devices
                WHERE mac_address = ?
                ORDER BY id DESC
                LIMIT 1
                """,
                (mac_address,),
            )
            return self._to_dict(row)

        except DatabaseError as exc:
            raise DeviceRepositoryError(
                f"Erro ao consultar dispositivo: {exc}"
            ) from exc

    def get_all(
        self,
        network_id: Optional[int] = None,
    ) -> list[dict]:
        """Lista dispositivos, opcionalmente filtrados por rede."""
        try:
            if network_id is None:
                rows = self.database.fetchall(
                    "SELECT * FROM devices ORDER BY id DESC"
                )
            else:
                if not isinstance(network_id, int) or network_id <= 0:
                    raise DeviceRepositoryError(
                        "Identificador de rede inválido."
                    )

                rows = self.database.fetchall(
                    """
                    SELECT * FROM devices
                    WHERE network_id = ?
                    ORDER BY id DESC
                    """,
                    (network_id,),
                )

            return [dict(row) for row in rows]

        except DatabaseError as exc:
            raise DeviceRepositoryError(
                f"Erro ao listar dispositivos: {exc}"
            ) from exc

    def update(
        self,
        device_id: int,
        ip_address: Optional[str] = None,
        mac_address: Optional[str] = None,
        hostname: Optional[str] = None,
        vendor: Optional[str] = None,
        network_id: Optional[int] = None,
    ) -> Optional[dict]:
        """Atualiza os dados de um dispositivo."""
        current = self.get_by_id(device_id)

        if current is None:
            return None

        new_ip = (
            self._validate_ip(ip_address)
            if ip_address is not None
            else current["ip_address"]
        )

        new_mac = (
            self._validate_mac(mac_address)
            if mac_address is not None
            else current["mac_address"]
        )

        new_hostname = (
            self._validate_text(hostname, "hostname")
            if hostname is not None
            else current["hostname"]
        )

        new_vendor = (
            self._validate_text(vendor, "vendor")
            if vendor is not None
            else current["vendor"]
        )

        new_network = (
            network_id
            if network_id is not None
            else current["network_id"]
        )

        if new_network is not None:
            if not isinstance(new_network, int) or new_network <= 0:
                raise DeviceRepositoryError(
                    "Identificador de rede inválido."
                )

            if self.database.fetchone(
                "SELECT id FROM networks WHERE id = ?",
                (new_network,),
            ) is None:
                raise DeviceRepositoryError(
                    "A rede indicada não existe."
                )

        try:
            self.database.execute(
                """
                UPDATE devices
                SET ip_address = ?,
                    mac_address = ?,
                    hostname = ?,
                    vendor = ?,
                    network_id = ?,
                    last_seen = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (
                    new_ip,
                    new_mac,
                    new_hostname,
                    new_vendor,
                    new_network,
                    device_id,
                ),
            )

            return self.get_by_id(device_id)

        except DatabaseError as exc:
            raise DeviceRepositoryError(
                f"Erro ao atualizar dispositivo: {exc}"
            ) from exc

    def delete(self, device_id: int) -> bool:
        """Remove um dispositivo."""
        if not isinstance(device_id, int) or device_id <= 0:
            raise DeviceRepositoryError(
                "Identificador de dispositivo inválido."
            )

        try:
            cursor = self.database.execute(
                "DELETE FROM devices WHERE id = ?",
                (device_id,),
            )
            return cursor.rowcount > 0

        except DatabaseError as exc:
            raise DeviceRepositoryError(
                f"Erro ao eliminar dispositivo: {exc}"
            ) from exc

    def count(self, network_id: Optional[int] = None) -> int:
        """Conta os dispositivos registados."""
        try:
            if network_id is None:
                row = self.database.fetchone(
                    "SELECT COUNT(*) AS total FROM devices"
                )
            else:
                row = self.database.fetchone(
                    """
                    SELECT COUNT(*) AS total
                    FROM devices WHERE network_id = ?
                    """,
                    (network_id,),
                )

            return int(row["total"]) if row else 0

        except DatabaseError as exc:
            raise DeviceRepositoryError(
                f"Erro ao contar dispositivos: {exc}"
            ) from exc
