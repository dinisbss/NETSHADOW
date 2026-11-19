
"""
NETSHADOW - Vendor Detection

Identificação passiva de fabricantes através de prefixos MAC.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from threading import RLock
from typing import Optional


class VendorDetectionError(ValueError):
    """Erro base de identificação de fabricantes."""


@dataclass(frozen=True)
class VendorInfo:
    mac_address: str
    oui: str
    vendor: Optional[str]
    identified: bool
    source: str = "local_database"

    def to_dict(self) -> dict:
        return asdict(self)


class VendorDetector:
    """Identifica fabricantes através de uma base de dados OUI local."""

    # Base de demonstração. Os prefixos devem ser confirmados
    # antes de serem utilizados como informação definitiva.
    DEFAULT_DATABASE = {
        "00000C": "Cisco Systems",
        "0001C8": "Cisco Systems",
        "000A95": "Apple",
        "001B63": "Apple",
        "3C0754": "Apple",
        "001A2B": "Ayecom Technology",
        "001C42": "Parallels",
        "005056": "VMware",
        "080027": "Oracle VirtualBox",
        "00155D": "Microsoft Hyper-V",
        "00163E": "Xensource",
        "B827EB": "Raspberry Pi Foundation",
        "DC A6 32": "Raspberry Pi Foundation",
    }

    def __init__(
        self,
        database: Optional[dict[str, str]] = None,
    ) -> None:
        self._lock = RLock()
        self._database: dict[str, str] = {}

        source = (
            database
            if database is not None
            else self.DEFAULT_DATABASE
        )

        self.load_database(source)

    @staticmethod
    def normalize_mac(mac_address: str) -> str:
        if not isinstance(mac_address, str):
            raise VendorDetectionError(
                "O endereço MAC tem de ser texto."
            )

        normalized = re.sub(
            r"[:.\-\s]",
            "",
            mac_address.strip(),
        ).upper()

        if not re.fullmatch(r"[0-9A-F]{12}", normalized):
            raise VendorDetectionError(
                "Endereço MAC inválido."
            )

        return ":".join(
            normalized[index:index + 2]
            for index in range(0, 12, 2)
        )

    @staticmethod
    def _normalize_oui(oui: str) -> str:
        if not isinstance(oui, str):
            raise VendorDetectionError(
                "O prefixo OUI tem de ser texto."
            )

        normalized = re.sub(
            r"[:.\-\s]",
            "",
            oui.strip(),
        ).upper()

        if not re.fullmatch(r"[0-9A-F]{6}", normalized):
            raise VendorDetectionError(
                "Prefixo OUI inválido."
            )

        return normalized

    @staticmethod
    def _validate_vendor(vendor: str) -> str:
        if not isinstance(vendor, str):
            raise VendorDetectionError(
                "O nome do fabricante tem de ser texto."
            )

        vendor = vendor.strip()

        if not vendor or len(vendor) > 150:
            raise VendorDetectionError(
                "Nome de fabricante inválido."
            )

        if any(ord(char) < 32 for char in vendor):
            raise VendorDetectionError(
                "Nome de fabricante contém caracteres inválidos."
            )

        return vendor

    def load_database(
        self,
        database: dict[str, str],
        replace: bool = False,
    ) -> int:
        """Carrega entradas OUI para a base de dados local."""

        if not isinstance(database, dict):
            raise VendorDetectionError(
                "A base de dados tem de ser um dicionário."
            )

        if len(database) > 100000:
            raise VendorDetectionError(
                "A base de dados excede o limite permitido."
            )

        validated = {}

        for oui, vendor in database.items():
            normalized_oui = self._normalize_oui(oui)
            normalized_vendor = self._validate_vendor(vendor)

            validated[normalized_oui] = normalized_vendor

        with self._lock:
            if replace:
                self._database = validated
            else:
                self._database.update(validated)

        return len(validated)

    def identify(self, mac_address: str) -> VendorInfo:
        """Identifica o fabricante através do prefixo MAC."""

        normalized_mac = self.normalize_mac(mac_address)

        oui = normalized_mac.replace(":", "")[:6]

        with self._lock:
            vendor = self._database.get(oui)

        return VendorInfo(
            mac_address=normalized_mac,
            oui=oui,
            vendor=vendor,
            identified=vendor is not None,
        )

    def identify_many(
        self,
        mac_addresses: list[str],
    ) -> list[VendorInfo]:
        if not isinstance(mac_addresses, list):
            raise VendorDetectionError(
                "A lista de endereços MAC é inválida."
            )

        if len(mac_addresses) > 1000:
            raise VendorDetectionError(
                "Demasiados endereços MAC."
            )

        return [
            self.identify(mac)
            for mac in mac_addresses
        ]

    def add_vendor(
        self,
        oui: str,
        vendor: str,
    ) -> None:
        normalized_oui = self._normalize_oui(oui)
        normalized_vendor = self._validate_vendor(vendor)

        with self._lock:
            self._database[normalized_oui] = normalized_vendor

    def remove_vendor(self, oui: str) -> bool:
        normalized_oui = self._normalize_oui(oui)

        with self._lock:
            return self._database.pop(
                normalized_oui,
                None,
            ) is not None

    def get_vendor(self, oui: str) -> Optional[str]:
        normalized_oui = self._normalize_oui(oui)

        with self._lock:
            return self._database.get(normalized_oui)

    def get_database(self) -> dict[str, str]:
        with self._lock:
            return dict(self._database)

    def get_summary(self) -> dict:
        with self._lock:
            return {
                "total_ouis": len(self._database),
                "unique_vendors": len(set(self._database.values())),
                "source": "local_database",
            }

    def get_status(self) -> dict:
        with self._lock:
            total = len(self._database)

        return {
            "available": True,
            "mode": "passive",
            "external_queries": False,
            "database_entries": total,
        }


VendorDetection = VendorDetector
VendorDetectionEngine = VendorDetector

__all__ = [
    "VendorDetectionError",
    "VendorInfo",
    "VendorDetector",
    "VendorDetection",
    "VendorDetectionEngine",
]
