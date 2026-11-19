
"""
NETSHADOW - Database Models

Modelos de dados centrais da aplicação.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Optional
from uuid import uuid4


class ModelError(ValueError):
    """Erro base para validação dos modelos da base de dados."""
    pass


def utc_now() -> str:
    """Devolve a data e hora UTC em formato ISO."""
    return datetime.now(timezone.utc).isoformat()


def generate_id() -> str:
    """Gera um identificador único."""
    return str(uuid4())


def validate_required_text(
    value: str,
    field_name: str,
    maximum: int = 255,
) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} não pode estar vazio.")

    value = value.strip()

    if len(value) > maximum:
        raise ValueError(
            f"{field_name} excede {maximum} caracteres."
        )

    return value


def serialize_value(value: Any) -> Any:
    """Converte valores complexos em estruturas serializáveis."""
    if hasattr(value, "to_dict"):
        return value.to_dict()

    if isinstance(value, datetime):
        return value.isoformat()

    if isinstance(value, list):
        return [serialize_value(item) for item in value]

    if isinstance(value, dict):
        return {
            key: serialize_value(item)
            for key, item in value.items()
        }

    return value



@dataclass
class NetworkModel:
    """Representa uma rede conhecida."""

    network: str
    name: str
    description: str = ""
    network_id: Optional[int] = None
    created_at: str = field(default_factory=utc_now)
    updated_at: str = field(default_factory=utc_now)

    def __post_init__(self) -> None:
        self.name = validate_required_text(
            self.name, "name", 100
        )

        if not isinstance(self.description, str):
            raise ModelError(
                "description tem de ser texto."
            )

        if len(self.description) > 5000:
            raise ModelError(
                "description excede 5000 caracteres."
            )

        try:
            self.network = str(
                ipaddress.ip_network(
                    self.network,
                    strict=False,
                )
            )
        except ValueError as exc:
            raise ModelError(
                "Endereço de rede inválido."
            ) from exc

        if self.network_id is not None:
            if (
                not isinstance(self.network_id, int)
                or isinstance(self.network_id, bool)
                or self.network_id <= 0
            ):
                raise ModelError(
                    "network_id inválido."
                )

    @property
    def network_address(self) -> str:
        """Compatibilidade com a nomenclatura anterior."""
        return self.network

    @network_address.setter
    def network_address(self, value: str) -> None:
        try:
            self.network = str(
                ipaddress.ip_network(value, strict=False)
            )
        except ValueError as exc:
            raise ModelError(
                "Endereço de rede inválido."
            ) from exc

    @property
    def id(self) -> Optional[int]:
        """Compatibilidade com o identificador anterior."""
        return self.network_id

    @id.setter
    def id(self, value: Optional[int]) -> None:
        self.network_id = value

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class DeviceModel:
    """Representa um dispositivo de rede."""

    ip_address: str
    mac_address: Optional[str] = None
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    network_id: Optional[int] = None
    id: Optional[int] = None
    first_seen: str = field(default_factory=utc_now)
    last_seen: str = field(default_factory=utc_now)
    metadata: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        try:
            self.ip_address = str(
                ipaddress.ip_address(self.ip_address)
            )
        except ValueError as exc:
            raise ValueError("Endereço IP inválido.") from exc

        if self.mac_address is not None:
            import re

            pattern = (
                r"^(?:[0-9A-Fa-f]{2}[:-]){5}"
                r"[0-9A-Fa-f]{2}$"
            )

            if not re.fullmatch(pattern, self.mac_address):
                raise ValueError("Endereço MAC inválido.")

            self.mac_address = (
                self.mac_address.replace("-", ":").lower()
            )

        if self.hostname is not None:
            self.hostname = validate_required_text(
                self.hostname, "hostname"
            )

        if self.vendor is not None:
            self.vendor = validate_required_text(
                self.vendor, "vendor"
            )

        if self.network_id is not None:
            if not isinstance(self.network_id, int):
                raise ValueError("network_id inválido.")

            if self.network_id <= 0:
                raise ValueError("network_id inválido.")

        if not isinstance(self.metadata, dict):
            raise ValueError("metadata tem de ser um dicionário.")

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ScanModel:
    """Representa uma auditoria executada ou planeada."""

    scan_type: str
    network_id: Optional[int] = None
    status: str = "pending"
    id: Optional[int] = None
    started_at: str = field(default_factory=utc_now)
    finished_at: Optional[str] = None
    metadata: dict = field(default_factory=dict)

    VALID_STATUSES = {
        "pending",
        "running",
        "completed",
        "failed",
        "cancelled",
    }

    VALID_TYPES = {
        "discovery",
        "network",
        "device",
        "security",
        "ports",
        "services",
        "full",
        "manual",
    }

    def __post_init__(self) -> None:
        self.scan_type = validate_required_text(
            self.scan_type, "scan_type", 50
        ).lower()

        if self.scan_type not in self.VALID_TYPES:
            raise ValueError("Tipo de auditoria inválido.")

        self.status = validate_required_text(
            self.status, "status", 30
        ).lower()

        if self.status not in self.VALID_STATUSES:
            raise ValueError("Estado de auditoria inválido.")

        if self.network_id is not None:
            if not isinstance(self.network_id, int):
                raise ValueError("network_id inválido.")

            if self.network_id <= 0:
                raise ValueError("network_id inválido.")

        if not isinstance(self.metadata, dict):
            raise ValueError("metadata tem de ser um dicionário.")

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class FindingModel:
    """Representa uma descoberta de segurança."""

    title: str
    severity: str = "info"
    description: Optional[str] = None
    scan_id: Optional[int] = None
    device_id: Optional[int] = None
    id: Optional[int] = None
    created_at: str = field(default_factory=utc_now)
    metadata: dict = field(default_factory=dict)

    VALID_SEVERITIES = {
        "info",
        "low",
        "medium",
        "high",
        "critical",
    }

    def __post_init__(self) -> None:
        self.title = validate_required_text(
            self.title, "title", 255
        )

        self.severity = validate_required_text(
            self.severity, "severity", 30
        ).lower()

        if self.severity not in self.VALID_SEVERITIES:
            raise ValueError("Gravidade inválida.")

        if self.description is not None:
            if not isinstance(self.description, str):
                raise ValueError(
                    "description tem de ser texto."
                )

            if len(self.description) > 5000:
                raise ValueError(
                    "description excede 5000 caracteres."
                )

        for field_name in ("scan_id", "device_id"):
            value = getattr(self, field_name)

            if value is not None:
                if not isinstance(value, int) or value <= 0:
                    raise ValueError(
                        f"{field_name} inválido."
                    )

        if not isinstance(self.metadata, dict):
            raise ValueError("metadata tem de ser um dicionário.")

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ReportModel:
    """Representa um relatório gerado."""

    file_path: str
    format: str
    scan_id: Optional[int] = None
    id: Optional[int] = None
    created_at: str = field(default_factory=utc_now)
    metadata: dict = field(default_factory=dict)

    VALID_FORMATS = {
        "json",
        "html",
        "txt",
        "pdf",
    }

    def __post_init__(self) -> None:
        self.file_path = validate_required_text(
            self.file_path, "file_path", 1000
        )

        self.format = validate_required_text(
            self.format, "format", 20
        ).lower()

        if self.format not in self.VALID_FORMATS:
            raise ValueError("Formato de relatório inválido.")

        if self.scan_id is not None:
            if not isinstance(self.scan_id, int):
                raise ValueError("scan_id inválido.")

            if self.scan_id <= 0:
                raise ValueError("scan_id inválido.")

        if not isinstance(self.metadata, dict):
            raise ValueError("metadata tem de ser um dicionário.")

    def to_dict(self) -> dict:
        return asdict(self)


# Aliases para compatibilidade com nomes alternativos.
Network = NetworkModel
Device = DeviceModel
Scan = ScanModel
Finding = FindingModel
Report = ReportModel


__all__ = [
    "ModelError",
    "utc_now",
    "generate_id",
    "serialize_value",
    "NetworkModel",
    "DeviceModel",
    "ScanModel",
    "FindingModel",
    "ReportModel",
    "Network",
    "Device",
    "Scan",
    "Finding",
    "Report",
]
