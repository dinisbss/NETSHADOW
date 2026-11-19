
"""
NETSHADOW Database Package

Central exports for database infrastructure,
models, sessions and repositories.
"""

from database.database import Database, DatabaseError

from database.session import (
    DatabaseSession,
    SessionManager,
    SessionError,
)

from database.models import (
    ModelError,
    NetworkModel,
    DeviceModel,
    ScanModel,
    FindingModel,
    ReportModel,
    utc_now,
    generate_id,
    validate_required_text,
    serialize_value,
)

from database.repositories import (
    NetworkRepository,
    DeviceRepository,
    ScanRepository,
    FindingsRepository,
    ReportRepository,
)

__all__ = [
    "Database",
    "DatabaseError",
    "DatabaseSession",
    "SessionManager",
    "SessionError",
    "ModelError",
    "NetworkModel",
    "DeviceModel",
    "ScanModel",
    "FindingModel",
    "ReportModel",
    "utc_now",
    "generate_id",
    "validate_required_text",
    "serialize_value",
    "NetworkRepository",
    "DeviceRepository",
    "ScanRepository",
    "FindingsRepository",
    "ReportRepository",
]
