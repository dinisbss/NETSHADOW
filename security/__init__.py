
"""
NETSHADOW - Security Package

Centraliza as exportações dos componentes de segurança.
"""

from security.permission_manager import (
    Authorization,
    PermissionManager,
    PermissionMode,
    PermissionResult,
)

__all__ = [
    "Authorization",
    "PermissionManager",
    "PermissionMode",
    "PermissionResult",
]
