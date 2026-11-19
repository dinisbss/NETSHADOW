
"""
NETSHADOW Core Package.

Central application infrastructure and coordination components.
"""

from core.application import NetShadowApplication
from core.event_bus import Event, EventBus
from core.lifecycle import (
    ComponentLifecycle,
    ComponentState,
    LifecycleError,
)
from core.network_context import (
    NetworkContext,
    NetworkContextManager,
)
from core.orchestrator import Orchestrator
from core.platform_detector import (
    PlatformInfo,
    detect_platform,
    get_platform_name,
    is_supported_platform,
)

__all__ = [
    "NetShadowApplication",
    "Event",
    "EventBus",
    "ComponentLifecycle",
    "ComponentState",
    "LifecycleError",
    "NetworkContext",
    "NetworkContextManager",
    "Orchestrator",
    "PlatformInfo",
    "detect_platform",
    "get_platform_name",
    "is_supported_platform",
]
