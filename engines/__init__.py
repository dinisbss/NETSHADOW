
"""
NETSHADOW - Engines Package

Centraliza as exportações públicas dos motores
de Network Intelligence & Security Auditing.
"""

from engines.network_engine.interfaces import NetworkInterfaces
from engines.network_engine.subnet import SubnetAnalyzer
from engines.network_engine.gateway import GatewayDetector
from engines.network_engine.network_info import NetworkInfoCollector

from engines.discovery_engine.discovery import DiscoveryEngine
from engines.discovery_engine.arp_discovery import ARPDiscovery
from engines.discovery_engine.icmp_discovery import ICMPDiscovery
from engines.discovery_engine.device_detection import DeviceDetection

from engines.port_engine.tcp_audit import TCPAudit
from engines.port_engine.udp_audit import UDPAudit
from engines.port_engine.port_states import PortStates

from engines.service_engine.service_detection import ServiceDetection
from engines.service_engine.tls_analysis import TLSAnalysis
from engines.service_engine.protocol_detection import ProtocolDetection

from engines.device_engine.device_profiler import DeviceProfiler
from engines.device_engine.vendor_detection import VendorDetection
from engines.device_engine.device_history import DeviceHistory

from engines.security_engine.security_checks import SecurityChecks
from engines.security_engine.risk_analyzer import RiskAnalyzer
from engines.security_engine.recommendations import Recommendations

from engines.monitoring_engine.availability import Availability
from engines.monitoring_engine.latency import Latency
from engines.monitoring_engine.metrics import Metrics
from engines.monitoring_engine.change_detection import ChangeDetection


__all__ = [
    # Network Engine
    "NetworkInterfaces",
    "SubnetAnalyzer",
    "GatewayDetector",
    "NetworkInfoCollector",

    # Discovery Engine
    "DiscoveryEngine",
    "ARPDiscovery",
    "ICMPDiscovery",
    "DeviceDetection",

    # Port Engine
    "TCPAudit",
    "UDPAudit",
    "PortStates",

    # Service Engine
    "ServiceDetection",
    "TLSAnalysis",
    "ProtocolDetection",

    # Device Engine
    "DeviceProfiler",
    "VendorDetection",
    "DeviceHistory",

    # Security Engine
    "SecurityChecks",
    "RiskAnalyzer",
    "Recommendations",

    # Monitoring Engine
    "Availability",
    "Latency",
    "Metrics",
    "ChangeDetection",
]
