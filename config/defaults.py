
from pathlib import Path

# --------------------------------------------------
# PROJECT INFORMATION
# --------------------------------------------------

APP_NAME = "NETSHADOW"
APP_VERSION = "0.1.0"
APP_DESCRIPTION = (
    "Network Intelligence & Security Auditing Platform"
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# --------------------------------------------------
# DIRECTORY PATHS
# --------------------------------------------------

CONFIG_DIR = PROJECT_ROOT / "config"
DATA_DIR = PROJECT_ROOT / "data"
LOGS_DIR = PROJECT_ROOT / "logs"

DATABASE_DIR = DATA_DIR
BACKUP_DIR = DATA_DIR / "backups"
EXPORT_DIR = DATA_DIR / "exports"

DATABASE_PATH = DATABASE_DIR / "netshadow.db"
LOG_FILE_PATH = LOGS_DIR / "netshadow.log"

# --------------------------------------------------
# CONFIGURATION FILES
# --------------------------------------------------

SETTINGS_FILE = CONFIG_DIR / "settings.yaml"
LOGGING_FILE = CONFIG_DIR / "logging.yaml"
SECURITY_FILE = CONFIG_DIR / "security.yaml"
NETWORKS_FILE = CONFIG_DIR / "networks.yaml"

# --------------------------------------------------
# APPLICATION MODES
# --------------------------------------------------

DEFAULT_MODE = "SAFE"

AVAILABLE_MODES = [
    "SAFE",
    "AUDIT",
    "MONITOR",
]

SUPPORTED_PLATFORMS = [
    "Linux",
    "Windows",
]

# --------------------------------------------------
# SECURITY DEFAULTS
# --------------------------------------------------

SAFE_MODE = True

REQUIRE_EXPLICIT_AUTHORIZATION = True
ALLOW_PRIVILEGE_ESCALATION = False
ACTIVE_OPERATIONS_ENABLED = False

VALIDATE_INPUTS = True
REDACT_SECRETS_IN_LOGS = True

# --------------------------------------------------
# NETWORK LIMITS
# --------------------------------------------------

DEFAULT_TIMEOUT = 5.0

MAX_CONCURRENT_TASKS = 2
MAX_RETRIES = 2

MAX_TARGETS_PER_OPERATION = 256
MAX_OPERATIONS_PER_MINUTE = 30

# --------------------------------------------------
# DATABASE SETTINGS
# --------------------------------------------------

DATABASE_TIMEOUT = 5.0
DATABASE_FOREIGN_KEYS = True
DATABASE_WAL_MODE = True

# --------------------------------------------------
# MONITORING SETTINGS
# --------------------------------------------------

DEFAULT_MONITORING_INTERVAL = 60
MIN_MONITORING_INTERVAL = 30
MAX_MONITORING_INTERVAL = 3600

# --------------------------------------------------
# VALIDATION
# --------------------------------------------------

def validate_mode(mode: str) -> bool:
    """Check whether an application mode is supported."""

    return (
        isinstance(mode, str)
        and mode.upper() in AVAILABLE_MODES
    )


def get_project_path(*parts: str) -> Path:
    """Resolve a path relative to the project root."""

    return PROJECT_ROOT.joinpath(*parts)


__all__ = [
    "APP_NAME",
    "APP_VERSION",
    "APP_DESCRIPTION",
    "PROJECT_ROOT",
    "CONFIG_DIR",
    "DATA_DIR",
    "LOGS_DIR",
    "DATABASE_DIR",
    "BACKUP_DIR",
    "EXPORT_DIR",
    "DATABASE_PATH",
    "LOG_FILE_PATH",
    "SETTINGS_FILE",
    "LOGGING_FILE",
    "SECURITY_FILE",
    "NETWORKS_FILE",
    "DEFAULT_MODE",
    "AVAILABLE_MODES",
    "SUPPORTED_PLATFORMS",
    "SAFE_MODE",
    "REQUIRE_EXPLICIT_AUTHORIZATION",
    "ALLOW_PRIVILEGE_ESCALATION",
    "ACTIVE_OPERATIONS_ENABLED",
    "VALIDATE_INPUTS",
    "REDACT_SECRETS_IN_LOGS",
    "DEFAULT_TIMEOUT",
    "MAX_CONCURRENT_TASKS",
    "MAX_RETRIES",
    "MAX_TARGETS_PER_OPERATION",
    "MAX_OPERATIONS_PER_MINUTE",
    "DATABASE_TIMEOUT",
    "DATABASE_FOREIGN_KEYS",
    "DATABASE_WAL_MODE",
    "DEFAULT_MONITORING_INTERVAL",
    "MIN_MONITORING_INTERVAL",
    "MAX_MONITORING_INTERVAL",
    "validate_mode",
    "get_project_path",
]
