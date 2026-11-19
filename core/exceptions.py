
"""
NETSHADOW - Core Exceptions

Sistema centralizado de exceções da aplicação.
"""


class NetShadowError(Exception):
    """Exceção base de todos os erros do NETSHADOW."""

    def __init__(self, message: str, details: str | None = None):
        self.message = message
        self.details = details
        super().__init__(message)

    def to_dict(self) -> dict:
        return {
            "error": self.__class__.__name__,
            "message": self.message,
            "details": self.details,
        }


# ---------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------

class ConfigurationError(NetShadowError):
    """Erro relacionado com configurações."""


class InvalidConfigurationError(ConfigurationError):
    """Configuração inválida."""


class MissingConfigurationError(ConfigurationError):
    """Configuração obrigatória em falta."""


# ---------------------------------------------------------
# PERMISSIONS AND AUTHORIZATION
# ---------------------------------------------------------

class PermissionDeniedError(NetShadowError):
    """Operação não autorizada."""


class AuthorizationError(PermissionDeniedError):
    """Erro durante a autorização."""


class AuthorizationExpiredError(AuthorizationError):
    """Autorização expirada."""


# ---------------------------------------------------------
# APPLICATION LIFECYCLE
# ---------------------------------------------------------

class ApplicationError(NetShadowError):
    """Erro geral da aplicação."""


class InitializationError(ApplicationError):
    """Falha durante a inicialização."""


class ShutdownError(ApplicationError):
    """Falha durante o encerramento."""


class LifecycleError(ApplicationError):
    """Erro durante o ciclo de vida de um componente."""


class ComponentError(ApplicationError):
    """Erro relacionado com um componente."""


class ComponentNotFoundError(ComponentError):
    """Componente não encontrado."""


class ComponentAlreadyRegisteredError(ComponentError):
    """Componente já registado."""


# ---------------------------------------------------------
# NETWORK
# ---------------------------------------------------------

class NetworkError(NetShadowError):
    """Erro relacionado com redes."""


class InvalidNetworkError(NetworkError):
    """Endereço ou rede inválida."""


class NetworkUnavailableError(NetworkError):
    """Rede indisponível."""


class NetworkContextError(NetworkError):
    """Erro no contexto de rede."""


# ---------------------------------------------------------
# DATABASE
# ---------------------------------------------------------

class DatabaseError(NetShadowError):
    """Erro relacionado com a base de dados."""


class DatabaseConnectionError(DatabaseError):
    """Falha de ligação à base de dados."""


class DatabaseTransactionError(DatabaseError):
    """Falha numa transação."""


class DatabaseIntegrityError(DatabaseError):
    """Violação de integridade da base de dados."""


# ---------------------------------------------------------
# SECURITY
# ---------------------------------------------------------

class SecurityError(NetShadowError):
    """Erro relacionado com segurança."""


class InputValidationError(SecurityError):
    """Dados de entrada inválidos."""


class IntegrityError(SecurityError):
    """Falha na verificação de integridade."""


class SecureStorageError(SecurityError):
    """Erro no armazenamento seguro."""


# ---------------------------------------------------------
# DISCOVERY AND AUDITING
# ---------------------------------------------------------

class DiscoveryError(NetShadowError):
    """Erro durante a descoberta de dispositivos."""


class AuditError(NetShadowError):
    """Erro durante uma auditoria."""


class ScanError(AuditError):
    """Erro associado a um pedido de análise."""


# ---------------------------------------------------------
# REPORTS
# ---------------------------------------------------------

class ReportError(NetShadowError):
    """Erro durante a geração de relatórios."""


class ReportExportError(ReportError):
    """Erro durante a exportação de um relatório."""


# ---------------------------------------------------------
# PLATFORM
# ---------------------------------------------------------

class PlatformError(NetShadowError):
    """Erro relacionado com a plataforma."""


class UnsupportedPlatformError(PlatformError):
    """Sistema operativo não suportado."""


# ---------------------------------------------------------
# RUST BRIDGE
# ---------------------------------------------------------

class RustBridgeError(NetShadowError):
    """Erro de comunicação com componentes Rust."""


class RustInitializationError(RustBridgeError):
    """Falha ao inicializar o módulo Rust."""


# ---------------------------------------------------------
# COMPATIBILITY
# ---------------------------------------------------------

NetShadowException = NetShadowError
BaseApplicationError = ApplicationError
