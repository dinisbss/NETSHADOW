
"""
NETSHADOW - Rust Bridge Adapter

Ponte opcional entre Python e a extensão Rust.
Utiliza Python como fallback quando Rust não está disponível.
Não executa operações de rede.
"""

from __future__ import annotations

import importlib
from dataclasses import dataclass, field
from enum import Enum
from threading import RLock
from typing import Any, Optional


class RustBridgeError(RuntimeError):
    """Erro base da ponte Python-Rust."""


class RustStatus(str, Enum):
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    INCOMPATIBLE = "incompatible"
    ERROR = "error"


class RustModuleUnavailableError(RustBridgeError):
    """A extensão Rust não está disponível."""


class RustOperationError(RustBridgeError):
    """Erro durante uma operação suportada."""


@dataclass(frozen=True)
class RustInfo:
    """Informação sobre o backend ativo."""

    backend: str
    status: RustStatus
    version: Optional[str] = None
    capabilities: list[str] = field(default_factory=list)
    error: Optional[str] = None


class RustBridgeAdapter:
    """Gere a ligação opcional entre Python e Rust."""

    MODULE_NAME = "netshadow_rust"

    ALLOWED_OPERATIONS = frozenset({
        "get_version",
        "get_capabilities",
        "health_check",
    })

    REQUIRED_FUNCTIONS = (
        "get_version",
        "health_check",
    )

    def __init__(
        self,
        module: Optional[Any] = None,
        auto_load: bool = False,
    ) -> None:
        self._module: Optional[Any] = None
        self._available = False
        self._load_error: Optional[str] = None
        self._status = RustStatus.UNAVAILABLE
        self._lock = RLock()

        if module is not None:
            self.set_module(module)
        elif auto_load:
            self.load()

    def _validate_module(self, module: Any) -> None:
        """Valida as funções mínimas da extensão."""

        if module is None:
            raise RustModuleUnavailableError(
                "A extensão Rust devolveu um módulo inválido."
            )

        for name in self.REQUIRED_FUNCTIONS:
            if not callable(getattr(module, name, None)):
                raise RustBridgeError(
                    f"A extensão Rust não implementa a função: {name}"
                )

    def load(self) -> bool:
        """Tenta carregar e validar a extensão Rust."""

        with self._lock:
            try:
                module = importlib.import_module(self.MODULE_NAME)
                self._validate_module(module)

                self._module = module
                self._available = True
                self._load_error = None
                self._status = RustStatus.AVAILABLE
                return True

            except ModuleNotFoundError as exc:
                self._module = None
                self._available = False
                self._load_error = str(exc)

                if exc.name == self.MODULE_NAME:
                    self._status = RustStatus.UNAVAILABLE
                else:
                    self._status = RustStatus.ERROR

                return False

            except RustBridgeError as exc:
                self._module = None
                self._available = False
                self._load_error = str(exc)
                self._status = RustStatus.INCOMPATIBLE
                return False

            except Exception as exc:
                self._module = None
                self._available = False
                self._load_error = f"{type(exc).__name__}: {exc}"
                self._status = RustStatus.ERROR
                return False

    def initialize(self) -> RustInfo:
        """Inicializa a ponte e devolve informação do backend."""

        with self._lock:
            if self._module is None:
                self.load()

        return self.get_info()

    def set_module(self, module: Any) -> None:
        """Define manualmente um módulo Rust."""

        if module is None:
            raise RustBridgeError(
                "O módulo Rust não pode ser None."
            )

        with self._lock:
            self._module = module
            self._available = True
            self._load_error = None
            self._status = RustStatus.AVAILABLE

    def get_module(self) -> Optional[Any]:
        """Devolve o módulo carregado."""

        with self._lock:
            return self._module

    def unload(self) -> None:
        """Desativa a ligação Rust."""

        with self._lock:
            self._module = None
            self._available = False
            self._load_error = None
            self._status = RustStatus.UNAVAILABLE

    def reset(self) -> None:
        """Repõe o adaptador no estado inicial."""

        self.unload()

    def is_available(self) -> bool:
        """Indica se a extensão está disponível."""

        with self._lock:
            return self._available and self._module is not None

    @property
    def status(self) -> RustStatus:
        """Estado atual da extensão."""

        with self._lock:
            return self._status

    def get_version(self) -> Optional[str]:
        """Obtém a versão da extensão."""

        with self._lock:
            if not self.is_available():
                return None
            module = self._module

        version = getattr(module, "__version__", None)

        if version is None:
            function = getattr(module, "get_version", None)

            if not callable(function):
                return None

            try:
                version = function()
            except Exception as exc:
                raise RustOperationError(
                    "Não foi possível obter a versão Rust."
                ) from exc

        if version is None:
            return None

        return str(version)

    def get_capabilities(self) -> list[str]:
        """Obtém as capacidades declaradas pela extensão."""

        with self._lock:
            if not self.is_available():
                return []
            module = self._module

        function = getattr(module, "get_capabilities", None)

        if callable(function):
            try:
                capabilities = function()
            except Exception as exc:
                raise RustOperationError(
                    "Não foi possível consultar as capacidades."
                ) from exc
        else:
            capabilities = getattr(
                module,
                "__capabilities__",
                [],
            )

        if not isinstance(capabilities, (list, tuple, set)):
            raise RustOperationError(
                "Formato de capacidades inválido."
            )

        result = {
            item.strip()
            for item in capabilities
            if isinstance(item, str)
            and item.strip()
            and len(item.strip()) <= 100
        }

        return sorted(result)

    def health_check(self) -> bool:
        """Verifica o estado operacional da extensão."""

        with self._lock:
            if not self.is_available():
                return False
            module = self._module

        function = getattr(module, "health_check", None)

        if not callable(function):
            return False

        try:
            return bool(function())
        except Exception as exc:
            raise RustOperationError(
                "A verificação da extensão Rust falhou."
            ) from exc

    def get_info(self) -> RustInfo:
        """Devolve informação estruturada sobre o backend."""

        with self._lock:
            available = self.is_available()
            status = self._status
            error = self._load_error

        if not available:
            return RustInfo(
                backend="PYTHON",
                status=status,
                error=error,
            )

        try:
            version = self.get_version()
            capabilities = self.get_capabilities()

            return RustInfo(
                backend="RUST",
                status=RustStatus.AVAILABLE,
                version=version,
                capabilities=capabilities,
            )

        except RustBridgeError as exc:
            return RustInfo(
                backend="PYTHON",
                status=RustStatus.INCOMPATIBLE,
                error=str(exc),
            )

    def execute(
        self,
        operation: str,
        **kwargs: Any,
    ) -> Any:
        """Executa apenas operações explicitamente permitidas."""

        if not isinstance(operation, str):
            raise RustOperationError(
                "O nome da operação tem de ser texto."
            )

        operation = operation.strip()

        if (
            not operation
            or operation.startswith("_")
            or "/" in operation
            or "\\" in operation
            or operation not in self.ALLOWED_OPERATIONS
        ):
            raise RustOperationError(
                "Operação não permitida."
            )

        if kwargs:
            raise RustOperationError(
                "Estas operações não aceitam argumentos."
            )

        with self._lock:
            if not self.is_available():
                raise RustModuleUnavailableError(
                    "A extensão Rust não está disponível."
                )
            module = self._module

        function = getattr(module, operation, None)

        if not callable(function):
            raise RustOperationError(
                f"A extensão não implementa: {operation}"
            )

        try:
            return function()
        except Exception as exc:
            raise RustOperationError(
                f"Falha na operação Rust: {operation}"
            ) from exc

    def get_status(self) -> dict[str, Any]:
        """Devolve o estado detalhado da ponte."""

        info = self.get_info()
        available = self.is_available()

        healthy = False
        if available:
            try:
                healthy = self.health_check()
            except RustOperationError:
                healthy = False

        return {
            "available": available,
            "healthy": healthy,
            "module": self.MODULE_NAME,
            "version": info.version,
            "capabilities": info.capabilities,
            "load_error": info.error,
            "status": info.status.value,
            "backend": info.backend,
        }


# Compatibilidade com nomes anteriores

RustBridgeStatus = RustStatus
RustUnavailableError = RustModuleUnavailableError
RustFunctionError = RustOperationError

RustAdapter = RustBridgeAdapter
RustBridge = RustBridgeAdapter
RustBridgeManager = RustBridgeAdapter


__all__ = [
    "RustStatus",
    "RustInfo",
    "RustBridgeStatus",
    "RustBridgeError",
    "RustModuleUnavailableError",
    "RustOperationError",
    "RustUnavailableError",
    "RustFunctionError",
    "RustAdapter",
    "RustBridge",
    "RustBridgeAdapter",
    "RustBridgeManager",
]
