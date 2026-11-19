
"""
NETSHADOW - Lifecycle Manager

Gere o ciclo de vida dos componentes da aplicação:
- Registo de componentes
- Inicialização
- Encerramento
- Rollback em caso de falha
- Consulta de estados
"""

from __future__ import annotations

import logging
import threading

from enum import Enum
from typing import Any, Optional


logger = logging.getLogger(__name__)


class LifecycleError(RuntimeError):
    """Erro associado ao ciclo de vida dos componentes."""


class LifecycleState(str, Enum):
    """Estados possíveis de um componente."""

    REGISTERED = "REGISTERED"
    INITIALIZING = "INITIALIZING"
    RUNNING = "RUNNING"
    STOPPING = "STOPPING"
    STOPPED = "STOPPED"
    FAILED = "FAILED"


class LifecycleComponent:
    """Interface base para componentes geridos pelo LifecycleManager."""

    def initialize(self) -> bool:
        """Inicializa o componente."""
        return True

    def shutdown(self) -> None:
        """Encerra o componente."""
        pass


class LifecycleManager:
    """
    Gere a inicialização e o encerramento dos componentes.

    Se um componente falhar durante o arranque, os componentes
    anteriormente inicializados são encerrados por ordem inversa.
    """

    def __init__(self) -> None:
        self._components: dict[str, Any] = {}
        self._states: dict[str, LifecycleState] = {}
        self._lock = threading.RLock()
        self._started_order: list[str] = []

    def register(self, name: str, component: Any) -> None:
        """Regista um componente."""

        if not isinstance(name, str) or not name.strip():
            raise ValueError("O nome do componente é obrigatório.")

        if component is None:
            raise ValueError("O componente não pode ser None.")

        with self._lock:
            if name in self._components:
                raise LifecycleError(
                    f"O componente '{name}' já está registado."
                )

            if not callable(getattr(component, "initialize", None)):
                raise LifecycleError(
                    f"O componente '{name}' não possui initialize()."
                )

            if not callable(getattr(component, "shutdown", None)):
                raise LifecycleError(
                    f"O componente '{name}' não possui shutdown()."
                )

            self._components[name] = component
            self._states[name] = LifecycleState.REGISTERED

            logger.info("Componente registado: %s", name)

    def initialize_component(self, name: str) -> bool:
        """Inicializa individualmente um componente."""

        with self._lock:
            if name not in self._components:
                raise LifecycleError(
                    f"Componente desconhecido: {name}"
                )

            state = self._states[name]

            if state == LifecycleState.RUNNING:
                return True

            if state in (
                LifecycleState.INITIALIZING,
                LifecycleState.STOPPING,
            ):
                raise LifecycleError(
                    f"Estado inválido para inicialização: {state.value}"
                )

            component = self._components[name]
            self._states[name] = LifecycleState.INITIALIZING

            try:
                result = component.initialize()

                if result is False:
                    raise LifecycleError(
                        f"Inicialização recusada: {name}"
                    )

                self._states[name] = LifecycleState.RUNNING

                if name not in self._started_order:
                    self._started_order.append(name)

                logger.info("Componente iniciado: %s", name)
                return True

            except Exception as exc:
                self._states[name] = LifecycleState.FAILED

                logger.exception(
                    "Falha ao inicializar componente: %s",
                    name,
                )

                return False

    def start(self) -> bool:
        """Inicializa todos os componentes pela ordem de registo."""

        with self._lock:
            initialized_now: list[str] = []

            for name in self._components:
                if self._states[name] == LifecycleState.RUNNING:
                    continue

                if not self.initialize_component(name):
                    logger.error(
                        "Arranque interrompido devido a: %s",
                        name,
                    )

                    self._rollback(initialized_now)
                    return False

                initialized_now.append(name)

            return True

    def start_all(self) -> bool:
        """Alias para start()."""
        return self.start()

    def _rollback(self, component_names: list[str]) -> None:
        """Encerra componentes inicializados nesta operação."""

        for name in reversed(component_names):
            try:
                self.stop_component(name)
            except Exception:
                logger.exception(
                    "Erro durante rollback do componente: %s",
                    name,
                )

    def stop_component(self, name: str) -> bool:
        """Encerra individualmente um componente."""

        with self._lock:
            if name not in self._components:
                raise LifecycleError(
                    f"Componente desconhecido: {name}"
                )

            state = self._states[name]

            if state in (
                LifecycleState.REGISTERED,
                LifecycleState.STOPPED,
            ):
                self._states[name] = LifecycleState.STOPPED
                return True

            if state == LifecycleState.FAILED:
                return False

            component = self._components[name]
            self._states[name] = LifecycleState.STOPPING

            try:
                component.shutdown()

                self._states[name] = LifecycleState.STOPPED

                if name in self._started_order:
                    self._started_order.remove(name)

                logger.info("Componente encerrado: %s", name)
                return True

            except Exception:
                self._states[name] = LifecycleState.FAILED

                logger.exception(
                    "Falha ao encerrar componente: %s",
                    name,
                )

                return False

    def stop(self) -> bool:
        """Encerra todos os componentes por ordem inversa."""

        with self._lock:
            success = True

            for name in reversed(self._started_order.copy()):
                if not self.stop_component(name):
                    success = False

            return success

    def stop_all(self) -> bool:
        """Alias para stop()."""
        return self.stop()

    def get_state(self, name: str) -> Optional[LifecycleState]:
        """Devolve o estado de um componente."""

        with self._lock:
            return self._states.get(name)

    def get_status(self) -> dict[str, str]:
        """Devolve o estado de todos os componentes."""

        with self._lock:
            return {
                name: state.value
                for name, state in self._states.items()
            }

    def is_running(self, name: str) -> bool:
        """Verifica se um componente está em execução."""

        with self._lock:
            return self._states.get(name) == LifecycleState.RUNNING


# Compatibilidade com nomes utilizados por outros módulos.
ComponentLifecycle = LifecycleManager
ComponentState = LifecycleState
