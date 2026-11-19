
"""
NETSHADOW - Core Orchestrator

Coordena o ciclo de vida dos componentes da aplicação.
"""

from __future__ import annotations

import logging
from enum import Enum
from threading import RLock
from typing import Any, Callable


class ComponentState(str, Enum):
    REGISTERED = "REGISTERED"
    INITIALIZING = "INITIALIZING"
    READY = "READY"
    FAILED = "FAILED"
    STOPPING = "STOPPING"
    STOPPED = "STOPPED"


class OrchestratorError(RuntimeError):
    """Erro durante a gestão de componentes."""


class CoreOrchestrator:
    """Regista, inicializa e encerra componentes."""




    def __init__(
        self,
        logger: logging.Logger | None = None,
    ):
        self.logger = logger or logging.getLogger("NETSHADOW")
        self.components: dict[str, Any] = {}
        self.states: dict[str, ComponentState] = {}
        self.errors: dict[str, str] = {}
        self._lock = RLock()
        self._started = False

    @property
    def started(self) -> bool:
        return self._started

    def register(
        self,
        name: str,
        component: Any,
    ) -> None:
        if not isinstance(name, str) or not name.strip():
            raise ValueError("Component name cannot be empty.")

        if component is None:
            raise ValueError("Component cannot be None.")

        name = name.strip()

        with self._lock:
            if self._started:
                raise OrchestratorError(
                    "Cannot register components after startup."
                )

            if name in self.components:
                raise OrchestratorError(
                    f"Component already registered: {name}"
                )

            self.components[name] = component
            self.states[name] = ComponentState.REGISTERED

        self.logger.info("Component registered: %s", name)

    def initialize_component(self, name: str) -> bool:
        with self._lock:
            if name not in self.components:
                raise KeyError(f"Unknown component: {name}")

            state = self.states[name]

            if state == ComponentState.READY:
                return True

            if state in {
                ComponentState.INITIALIZING,
                ComponentState.STOPPING,
            }:
                return False

            component = self.components[name]
            self.states[name] = ComponentState.INITIALIZING

        try:
            initializer: Callable[[], Any] | None = getattr(
                component,
                "initialize",
                None,
            )

            if callable(initializer):
                result = initializer()

                if result is False:
                    raise OrchestratorError(
                        f"Initialization rejected: {name}"
                    )

            with self._lock:
                self.states[name] = ComponentState.READY
                self.errors.pop(name, None)

            self.logger.info("Component ready: %s", name)
            return True

        except Exception as exc:
            with self._lock:
                self.states[name] = ComponentState.FAILED
                self.errors[name] = str(exc)

            self.logger.exception(
                "Component initialization failed: %s",
                name,
            )
            return False

    def start_all(self) -> bool:
        with self._lock:
            if self._started:
                return True

            names = list(self.components)

        success = True

        for name in names:
            if not self.initialize_component(name):
                success = False

        with self._lock:
            self._started = success

        return success

    def stop_component(self, name: str) -> bool:
        with self._lock:
            if name not in self.components:
                return False

            state = self.states[name]

            if state in {
                ComponentState.REGISTERED,
                ComponentState.STOPPED,
            }:
                self.states[name] = ComponentState.STOPPED
                return True

            self.states[name] = ComponentState.STOPPING
            component = self.components[name]

        try:
            shutdown = getattr(component, "shutdown", None)

            if not callable(shutdown):
                shutdown = getattr(component, "stop", None)

            if callable(shutdown):
                shutdown()

            with self._lock:
                self.states[name] = ComponentState.STOPPED

            self.logger.info("Component stopped: %s", name)
            return True

        except Exception as exc:
            with self._lock:
                self.states[name] = ComponentState.FAILED
                self.errors[name] = str(exc)

            self.logger.exception(
                "Component shutdown failed: %s",
                name,
            )
            return False

    def stop_all(self) -> bool:
        with self._lock:
            names = list(reversed(list(self.components)))

        success = True

        for name in names:
            if not self.stop_component(name):
                success = False

        with self._lock:
            self._started = False

        return success

    def get_state(self, name: str) -> ComponentState | None:
        with self._lock:
            return self.states.get(name)

    def get_status(self) -> dict[str, Any]:
        with self._lock:
            return {
                "started": self._started,
                "total_components": len(self.components),
                "states": {
                    name: state.value
                    for name, state in self.states.items()
                },
                "errors": dict(self.errors),
            }
# Compatibilidade com módulos que utilizam o nome antigo.
Orchestrator = CoreOrchestrator
