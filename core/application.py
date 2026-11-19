
"""
NETSHADOW - Application Core

Ponto central de inicialização e encerramento da aplicação.
"""

from __future__ import annotations

import logging
from enum import Enum
from threading import RLock
from typing import Any

from core.orchestrator import Orchestrator


class ApplicationState(str, Enum):
    CREATED = "CREATED"
    STARTING = "STARTING"
    RUNNING = "RUNNING"
    STOPPING = "STOPPING"
    STOPPED = "STOPPED"
    FAILED = "FAILED"


class NetShadowApplication:
    """Coordena o ciclo de vida global do NETSHADOW."""

    def __init__(
        self,
        logger: logging.Logger | None = None,
        orchestrator: Orchestrator | None = None,
    ):
        self.logger = logger or logging.getLogger("NETSHADOW")
        self.orchestrator = orchestrator or Orchestrator()
        self.state = ApplicationState.CREATED
        self._lock = RLock()

    def register_component(
        self,
        name: str,
        component: Any,
    ) -> None:
        with self._lock:
            if self.state != ApplicationState.CREATED:
                raise RuntimeError(
                    "Components must be registered before startup."
                )

            self.orchestrator.register(name, component)

    def start(self) -> bool:
        with self._lock:
            if self.state == ApplicationState.RUNNING:
                return True

            if self.state in {
                ApplicationState.STARTING,
                ApplicationState.STOPPING,
            }:
                return False

            self.state = ApplicationState.STARTING

        try:
            success = self.orchestrator.start_all()

            with self._lock:
                self.state = (
                    ApplicationState.RUNNING
                    if success
                    else ApplicationState.FAILED
                )

            return success

        except Exception:
            with self._lock:
                self.state = ApplicationState.FAILED

            self.logger.exception(
                "Application startup failed."
            )
            return False

    def stop(self) -> bool:
        with self._lock:
            if self.state == ApplicationState.STOPPED:
                return True

            self.state = ApplicationState.STOPPING

        try:
            success = self.orchestrator.stop_all()

            with self._lock:
                self.state = ApplicationState.STOPPED

            return success

        except Exception:
            with self._lock:
                self.state = ApplicationState.FAILED

            self.logger.exception(
                "Application shutdown failed."
            )
            return False

    def get_status(self) -> dict[str, Any]:
        with self._lock:
            return {
                "state": self.state.value,
                "orchestrator": self.orchestrator.get_status(),
            }


Application = NetShadowApplication
