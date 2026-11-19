
from __future__ import annotations

import sys
import time
import threading
from dataclasses import dataclass
from typing import Optional, TextIO


class ProgressError(Exception):
    """Erro relacionado com a gestão do progresso."""


@dataclass
class ProgressState:
    """Estado atual de uma operação."""
    total: int
    current: int = 0
    description: str = "A processar"
    started_at: float = 0.0
    finished: bool = False
    failed: bool = False

    @property
    def percentage(self) -> float:
        if self.total <= 0:
            return 100.0
        return min(100.0, (self.current / self.total) * 100)

    @property
    def elapsed(self) -> float:
        if not self.started_at:
            return 0.0
        return max(0.0, time.monotonic() - self.started_at)


class ProgressBar:
    """Barra de progresso simples para o terminal."""

    def __init__(
        self,
        total: int,
        description: str = "A processar",
        width: int = 30,
        stream: Optional[TextIO] = None,
    ):
        if not isinstance(total, int) or isinstance(total, bool) or total < 0:
            raise ProgressError("O total deve ser um inteiro não negativo.")

        if not isinstance(width, int) or width < 5:
            raise ProgressError("A largura deve ser um inteiro igual ou superior a 5.")

        self.state = ProgressState(
            total=total,
            description=str(description),
            started_at=time.monotonic(),
        )
        self.width = width
        self.stream = stream or sys.stdout
        self._lock = threading.RLock()
        self._rendered = False

    def update(self, amount: int = 1) -> ProgressState:
        """Atualiza o progresso sem ultrapassar o total."""
        if not isinstance(amount, int) or isinstance(amount, bool):
            raise ProgressError("O incremento deve ser um inteiro.")

        with self._lock:
            if self.state.finished:
                raise ProgressError("A operação já terminou.")

            self.state.current = max(
                0,
                min(self.state.total, self.state.current + amount),
            )
            self.render()
            return self.get_state()

    def set_progress(self, value: int) -> ProgressState:
        """Define diretamente o progresso atual."""
        if not isinstance(value, int) or isinstance(value, bool):
            raise ProgressError("O progresso deve ser um inteiro.")

        with self._lock:
            if self.state.finished:
                raise ProgressError("A operação já terminou.")

            self.state.current = max(0, min(self.state.total, value))
            self.render()
            return self.get_state()

    def set_description(self, description: str) -> None:
        with self._lock:
            self.state.description = str(description)
            self.render()

    def render(self) -> None:
        """Desenha a barra de progresso."""
        with self._lock:
            percentage = self.state.percentage

            if self.state.total == 0:
                filled = self.width
            else:
                filled = int(self.width * percentage / 100)

            bar = "#" * filled + "-" * (self.width - filled)

            line = (
                f"\r{self.state.description} "
                f"[{bar}] {percentage:6.2f}% "
                f"({self.state.current}/{self.state.total})"
            )

            if self.state.finished:
                line += " CONCLUIDO"
            elif self.state.failed:
                line += " FALHOU"

            self.stream.write(line)
            self.stream.flush()
            self._rendered = True

            if self.state.finished or self.state.failed:
                self.stream.write("\n")
                self.stream.flush()

    def finish(self) -> ProgressState:
        """Conclui a operação."""
        with self._lock:
            self.state.current = self.state.total
            self.state.finished = True
            self.render()
            return self.get_state()

    def fail(self) -> ProgressState:
        """Marca a operação como falhada."""
        with self._lock:
            self.state.failed = True
            self.render()
            return self.get_state()

    def reset(self) -> ProgressState:
        """Reinicia a barra de progresso."""
        with self._lock:
            self.state.current = 0
            self.state.finished = False
            self.state.failed = False
            self.state.started_at = time.monotonic()
            self.render()
            return self.get_state()

    def get_state(self) -> ProgressState:
        with self._lock:
            return ProgressState(
                total=self.state.total,
                current=self.state.current,
                description=self.state.description,
                started_at=self.state.started_at,
                finished=self.state.finished,
                failed=self.state.failed,
            )

    def get_status(self) -> dict:
        state = self.get_state()
        return {
            "total": state.total,
            "current": state.current,
            "description": state.description,
            "percentage": state.percentage,
            "elapsed": state.elapsed,
            "finished": state.finished,
            "failed": state.failed,
        }


class ProgressManager:
    """Gere várias barras de progresso."""

    def __init__(self):
        self._progress_bars: dict[str, ProgressBar] = {}
        self._lock = threading.RLock()

    def create(
        self,
        name: str,
        total: int,
        description: Optional[str] = None,
    ) -> ProgressBar:
        with self._lock:
            if not name:
                raise ProgressError("O nome da operação é obrigatório.")

            if name in self._progress_bars:
                raise ProgressError(f"Já existe uma operação chamada '{name}'.")

            progress = ProgressBar(
                total=total,
                description=description or name,
            )
            self._progress_bars[name] = progress
            return progress

    def get(self, name: str) -> Optional[ProgressBar]:
        with self._lock:
            return self._progress_bars.get(name)

    def remove(self, name: str) -> bool:
        with self._lock:
            return self._progress_bars.pop(name, None) is not None

    def get_all_status(self) -> dict:
        with self._lock:
            return {
                name: progress.get_status()
                for name, progress in self._progress_bars.items()
            }

    def clear(self) -> None:
        with self._lock:
            self._progress_bars.clear()


# Compatibilidade com nomes alternativos.
Progress = ProgressBar
ProgressTracker = ProgressBar
ProgressController = ProgressManager
ProgressBarManager = ProgressManager
NetShadowProgress = ProgressBar

__all__ = [
    "ProgressError",
    "ProgressState",
    "ProgressBar",
    "ProgressManager",
    "Progress",
    "ProgressTracker",
    "ProgressController",
    "ProgressBarManager",
    "NetShadowProgress",
]
