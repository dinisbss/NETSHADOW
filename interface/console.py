
"""Console utilities for NETSHADOW."""

from __future__ import annotations

import sys
from typing import Any, Optional


class ConsoleError(RuntimeError):
    """Raised when a console operation fails."""


class Console:
    """Centralized terminal output manager."""

    COLORS = {
        "reset": "\033[0m",
        "red": "\033[31m",
        "green": "\033[32m",
        "yellow": "\033[33m",
        "blue": "\033[34m",
        "cyan": "\033[36m",
        "white": "\033[37m",
        "bold": "\033[1m",
    }

    def __init__(
        self,
        color: Optional[bool] = None,
        stream: Any = None,
    ) -> None:
        self.stream = stream if stream is not None else sys.stdout

        if color is None:
            self.color_enabled = bool(
                getattr(self.stream, "isatty", lambda: False)()
            )
        else:
            self.color_enabled = bool(color)

    def _colorize(self, message: str, color: str) -> str:
        """Apply terminal color when supported."""
        if not self.color_enabled:
            return message

        code = self.COLORS.get(color)

        if code is None:
            return message

        return f"{code}{message}{self.COLORS['reset']}"

    def write(self, message: Any = "") -> None:
        """Write text without adding a newline."""
        try:
            self.stream.write(str(message))
            self.stream.flush()
        except (OSError, ValueError) as exc:
            raise ConsoleError(
                f"Unable to write to console: {exc}"
            ) from exc

    def print(self, message: Any = "") -> None:
        """Write text followed by a newline."""
        self.write(f"{message}\n")

    def info(self, message: Any) -> None:
        self.print(
            self._colorize(f"[INFO] {message}", "cyan")
        )

    def success(self, message: Any) -> None:
        self.print(
            self._colorize(f"[SUCCESS] {message}", "green")
        )

    def warning(self, message: Any) -> None:
        self.print(
            self._colorize(f"[WARNING] {message}", "yellow")
        )

    def error(self, message: Any) -> None:
        self.print(
            self._colorize(f"[ERROR] {message}", "red")
        )

    def debug(self, message: Any) -> None:
        self.print(
            self._colorize(f"[DEBUG] {message}", "blue")
        )

    def title(self, message: str, width: int = 60) -> None:
        """Display a centered section title."""
        if width < 10:
            raise ValueError("Title width must be at least 10.")

        text = str(message)
        print_line = "=" * width

        self.print()
        self.print(self._colorize(print_line, "cyan"))
        self.print(self._colorize(text.center(width), "bold"))
        self.print(self._colorize(print_line, "cyan"))

    def separator(self, width: int = 60, char: str = "-") -> None:
        """Display a separator line."""
        if width < 1:
            raise ValueError("Separator width must be positive.")

        if not char:
            raise ValueError("Separator character cannot be empty.")

        self.print(char[0] * width)

    def clear(self) -> None:
        """Clear the terminal using a platform-independent command."""
        import os

        if not getattr(self.stream, "isatty", lambda: False)():
            return

        command = "cls" if os.name == "nt" else "clear"
        os.system(command)

    def read(self, prompt: str = "") -> str:
        """Read a line from the user."""
        try:
            return input(prompt)
        except (EOFError, KeyboardInterrupt):
            raise ConsoleError("Console input was interrupted.")

    def confirm(self, prompt: str, default: bool = False) -> bool:
        """Ask for a yes/no confirmation."""
        suffix = " [Y/n]: " if default else " [y/N]: "

        answer = self.read(prompt + suffix).strip().lower()

        if not answer:
            return default

        if answer in {"y", "yes", "s", "sim"}:
            return True

        if answer in {"n", "no", "nao", "não"}:
            return False

        self.warning("Invalid answer. Using the default value.")
        return default



TerminalConsole = Console
ConsoleManager = Console
NetShadowConsole = Console

__all__ = [
    "ConsoleError",
    "Console",
    "TerminalConsole",
    "ConsoleManager",
    "NetShadowConsole",
]
