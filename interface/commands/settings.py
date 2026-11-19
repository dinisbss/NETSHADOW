
"""Settings commands for NETSHADOW."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

import yaml


class SettingsCommandError(RuntimeError):
    """Raised when a settings operation fails."""


class SettingsCommand:
    """Read and safely manage application settings."""

    def __init__(
        self,
        settings_path: Optional[str | Path] = None,
    ) -> None:
        if settings_path is None:
            settings_path = (
                Path(__file__).resolve().parents[2]
                / "config"
                / "settings.yaml"
            )

        self.settings_path = Path(settings_path).resolve()
        self._settings: dict[str, Any] = {}

    def load(self) -> dict[str, Any]:
        """Load settings from the YAML configuration file."""
        if not self.settings_path.is_file():
            raise SettingsCommandError(
                f"Settings file not found: {self.settings_path}"
            )

        try:
            with self.settings_path.open(
                "r",
                encoding="utf-8",
            ) as file:
                data = yaml.safe_load(file)

            if data is None:
                data = {}

            if not isinstance(data, dict):
                raise SettingsCommandError(
                    "Settings file must contain a YAML mapping."
                )

            self._settings = data
            return self.get_settings()

        except SettingsCommandError:
            raise
        except yaml.YAMLError as exc:
            raise SettingsCommandError(
                f"Invalid YAML configuration: {exc}"
            ) from exc
        except OSError as exc:
            raise SettingsCommandError(
                f"Unable to read settings: {exc}"
            ) from exc

    def get_settings(self) -> dict[str, Any]:
        """Return a copy of the current settings."""
        return self._safe_copy(self._settings)

    @classmethod
    def _safe_copy(cls, value: Any) -> Any:
        if isinstance(value, dict):
            return {
                key: cls._safe_copy(item)
                for key, item in value.items()
            }

        if isinstance(value, list):
            return [cls._safe_copy(item) for item in value]

        return value

    def get_setting(self, key: str, default: Any = None) -> Any:
        """Retrieve a setting using a dotted key."""
        if not isinstance(key, str) or not key.strip():
            raise ValueError("Setting key cannot be empty.")

        current: Any = self._settings

        for part in key.split("."):
            if not isinstance(current, dict):
                return default

            if part not in current:
                return default

            current = current[part]

        return self._safe_copy(current)

    def validate_key(self, key: str) -> bool:
        """Check whether a dotted setting key exists."""
        marker = object()
        return self.get_setting(key, marker) is not marker

    def display_settings(self) -> None:
        """Display loaded settings without exposing secrets."""
        settings = self.get_settings()

        if not settings:
            settings = self.load()

        sensitive_words = (
            "password",
            "secret",
            "token",
            "api_key",
            "apikey",
            "private_key",
            "credential",
        )

        def redact(value: Any, parent_key: str = "") -> Any:
            normalized = parent_key.lower()

            if any(word in normalized for word in sensitive_words):
                return "[REDACTED]"

            if isinstance(value, dict):
                return {
                    key: redact(item, str(key))
                    for key, item in value.items()
                }

            if isinstance(value, list):
                return [redact(item, parent_key) for item in value]

            return value

        import json

        print("\nNETSHADOW - SETTINGS")
        print("=" * 55)
        print(
            json.dumps(
                redact(settings),
                indent=2,
                ensure_ascii=False,
                default=str,
            )
        )
        print("=" * 55)


SettingsManager = SettingsCommand
SettingsCommands = SettingsCommand

__all__ = [
    "SettingsCommandError",
    "SettingsCommand",
    "SettingsManager",
    "SettingsCommands",
]
