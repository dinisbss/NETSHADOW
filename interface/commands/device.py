
"""Device management commands for NETSHADOW."""

from __future__ import annotations

from typing import Any, Optional

from database.database import DatabaseManager
from database.repositories.device_repository import DeviceRepository


class DeviceCommandError(RuntimeError):
    """Raised when a device command fails."""


class DeviceCommand:
    """Provides read-only access to registered device records."""

    def __init__(
        self,
        repository: Optional[DeviceRepository] = None,
        database: Optional[DatabaseManager] = None,
    ) -> None:
        self.database = database
        self._owns_database = False

        if repository is not None:
            self.repository = repository
        else:
            if self.database is None:
                self.database = DatabaseManager()
                self._owns_database = True

            self.repository = DeviceRepository(self.database)

    @staticmethod
    def _serialize(device: Any) -> dict[str, Any]:
        if isinstance(device, dict):
            return device.copy()

        if hasattr(device, "to_dict"):
            result = device.to_dict()
            if isinstance(result, dict):
                return result

        if hasattr(device, "__dict__"):
            return {
                key: value
                for key, value in vars(device).items()
                if not key.startswith("_")
            }

        raise DeviceCommandError("Unsupported device record format.")

    def list_devices(self) -> list[dict[str, Any]]:
        try:
            devices = self.repository.get_all()
            return [self._serialize(device) for device in devices or []]
        except Exception as exc:
            raise DeviceCommandError(
                f"Unable to retrieve devices: {exc}"
            ) from exc

    def get_device(self, device_id: int) -> dict[str, Any]:
        if isinstance(device_id, bool) or not isinstance(device_id, int):
            raise ValueError("Device ID must be an integer.")

        if device_id <= 0:
            raise ValueError("Device ID must be positive.")

        try:
            device = self.repository.get_by_id(device_id)

            if device is None:
                raise DeviceCommandError(
                    f"Device {device_id} was not found."
                )

            return self._serialize(device)
        except DeviceCommandError:
            raise
        except Exception as exc:
            raise DeviceCommandError(
                f"Unable to retrieve device: {exc}"
            ) from exc

    def count_devices(self) -> int:
        try:
            return int(self.repository.count())
        except Exception as exc:
            raise DeviceCommandError(
                f"Unable to count devices: {exc}"
            ) from exc

    def display_devices(self) -> None:
        devices = self.list_devices()

        print("\nNETSHADOW - REGISTERED DEVICES")
        print("=" * 65)

        if not devices:
            print("No registered devices.")
        else:
            for index, device in enumerate(devices, start=1):
                print(f"\nDevice #{index}")
                for key, value in device.items():
                    print(f"  {key}: {value}")
                print("-" * 65)

        print(f"Total devices: {len(devices)}")
        print("=" * 65)

    def display_device(self, device_id: int) -> None:
        device = self.get_device(device_id)

        print("\nNETSHADOW - DEVICE DETAILS")
        print("=" * 50)

        for key, value in device.items():
            print(f"{key}: {value}")

        print("=" * 50)

    def display_summary(self) -> None:
        print("\nDEVICE INVENTORY")
        print("-" * 40)
        print(f"Registered devices: {self.count_devices()}")
        print("-" * 40)

    def close(self) -> None:
        """Close the database only when this command owns it."""
        if self._owns_database and self.database is not None:
            self.database.close()
            self._owns_database = False


DeviceCommands = DeviceCommand
DeviceManagerCommand = DeviceCommand

__all__ = [
    "DeviceCommandError",
    "DeviceCommand",
    "DeviceCommands",
    "DeviceManagerCommand",
]
