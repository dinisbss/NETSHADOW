
"""
NETSHADOW - Platform Detector

Deteta o sistema operativo, arquitetura, distribuição
e características do ambiente de execução.
"""

from __future__ import annotations

import platform
import sys

from dataclasses import dataclass
from functools import lru_cache
from typing import Optional


class PlatformDetectionError(RuntimeError):
    """Erro durante a deteção da plataforma."""


@dataclass(frozen=True)
class PlatformInfo:
    """Informações detalhadas sobre a plataforma."""

    system: str
    release: str
    version: str
    machine: str
    architecture: str
    processor: str
    python_version: str
    python_implementation: str
    distribution: str
    is_windows: bool
    is_linux: bool
    is_macos: bool
    is_kali: bool

    def to_dict(self) -> dict:
        return {
            "system": self.system,
            "release": self.release,
            "version": self.version,
            "machine": self.machine,
            "architecture": self.architecture,
            "processor": self.processor,
            "python_version": self.python_version,
            "python_implementation": self.python_implementation,
            "distribution": self.distribution,
            "is_windows": self.is_windows,
            "is_linux": self.is_linux,
            "is_macos": self.is_macos,
            "is_kali": self.is_kali,
        }


class PlatformDetector:
    """Identifica e disponibiliza informações da plataforma."""

    def __init__(self) -> None:
        self._info: Optional[PlatformInfo] = None

    @staticmethod
    def _get_distribution() -> str:
        """Obtém o nome da distribuição Linux."""

        try:
            if hasattr(platform, "freedesktop_os_release"):
                data = platform.freedesktop_os_release()
                return data.get(
                    "PRETTY_NAME",
                    data.get("NAME", "Linux")
                )
        except (OSError, AttributeError):
            pass

        return "Linux"

    def detect(self, refresh: bool = False) -> PlatformInfo:
        """Deteta a plataforma atual."""

        if self._info is not None and not refresh:
            return self._info

        try:
            system = platform.system()
            release = platform.release()
            version = platform.version()
            machine = platform.machine()
            processor = platform.processor()

            architecture = platform.architecture()[0]
            python_version = platform.python_version()
            python_implementation = platform.python_implementation()

            if system == "Linux":
                distribution = self._get_distribution()
            else:
                distribution = system

            distribution_lower = distribution.lower()

            self._info = PlatformInfo(
                system=system,
                release=release,
                version=version,
                machine=machine,
                architecture=architecture,
                processor=processor,
                python_version=python_version,
                python_implementation=python_implementation,
                distribution=distribution,
                is_windows=system == "Windows",
                is_linux=system == "Linux",
                is_macos=system == "Darwin",
                is_kali="kali" in distribution_lower,
            )

            return self._info

        except Exception as exc:
            raise PlatformDetectionError(
                f"Falha na deteção da plataforma: {exc}"
            ) from exc

    def get_info(self) -> PlatformInfo:
        return self.detect()

    def get_system(self) -> str:
        return self.detect().system

    def get_platform_name(self) -> str:
        return get_platform_name()

    def get_architecture(self) -> str:
        return self.detect().architecture

    def is_supported(self) -> bool:
        info = self.detect()
        return info.is_windows or info.is_linux

    def get_capabilities(self) -> dict:
        info = self.detect()

        return {
            "platform_supported": self.is_supported(),
            "windows": info.is_windows,
            "linux": info.is_linux,
            "macos": info.is_macos,
            "kali": info.is_kali,
            "python_version": info.python_version,
            "architecture": info.architecture,
        }

    def get_status(self) -> dict:
        info = self.detect()

        return {
            "detected": True,
            "platform": info.to_dict(),
            "capabilities": self.get_capabilities(),
        }


# Instância partilhada para as funções públicas.
_default_detector = PlatformDetector()


def detect_platform(refresh: bool = False) -> PlatformInfo:
    """Deteta a plataforma e devolve PlatformInfo."""
    return _default_detector.detect(refresh=refresh)


def get_platform_info() -> dict:
    """Devolve as informações da plataforma em dicionário."""
    return detect_platform().to_dict()


def get_platform_name() -> str:
    """Devolve o nome do sistema operativo."""
    info = detect_platform()
    return info.distribution or info.system


def get_platform_system() -> str:
    """Devolve Windows, Linux ou Darwin."""
    return detect_platform().system


def get_platform_architecture() -> str:
    """Devolve a arquitetura do sistema."""
    return detect_platform().architecture


def is_supported_platform() -> bool:
    """Verifica se Windows ou Linux são utilizados."""
    return PlatformDetector().is_supported()


def is_windows() -> bool:
    return detect_platform().is_windows


def is_linux() -> bool:
    return detect_platform().is_linux


def is_kali_linux() -> bool:
    return detect_platform().is_kali


# Compatibilidade com nomes alternativos.
Platform = PlatformInfo
