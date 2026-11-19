
"""
NETSHADOW - Dependency Audit

Auditoria local das dependências Python.
Não instala nem modifica pacotes.
"""

import importlib.metadata
import re

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


class DependencyAuditError(Exception):
    """Erro durante a auditoria de dependências."""


@dataclass
class DependencyResult:
    name: str
    required: bool
    installed: bool
    installed_version: Optional[str]
    minimum_version: Optional[str]
    status: str
    message: str


class DependencyAudit:
    """Analisa dependências instaladas no ambiente Python."""

    MAX_DEPENDENCIES = 500

    DEFAULT_DEPENDENCIES = {
        "PyYAML": "6.0",
        "psutil": "5.9",
        "pytest": "8.0",
        "pytest-cov": "5.0",
    }

    def __init__(
        self,
        dependencies: Optional[Dict[str, str]] = None,
    ):
        source = (
            dependencies
            if dependencies is not None
            else self.DEFAULT_DEPENDENCIES
        )

        if not isinstance(source, dict):
            raise DependencyAuditError(
                "Configuração de dependências inválida."
            )

        if len(source) > self.MAX_DEPENDENCIES:
            raise DependencyAuditError(
                "Número excessivo de dependências."
            )

        self.dependencies = {}

        for name, minimum in source.items():
            if not self._valid_name(name):
                raise DependencyAuditError(
                    "Nome de dependência inválido."
                )

            if minimum is not None and not self._valid_version(minimum):
                raise DependencyAuditError(
                    "Versão mínima inválida."
                )

            self.dependencies[name] = minimum

        self._results: List[DependencyResult] = []

    @staticmethod
    def _valid_name(name: str) -> bool:
        return (
            isinstance(name, str)
            and re.fullmatch(
                r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}",
                name,
            ) is not None
        )

    @staticmethod
    def _valid_version(version: str) -> bool:
        return (
            isinstance(version, str)
            and re.fullmatch(
                r"[0-9]+(?:\.[0-9A-Za-z]+)*(?:[-+][0-9A-Za-z.-]+)?",
                version,
            ) is not None
        )

    @staticmethod
    def _version_tuple(version: str) -> Tuple:
        """
        Comparação simplificada de versões numéricas.

        Não substitui um comparador completo PEP 440.
        """

        match = re.match(r"^(\d+(?:\.\d+)*)", version)

        if not match:
            return ()

        return tuple(
            int(part)
            for part in match.group(1).split(".")
        )

    def _check_dependency(
        self,
        name: str,
        minimum: Optional[str],
    ) -> DependencyResult:

        try:
            installed_version = (
                importlib.metadata.version(name)
            )

        except importlib.metadata.PackageNotFoundError:
            return DependencyResult(
                name=name,
                required=True,
                installed=False,
                installed_version=None,
                minimum_version=minimum,
                status="MISSING",
                message="Pacote não instalado.",
            )

        status = "OK"
        message = "Dependência instalada."

        if minimum is not None:
            installed_tuple = self._version_tuple(
                installed_version
            )

            minimum_tuple = self._version_tuple(minimum)

            if not installed_tuple or not minimum_tuple:
                status = "UNKNOWN_VERSION"
                message = "Não foi possível comparar as versões."

            elif installed_tuple < minimum_tuple:
                status = "OUTDATED"
                message = "Versão inferior ao mínimo configurado."

        return DependencyResult(
            name=name,
            required=True,
            installed=True,
            installed_version=installed_version,
            minimum_version=minimum,
            status=status,
            message=message,
        )

    def run_audit(self) -> List[DependencyResult]:
        """Executa uma auditoria local das dependências."""

        results = []

        for name, minimum in self.dependencies.items():
            results.append(
                self._check_dependency(name, minimum)
            )

        self._results = results

        return list(results)

    def get_results(self) -> List[DependencyResult]:
        return list(self._results)

    def get_summary(self) -> dict:
        summary = {
            "total": len(self._results),
            "installed": 0,
            "missing": 0,
            "outdated": 0,
            "unknown_version": 0,
        }

        for result in self._results:
            if result.status == "MISSING":
                summary["missing"] += 1
            elif result.status == "OUTDATED":
                summary["outdated"] += 1
            elif result.status == "UNKNOWN_VERSION":
                summary["unknown_version"] += 1
            else:
                summary["installed"] += 1

        return summary

    def check_package(self, name: str) -> Optional[DependencyResult]:
        if not self._valid_name(name):
            raise DependencyAuditError(
                "Nome de pacote inválido."
            )

        for result in self._results:
            if result.name.lower() == name.lower():
                return result

        return None

    def reset(self) -> None:
        self._results.clear()
