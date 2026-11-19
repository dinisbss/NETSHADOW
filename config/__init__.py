
from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


CONFIG_DIRECTORY = Path(__file__).resolve().parent

CONFIG_FILES = {
    "settings": CONFIG_DIRECTORY / "settings.yaml",
    "logging": CONFIG_DIRECTORY / "logging.yaml",
    "security": CONFIG_DIRECTORY / "security.yaml",
    "networks": CONFIG_DIRECTORY / "networks.yaml",
}


class ConfigurationError(Exception):
    """Erro durante o carregamento das configurações."""


def load_yaml_config(name: str) -> dict[str, Any]:
    """
    Carrega um ficheiro YAML da pasta config.

    Apenas aceita os ficheiros previamente definidos em CONFIG_FILES.
    """
    if not isinstance(name, str) or name not in CONFIG_FILES:
        raise ConfigurationError(f"Configuração desconhecida: {name!r}")

    path = CONFIG_FILES[name]

    try:
        with path.open("r", encoding="utf-8") as file:
            data = yaml.safe_load(file)
    except FileNotFoundError as exc:
        raise ConfigurationError(
            f"Ficheiro de configuração não encontrado: {path.name}"
        ) from exc
    except yaml.YAMLError as exc:
        raise ConfigurationError(
            f"YAML inválido em {path.name}"
        ) from exc
    except OSError as exc:
        raise ConfigurationError(
            f"Não foi possível ler {path.name}"
        ) from exc

    if not isinstance(data, dict):
        raise ConfigurationError(
            f"A configuração {path.name} tem de conter um objeto YAML."
        )

    return data


def load_all_configs() -> dict[str, dict[str, Any]]:
    """Carrega todas as configurações disponíveis."""
    return {
        name: load_yaml_config(name)
        for name in CONFIG_FILES
    }


def get_config(name: str) -> dict[str, Any]:
    """Obtém uma configuração pelo nome."""
    return load_yaml_config(name)


__all__ = [
    "CONFIG_DIRECTORY",
    "CONFIG_FILES",
    "ConfigurationError",
    "load_yaml_config",
    "load_all_configs",
    "get_config",
]
