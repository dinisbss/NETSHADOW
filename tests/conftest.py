
from __future__ import annotations

import pytest

from pathlib import Path
from tempfile import TemporaryDirectory

from database.database import Database


@pytest.fixture
def temporary_directory():
    """Disponibiliza um diretório temporário isolado."""

    with TemporaryDirectory(prefix="netshadow_test_") as directory:
        yield Path(directory)


@pytest.fixture
def test_database(temporary_directory):
    """Cria uma base de dados SQLite exclusiva para o teste."""

    database_path = temporary_directory / "test_netshadow.db"
    database = Database(database_path=database_path)

    database.initialize()

    try:
        yield database
    finally:
        database.close()


@pytest.fixture
def test_config():
    """Configuração segura e independente para testes."""

    return {
        "environment": "testing",
        "debug": False,
        "safe_mode": True,
        "database": {
            "type": "sqlite",
            "timeout": 5.0,
        },
        "network": {
            "active_auditing": False,
            "require_authorization": True,
        },
        "logging": {
            "level": "WARNING",
        },
    }
