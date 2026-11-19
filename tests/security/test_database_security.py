
import pytest

from database import (
    Database,
    NetworkModel,
    NetworkRepository,
)


@pytest.fixture
def database():
    db = Database(":memory:")
    db.initialize()

    yield db

    db.close()


def test_sql_parameters_are_safe(database):
    repository = NetworkRepository(database)

    malicious_name = "'; DROP TABLE networks; --"

    network = repository.create(
        NetworkModel(
            network="192.168.10.0/24",
            name=malicious_name,
            description="Security test",
        )
    )

    stored = repository.get_by_id(network.network_id)

    assert stored is not None
    assert stored.name == malicious_name

    # A tabela continua disponível.
    assert database.fetch_all(
        "SELECT * FROM networks"
    )


def test_foreign_keys_are_enabled(database):
    with database.connection() as connection:
        result = connection.execute(
            "PRAGMA foreign_keys"
        ).fetchone()

    assert result[0] == 1


def test_invalid_foreign_key_is_rejected(database):
    with database.connection() as connection:
        with pytest.raises(Exception):
            connection.execute(
                """
                INSERT INTO devices (
                    ip_address,
                    network_id,
                    created_at,
                    updated_at
                )
                VALUES (?, ?, ?, ?)
                """,
                (
                    "192.168.10.20",
                    999999,
                    "2026-01-01T00:00:00+00:00",
                    "2026-01-01T00:00:00+00:00",
                ),
            )


def test_transaction_rollback(database):
    with pytest.raises(RuntimeError):
        with database.connection() as connection:
            connection.execute(
                """
                INSERT INTO networks (
                    network,
                    name,
                    description,
                    created_at
                )
                VALUES (?, ?, ?, ?)
                """,
                (
                    "192.168.20.0/24",
                    "Rollback Test",
                    "",
                    "2026-01-01T00:00:00+00:00",
                ),
            )

            raise RuntimeError("Simulated transaction failure")

    result = database.fetch_all(
        "SELECT * FROM networks WHERE network = ?",
        ("192.168.20.0/24",),
    )

    assert len(result) == 0


def test_database_health_check(database):
    assert database.health_check() is True


def test_database_rejects_invalid_sql_parameters(database):
    with pytest.raises(Exception):
        database.execute(
            "SELECT * FROM tabela_inexistente"
        )
