
"""
NETSHADOW - Database Manager

Gestão SQLite, inicialização do esquema, migrações,
transações e operações de persistência.
"""

from __future__ import annotations

import sqlite3
import threading

from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Optional


class DatabaseError(RuntimeError):
    """Erro geral da camada de base de dados."""


class DatabaseManager:
    """Gestor de ligações e operações SQLite."""

    def __init__(
        self,
        database_path: str = "data/netshadow.db",
        timeout: float = 10.0,
        **kwargs: Any,
    ) -> None:
        if "db_path" in kwargs:
            database_path = kwargs.pop("db_path")

        if kwargs:
            raise TypeError(
                f"Argumentos desconhecidos: {', '.join(kwargs)}"
            )

        if not isinstance(database_path, str):
            raise TypeError("database_path tem de ser texto.")

        if timeout <= 0:
            raise ValueError("timeout tem de ser positivo.")

        self.database_path = database_path
        self.timeout = timeout

        self._connection: Optional[sqlite3.Connection] = None
        self._lock = threading.RLock()
        self._transaction_depth = 0
        self._savepoint_counter = 0
        self._initialized = False

    @property
    def is_connected(self) -> bool:
        return self._connection is not None

    @property
    def connection_object(self) -> Optional[sqlite3.Connection]:
        return self._connection

    def connect(self) -> sqlite3.Connection:
        """Abre a ligação à base de dados."""

        with self._lock:
            if self._connection is not None:
                return self._connection

            try:
                if self.database_path != ":memory:":
                    Path(self.database_path).parent.mkdir(
                        parents=True,
                        exist_ok=True,
                    )

                connection = sqlite3.connect(
                    self.database_path,
                    timeout=self.timeout,
                    check_same_thread=False,
                )

                connection.row_factory = sqlite3.Row

                connection.execute("PRAGMA foreign_keys = ON")
                connection.execute(
                    f"PRAGMA busy_timeout = {int(self.timeout * 1000)}"
                )

                if self.database_path != ":memory:":
                    connection.execute("PRAGMA journal_mode = WAL")

                self._connection = connection
                return connection

            except sqlite3.Error as exc:
                raise DatabaseError(
                    f"Não foi possível ligar à base de dados: {exc}"
                ) from exc

    def _get_connection(self) -> sqlite3.Connection:
        if self._connection is None:
            return self.connect()

        return self._connection

    def initialize(self) -> None:
        """Cria as tabelas e aplica migrações necessárias."""

        with self._lock:
            connection = self._get_connection()

            schema = """
            CREATE TABLE IF NOT EXISTS networks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                network TEXT,
                network_address TEXT,
                name TEXT NOT NULL,
                description TEXT DEFAULT '',
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                network_id INTEGER,
                ip_address TEXT NOT NULL,
                mac_address TEXT,
                hostname TEXT,
                vendor TEXT,
                status TEXT DEFAULT 'unknown',
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (network_id)
                    REFERENCES networks(id)
                    ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                network_id INTEGER,
                scan_type TEXT,
                status TEXT DEFAULT 'pending',
                started_at TEXT DEFAULT CURRENT_TIMESTAMP,
                completed_at TEXT,
                FOREIGN KEY (network_id)
                    REFERENCES networks(id)
                    ON DELETE SET NULL
            );

            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                device_id INTEGER,
                severity TEXT DEFAULT 'info',
                title TEXT NOT NULL,
                description TEXT DEFAULT '',
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_id)
                    REFERENCES scans(id)
                    ON DELETE CASCADE,
                FOREIGN KEY (device_id)
                    REFERENCES devices(id)
                    ON DELETE SET NULL
            );

            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                report_type TEXT,
                file_path TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_id)
                    REFERENCES scans(id)
                    ON DELETE SET NULL
            );

            CREATE INDEX IF NOT EXISTS idx_devices_network
                ON devices(network_id);

            CREATE INDEX IF NOT EXISTS idx_devices_ip
                ON devices(ip_address);

            CREATE INDEX IF NOT EXISTS idx_scans_network
                ON scans(network_id);

            CREATE INDEX IF NOT EXISTS idx_findings_scan
                ON findings(scan_id);

            CREATE INDEX IF NOT EXISTS idx_reports_scan
                ON reports(scan_id);
            """

            try:
                connection.executescript(schema)

                # Migração da tabela networks.
                columns = {
                    row["name"]
                    for row in connection.execute(
                        "PRAGMA table_info(networks)"
                    ).fetchall()
                }

                migrations = {
                    "network": "TEXT",
                    "network_address": "TEXT",
                    "description": "TEXT DEFAULT ''",
                    "created_at": "TEXT",
                    "updated_at": "TEXT",
                }

                for column, definition in migrations.items():
                    if column not in columns:
                        connection.execute(
                            f"ALTER TABLE networks ADD COLUMN "
                            f"{column} {definition}"
                        )

                connection.execute(
                    """
                    UPDATE networks
                    SET network = COALESCE(network, network_address),
                        network_address = COALESCE(
                            network_address, network
                        ),
                        updated_at = COALESCE(
                            updated_at, created_at, CURRENT_TIMESTAMP
                        ),
                        description = COALESCE(description, '')
                    """
                )

                connection.commit()
                self._initialized = True

            except sqlite3.Error as exc:
                connection.rollback()
                raise DatabaseError(
                    f"Erro ao inicializar a base de dados: {exc}"
                ) from exc

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        """
        Context manager transacional.

        Transações aninhadas utilizam SAVEPOINT.
        """

        with self._lock:
            conn = self._get_connection()

            nested = self._transaction_depth > 0
            savepoint = None

            try:
                if nested:
                    self._savepoint_counter += 1
                    savepoint = (
                        f"netshadow_sp_{self._savepoint_counter}"
                    )
                    conn.execute(f"SAVEPOINT {savepoint}")
                else:
                    conn.execute("BEGIN")

                self._transaction_depth += 1

                try:
                    yield conn

                    if nested and savepoint:
                        conn.execute(f"RELEASE SAVEPOINT {savepoint}")
                    else:
                        conn.commit()

                except Exception:
                    if nested and savepoint:
                        conn.execute(
                            f"ROLLBACK TO SAVEPOINT {savepoint}"
                        )
                        conn.execute(
                            f"RELEASE SAVEPOINT {savepoint}"
                        )
                    else:
                        conn.rollback()

                    raise

            except sqlite3.Error as exc:
                raise DatabaseError(
                    f"Erro na transação: {exc}"
                ) from exc

            finally:
                if self._transaction_depth > 0:
                    self._transaction_depth -= 1

    def execute(
        self,
        query: str,
        parameters: tuple = (),
    ) -> sqlite3.Cursor:
        """Executa uma instrução SQL."""

        with self._lock:
            connection = self._get_connection()

            try:
                cursor = connection.execute(
                    query,
                    tuple(parameters),
                )

                if self._transaction_depth == 0:
                    connection.commit()

                return cursor

            except sqlite3.Error as exc:
                if self._transaction_depth == 0:
                    connection.rollback()

                raise DatabaseError(
                    f"Erro ao executar SQL: {exc}"
                ) from exc

    def executemany(
        self,
        query: str,
        parameters: list[tuple],
    ) -> sqlite3.Cursor:
        """Executa uma instrução SQL para vários registos."""

        with self._lock:
            connection = self._get_connection()

            try:
                cursor = connection.executemany(
                    query,
                    parameters,
                )

                if self._transaction_depth == 0:
                    connection.commit()

                return cursor

            except sqlite3.Error as exc:
                if self._transaction_depth == 0:
                    connection.rollback()

                raise DatabaseError(
                    f"Erro ao executar operações SQL: {exc}"
                ) from exc

    def fetchone(
        self,
        query: str,
        parameters: tuple = (),
    ) -> Optional[sqlite3.Row]:
        """Obtém um registo."""

        with self._lock:
            try:
                return self._get_connection().execute(
                    query,
                    tuple(parameters),
                ).fetchone()

            except sqlite3.Error as exc:
                raise DatabaseError(
                    f"Erro ao consultar registo: {exc}"
                ) from exc

    def fetchall(
        self,
        query: str,
        parameters: tuple = (),
    ) -> list[sqlite3.Row]:
        """Obtém vários registos."""

        with self._lock:
            try:
                return self._get_connection().execute(
                    query,
                    tuple(parameters),
                ).fetchall()

            except sqlite3.Error as exc:
                raise DatabaseError(
                    f"Erro ao consultar registos: {exc}"
                ) from exc

    def fetch_all(
        self,
        query: str,
        parameters: tuple = (),
    ) -> list[sqlite3.Row]:
        """Alias de fetchall."""

        return self.fetchall(query, parameters)

    def create_session(self):
        """Cria uma sessão independente."""

        from database.session import DatabaseSession

        return DatabaseSession(
            database=self.database_path,
            timeout=self.timeout,
        )

    def health_check(self) -> bool:
        """Verifica se a ligação está operacional."""

        try:
            row = self.fetchone("SELECT 1 AS result")
            return row is not None and row["result"] == 1

        except DatabaseError:
            return False

    def get_status(self) -> dict:
        """Devolve o estado da base de dados."""

        return {
            "connected": self.is_connected,
            "initialized": self._initialized,
            "healthy": self.health_check(),
            "database_path": self.database_path,
            "transaction_depth": self._transaction_depth,
        }

    def close(self) -> None:
        """Fecha a ligação."""

        with self._lock:
            if self._connection is None:
                return

            if self._transaction_depth > 0:
                raise DatabaseError(
                    "Não é possível fechar durante uma transação."
                )

            try:
                self._connection.close()
                self._connection = None
                self._initialized = False

            except sqlite3.Error as exc:
                raise DatabaseError(
                    f"Erro ao fechar a base de dados: {exc}"
                ) from exc

    def __enter__(self):
        self.connect()
        self.initialize()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()


Database = DatabaseManager
SQLiteDatabase = DatabaseManager


__all__ = [
    "DatabaseError",
    "DatabaseManager",
    "Database",
    "SQLiteDatabase",
]
