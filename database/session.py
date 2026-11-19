
"""
NETSHADOW - Database Session Manager

Gere sessões, consultas e transações SQLite.
Inclui suporte a rollback e gestão segura de ligações.
"""

from __future__ import annotations

import logging
import sqlite3
import threading

from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Optional, Sequence


logger = logging.getLogger(__name__)


class SessionError(RuntimeError):
    """Erro geral de sessão."""


class SessionClosedError(SessionError):
    """Tentativa de utilizar uma sessão encerrada."""


class DatabaseSession:
    """Gere uma ligação SQLite e as respetivas transações."""

    def __init__(
        self,
        database: str | Path = ":memory:",
        timeout: float = 10.0,
    ) -> None:
        if timeout <= 0:
            raise ValueError("O timeout tem de ser positivo.")

        self.database = str(database)
        self.timeout = timeout
        self._connection: Optional[sqlite3.Connection] = None
        self._lock = threading.RLock()
        self._transaction_depth = 0
        self._savepoint_counter = 0
        self._closed = False

        self.connect()

    def connect(self) -> sqlite3.Connection:
        """Cria ou devolve a ligação SQLite existente."""

        with self._lock:
            if self._closed:
                raise SessionClosedError(
                    "A sessão já foi encerrada."
                )

            if self._connection is not None:
                return self._connection

            if self.database != ":memory:":
                path = Path(self.database).expanduser().resolve()
                path.parent.mkdir(parents=True, exist_ok=True)
                self.database = str(path)

            try:
                self._connection = sqlite3.connect(
                    self.database,
                    timeout=self.timeout,
                    check_same_thread=False,
                    isolation_level=None,
                )

                self._connection.row_factory = sqlite3.Row

                self._connection.execute(
                    "PRAGMA foreign_keys = ON"
                )

                return self._connection

            except sqlite3.Error as exc:
                raise SessionError(
                    f"Não foi possível abrir a base de dados: {exc}"
                ) from exc

    @property
    def connection(self) -> sqlite3.Connection:
        """Devolve a ligação ativa."""

        with self._lock:
            if self._closed or self._connection is None:
                raise SessionClosedError(
                    "Não existe uma ligação ativa."
                )

            return self._connection

    @property
    def is_connected(self) -> bool:
        with self._lock:
            return (
                not self._closed
                and self._connection is not None
            )

    @property
    def in_transaction(self) -> bool:
        with self._lock:
            return self._transaction_depth > 0

    def execute(
        self,
        query: str,
        parameters: Sequence[Any] = (),
    ) -> sqlite3.Cursor:
        """Executa uma instrução SQL sem confirmar automaticamente."""

        with self._lock:
            try:
                return self.connection.execute(
                    query,
                    tuple(parameters),
                )

            except sqlite3.Error as exc:
                logger.error("Erro SQL: %s", exc)
                raise SessionError(
                    f"Falha na execução SQL: {exc}"
                ) from exc

    def executemany(
        self,
        query: str,
        parameters: Sequence[Sequence[Any]],
    ) -> sqlite3.Cursor:
        """Executa uma instrução SQL sobre vários conjuntos de dados."""

        with self._lock:
            try:
                return self.connection.executemany(
                    query,
                    parameters,
                )

            except sqlite3.Error as exc:
                logger.error("Erro SQL em lote: %s", exc)
                raise SessionError(
                    f"Falha na execução SQL em lote: {exc}"
                ) from exc

    def fetchone(
        self,
        query: str,
        parameters: Sequence[Any] = (),
    ) -> Optional[sqlite3.Row]:
        """Executa uma consulta e devolve uma linha."""

        with self._lock:
            cursor = self.execute(query, parameters)
            return cursor.fetchone()

    def fetchall(
        self,
        query: str,
        parameters: Sequence[Any] = (),
    ) -> list[sqlite3.Row]:
        """Executa uma consulta e devolve todas as linhas."""

        with self._lock:
            cursor = self.execute(query, parameters)
            return cursor.fetchall()

    def commit(self) -> None:
        """Confirma a transação ativa."""

        with self._lock:
            if self._transaction_depth > 0:
                raise SessionError(
                    "Não podes confirmar manualmente uma transação "
                    "gerida por transaction()."
                )

            try:
                self.connection.commit()
            except sqlite3.Error as exc:
                raise SessionError(
                    f"Falha ao confirmar transação: {exc}"
                ) from exc

    def rollback(self) -> None:
        """Reverte a transação ativa."""

        with self._lock:
            if self._transaction_depth > 0:
                raise SessionError(
                    "Não podes reverter manualmente uma transação "
                    "gerida por transaction()."
                )

            try:
                self.connection.rollback()
            except sqlite3.Error as exc:
                raise SessionError(
                    f"Falha no rollback: {exc}"
                ) from exc

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """
        Abre uma transação.

        Transações aninhadas utilizam SAVEPOINT.
        A confirmação só ocorre no fim do bloco exterior.
        """

        with self._lock:
            connection = self.connection
            nested = self._transaction_depth > 0

            if nested:
                self._savepoint_counter += 1
                savepoint = (
                    f"netshadow_sp_{self._savepoint_counter}"
                )

                connection.execute(
                    f"SAVEPOINT {savepoint}"
                )
            else:
                savepoint = None
                connection.execute("BEGIN")

            self._transaction_depth += 1

            try:
                yield connection

                if nested:
                    connection.execute(
                        f"RELEASE SAVEPOINT {savepoint}"
                    )
                else:
                    connection.commit()

            except Exception:
                try:
                    if nested:
                        connection.execute(
                            f"ROLLBACK TO SAVEPOINT {savepoint}"
                        )
                        connection.execute(
                            f"RELEASE SAVEPOINT {savepoint}"
                        )
                    else:
                        connection.rollback()
                except sqlite3.Error:
                    logger.exception(
                        "Falha adicional durante rollback."
                    )

                raise

            finally:
                self._transaction_depth -= 1

    def close(self) -> None:
        """Encerra a ligação à base de dados."""

        with self._lock:
            if self._closed:
                return

            if self._transaction_depth > 0:
                raise SessionError(
                    "Não podes encerrar a sessão durante uma transação."
                )

            if self._connection is not None:
                try:
                    self._connection.close()
                except sqlite3.Error as exc:
                    raise SessionError(
                        f"Falha ao encerrar sessão: {exc}"
                    ) from exc

                self._connection = None

            self._closed = True
            logger.info("Sessão SQLite encerrada.")

    def __enter__(self) -> DatabaseSession:
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> bool:
        self.close()
        return False


# Compatibilidade com nomes alternativos.
Session = DatabaseSession
SessionManager = DatabaseSession
DatabaseSessionManager = DatabaseSession
