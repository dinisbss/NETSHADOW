
"""
NETSHADOW - Input Validation

Validação centralizada de dados de entrada.
Não executa operações de rede ou ficheiros.
"""

from __future__ import annotations

import ipaddress
import math
import re

from pathlib import Path
from typing import Optional, Union


class InputValidationError(ValueError):
    """Erro de validação de dados de entrada."""


class InputValidator:
    """Validador central de dados utilizados pelo NETSHADOW."""

    MAX_TEXT_LENGTH = 1024
    MAX_NAME_LENGTH = 128
    MAX_PATH_LENGTH = 4096

    MAX_PORT = 65535
    MIN_PORT = 1

    MAC_PATTERN = re.compile(
        r"^(?:[0-9A-Fa-f]{2}[:-]){5}"
        r"[0-9A-Fa-f]{2}$"
    )

    NAME_PATTERN = re.compile(
        r"^[A-Za-z0-9][A-Za-z0-9_. -]{0,127}$"
    )

    @classmethod
    def validate_ip(
        cls,
        value: str,
        version: Optional[int] = None,
    ) -> str:

        if not isinstance(value, str):
            raise InputValidationError("O IP tem de ser texto.")

        value = value.strip()

        if not value or len(value) > 45:
            raise InputValidationError("Endereço IP inválido.")

        if version not in (None, 4, 6):
            raise InputValidationError("Versão IP inválida.")

        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise InputValidationError(
                "Endereço IP inválido."
            ) from exc

        if version is not None and address.version != version:
            raise InputValidationError(
                f"É esperado um endereço IPv{version}."
            )

        return str(address)

    @classmethod
    def validate_network(
        cls,
        value: str,
        strict: bool = False,
    ) -> str:

        if not isinstance(value, str):
            raise InputValidationError("A rede tem de ser texto.")

        value = value.strip()

        if not value or len(value) > 128:
            raise InputValidationError("Rede ou sub-rede inválida.")

        if not isinstance(strict, bool):
            raise InputValidationError("Parâmetro strict inválido.")

        try:
            network = ipaddress.ip_network(
                value,
                strict=strict,
            )
        except ValueError as exc:
            raise InputValidationError(
                "Rede ou sub-rede inválida."
            ) from exc

        return str(network)

    @classmethod
    def validate_port(cls, value: int) -> int:

        if isinstance(value, bool) or not isinstance(value, int):
            raise InputValidationError(
                "A porta tem de ser um inteiro."
            )

        if not cls.MIN_PORT <= value <= cls.MAX_PORT:
            raise InputValidationError(
                "A porta deve estar entre 1 e 65535."
            )

        return value

    @classmethod
    def validate_port_range(
        cls,
        start: int,
        end: int,
    ) -> tuple[int, int]:

        start = cls.validate_port(start)
        end = cls.validate_port(end)

        if start > end:
            raise InputValidationError(
                "O início do intervalo não pode exceder o fim."
            )

        if end - start > 1023:
            raise InputValidationError(
                "O intervalo é demasiado amplo."
            )

        return start, end

    @classmethod
    def validate_mac(cls, value: str) -> str:

        if not isinstance(value, str):
            raise InputValidationError("MAC inválido.")

        normalized = value.strip().replace("-", ":")

        if not cls.MAC_PATTERN.fullmatch(normalized):
            raise InputValidationError(
                "Formato de endereço MAC inválido."
            )

        return normalized.upper()

    @classmethod
    def validate_name(cls, value: str) -> str:

        if not isinstance(value, str):
            raise InputValidationError("Nome inválido.")

        value = value.strip()

        if (
            not value
            or len(value) > cls.MAX_NAME_LENGTH
            or not cls.NAME_PATTERN.fullmatch(value)
        ):
            raise InputValidationError(
                "Nome contém caracteres não permitidos."
            )

        return value

    @classmethod
    def validate_text(
        cls,
        value: str,
        max_length: int = MAX_TEXT_LENGTH,
        allow_empty: bool = False,
    ) -> str:

        if not isinstance(value, str):
            raise InputValidationError("O valor tem de ser texto.")

        if not isinstance(allow_empty, bool):
            raise InputValidationError(
                "Parâmetro allow_empty inválido."
            )

        if (
            isinstance(max_length, bool)
            or not isinstance(max_length, int)
            or not 1 <= max_length <= cls.MAX_TEXT_LENGTH
        ):
            raise InputValidationError("Limite de texto inválido.")

        value = value.strip()

        if not allow_empty and not value:
            raise InputValidationError(
                "O texto não pode estar vazio."
            )

        if len(value) > max_length:
            raise InputValidationError("Texto demasiado longo.")

        if any(
            ord(char) < 32 and char not in "\t\n"
            for char in value
        ):
            raise InputValidationError(
                "O texto contém caracteres de controlo."
            )

        return value

    @classmethod
    def validate_path(
        cls,
        value: Union[str, Path],
        base_directory: Optional[Union[str, Path]] = None,
    ) -> Path:
        """
        Valida um caminho sem abrir, criar ou modificar ficheiros.

        Quando existe base_directory, o caminho resolvido tem de
        permanecer dentro desse diretório.
        """

        if not isinstance(value, (str, Path)):
            raise InputValidationError("Caminho inválido.")

        raw_value = str(value)

        if (
            not raw_value.strip()
            or len(raw_value) > cls.MAX_PATH_LENGTH
            or "\x00" in raw_value
        ):
            raise InputValidationError("Caminho inválido.")

        path = Path(raw_value)

        if base_directory is None:
            return path

        if not isinstance(base_directory, (str, Path)):
            raise InputValidationError(
                "Diretório de referência inválido."
            )

        try:
            base = Path(base_directory).resolve()
            candidate = (
                path if path.is_absolute() else base / path
            ).resolve()

            if not candidate.is_relative_to(base):
                raise InputValidationError(
                    "O caminho ultrapassa o diretório permitido."
                )

            return candidate

        except InputValidationError:
            raise
        except (OSError, RuntimeError, ValueError) as exc:
            raise InputValidationError(
                "Não foi possível validar o caminho."
            ) from exc

    @classmethod
    def validate_integer(
        cls,
        value: int,
        minimum: int,
        maximum: int,
    ) -> int:

        if isinstance(value, bool) or not isinstance(value, int):
            raise InputValidationError(
                "É esperado um número inteiro."
            )

        if (
            isinstance(minimum, bool)
            or isinstance(maximum, bool)
            or not isinstance(minimum, int)
            or not isinstance(maximum, int)
            or minimum > maximum
        ):
            raise InputValidationError("Limites inválidos.")

        if not minimum <= value <= maximum:
            raise InputValidationError(
                "Número fora dos limites permitidos."
            )

        return value

    @classmethod
    def validate_timeout(
        cls,
        value: Union[int, float],
    ) -> float:

        if isinstance(value, bool) or not isinstance(
            value, (int, float)
        ):
            raise InputValidationError("Timeout inválido.")

        if not math.isfinite(value):
            raise InputValidationError("Timeout inválido.")

        if not 0.1 <= value <= 30:
            raise InputValidationError(
                "Timeout deve estar entre 0.1 e 30 segundos."
            )

        return float(value)

    @classmethod
    def validate_boolean(cls, value: bool) -> bool:

        if not isinstance(value, bool):
            raise InputValidationError(
                "É esperado um valor booleano."
            )

        return value


__all__ = [
    "InputValidationError",
    "InputValidator",
]
