
"""
NETSHADOW - Command Line Interface

Interface principal de linha de comandos.
"""

from __future__ import annotations

import argparse
import sys
from typing import Optional, Sequence

from core.application import NetShadowApplication


VERSION = "1.0.0"


class CLIError(RuntimeError):
    """Erro da interface de linha de comandos."""


class NetShadowCLI:
    """Gere a interface CLI do NETSHADOW."""

    def __init__(self) -> None:
        self.application = NetShadowApplication()
        self.parser = self._build_parser()

    def _build_parser(self) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(
            prog="netshadow",
            description=(
                "NETSHADOW - Network Intelligence "
                "& Security Auditing"
            ),
            epilog=(
                "Utilize apenas em redes e dispositivos "
                "para os quais tenha autorização."
            ),
        )

        parser.add_argument(
            "--version",
            action="version",
            version=f"NETSHADOW {VERSION}",
        )

        subparsers = parser.add_subparsers(
            dest="command",
            title="comandos",
            metavar="COMANDO",
        )

        subparsers.add_parser(
            "start",
            help="Inicializar a aplicação.",
        )

        subparsers.add_parser(
            "stop",
            help="Encerrar a aplicação.",
        )

        subparsers.add_parser(
            "status",
            help="Consultar o estado da aplicação.",
        )

        subparsers.add_parser(
            "info",
            help="Apresentar informações do NETSHADOW.",
        )

        return parser

    @staticmethod
    def _print_banner() -> None:
        banner = r"""
 _   _ _____ _____ ____  _   _    _    ____   ___  ____
| \ | | ____|_   _/ ___|| | | |  / \  |  _ \ / _ \|  _ \
|  \| |  _|   | | \___ \| |_| | / _ \ | | | | | | | |_) |
| |\  | |___  | |  ___) |  _  |/ ___ \| |_| | |_| |  __/
|_| \_|_____| |_| |____/|_| |_/_/   \_\____/ \___/|_|
"""
        print(banner)
        print("       Network Intelligence & Security Auditing")
        print(f"                    Version {VERSION}")
        print()

    def _start(self) -> int:
        try:
            result = self.application.start()

            print("[OK] NETSHADOW iniciado.")
            print(f"Estado: {result}")

            return 0

        except Exception as exc:
            print(
                f"[ERRO] Não foi possível iniciar: {exc}",
                file=sys.stderr,
            )
            return 1

    def _stop(self) -> int:
        try:
            result = self.application.stop()

            print("[OK] NETSHADOW encerrado.")
            print(f"Estado: {result}")

            return 0

        except Exception as exc:
            print(
                f"[ERRO] Não foi possível encerrar: {exc}",
                file=sys.stderr,
            )
            return 1

    def _status(self) -> int:
        try:
            status = self.application.get_status()

            print("\nNETSHADOW STATUS")
            print("-" * 35)

            if isinstance(status, dict):
                for key, value in status.items():
                    print(f"{key}: {value}")
            else:
                print(status)

            print("-" * 35)

            return 0

        except Exception as exc:
            print(
                f"[ERRO] Não foi possível consultar o estado: {exc}",
                file=sys.stderr,
            )
            return 1

    @staticmethod
    def _info() -> int:
        print("\nNETSHADOW")
        print("Network Intelligence & Security Auditing")
        print(f"Versão: {VERSION}")
        print("Linguagem principal: Python")
        print("Extensão opcional: Rust")
        print("Interface: Command Line Interface")
        print("Modo: Auditoria autorizada")
        print()

        return 0

    def run(
        self,
        arguments: Optional[Sequence[str]] = None,
    ) -> int:
        """Processa argumentos e executa o comando solicitado."""

        if arguments is None:
            arguments = sys.argv[1:]

        if not arguments:
            self._print_banner()
            self.parser.print_help()
            return 0

        args = self.parser.parse_args(arguments)

        if args.command == "start":
            return self._start()

        if args.command == "stop":
            return self._stop()

        if args.command == "status":
            return self._status()

        if args.command == "info":
            return self._info()

        self.parser.print_help()
        return 0


CLI = NetShadowCLI
CommandLineInterface = NetShadowCLI


def main(
    arguments: Optional[Sequence[str]] = None,
) -> int:
    """Ponto de entrada público da CLI."""

    cli = NetShadowCLI()
    return cli.run(arguments)


__all__ = [
    "VERSION",
    "CLIError",
    "NetShadowCLI",
    "CLI",
    "CommandLineInterface",
    "main",
]


if __name__ == "__main__":
    raise SystemExit(main())
