
import logging
import sys

from core.application import NetShadowApplication
from core.exceptions import NetShadowError
from interface.cli import NetShadowCLI


def configure_terminal() -> None:
    """Configure terminal output for UTF-8."""

    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8")
            except (OSError, ValueError):
                pass


def main() -> int:
    """NETSHADOW application entry point."""

    configure_terminal()

    application = NetShadowApplication()

    exit_code = 0

    try:
        application.initialize()

        print(
            f"\n[ SYSTEM ] {application.name} "
            f"v{application.version}"
        )

        cli = NetShadowCLI(application)
        cli.run()

    except NetShadowError as error:
        logging.getLogger("NETSHADOW").error(
            "Application error: %s",
            error,
        )
        print(f"\n[ERROR] {error}")
        exit_code = 1

    except KeyboardInterrupt:
        print("\n[SYSTEM] Shutdown requested.")
        exit_code = 130

    except EOFError:
        print("\n[SYSTEM] Input stream closed.")

    except Exception:
        logging.getLogger("NETSHADOW").exception(
            "Unexpected application error."
        )
        print("\n[ERROR] Unexpected application error.")
        exit_code = 1

    finally:
        application.shutdown()

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
