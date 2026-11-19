
"""Interactive terminal menus for NETSHADOW."""

from __future__ import annotations

import os
import shutil
from typing import Callable, Optional


class MenuError(RuntimeError):
    """Raised when a menu operation fails."""


class Colors:
    """ANSI terminal colors."""

    RESET = "\033[0m"
    BOLD = "\033[1m"
    CYAN = "\033[96m"
    BLUE = "\033[94m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    WHITE = "\033[97m"
    GRAY = "\033[90m"


class MenuOption:
    """Represents a selectable menu option."""

    def __init__(
        self,
        key: str,
        label: str,
        description: str = "",
        action: Optional[Callable[[], object]] = None,
    ) -> None:
        key = str(key).strip()
        label = str(label).strip()

        if not key or not label:
            raise ValueError("Menu key and label cannot be empty.")

        self.key = key
        self.label = label
        self.description = str(description).strip()
        self.action = action

    def execute(self) -> object:
        if self.action is None:
            return None
        return self.action()


class Menu:
    """Reusable interactive terminal menu."""

    def __init__(
        self,
        title: str,
        options: Optional[list[MenuOption]] = None,
        prompt: str = "Select an option: ",
    ) -> None:
        self.title = str(title).strip()
        self.prompt = prompt
        self.options: dict[str, MenuOption] = {}

        if not self.title:
            raise ValueError("Menu title cannot be empty.")

        for option in options or []:
            self.add_option(option)

    def add_option(self, option: MenuOption) -> None:
        if not isinstance(option, MenuOption):
            raise TypeError("option must be a MenuOption.")

        if option.key in self.options:
            raise MenuError(f"Duplicate menu option: {option.key}")

        self.options[option.key] = option

    def remove_option(self, key: str) -> bool:
        return self.options.pop(str(key), None) is not None

    @staticmethod
    def clear_screen() -> None:
        os.system("cls" if os.name == "nt" else "clear")

    @staticmethod
    def terminal_width() -> int:
        return max(60, min(shutil.get_terminal_size((80, 24)).columns, 100))

    def display(self) -> None:
        width = self.terminal_width()

        print()
        print(Colors.CYAN + Colors.BOLD + "╔" + "═" * (width - 2) + "╗" + Colors.RESET)
        print(
            Colors.CYAN + Colors.BOLD
            + "║" + "NETSHADOW".center(width - 2) + "║"
            + Colors.RESET
        )
        print(
            Colors.CYAN + "║"
            + "NETWORK INTELLIGENCE & SECURITY AUDITING".center(width - 2)
            + "║" + Colors.RESET
        )
        print(Colors.CYAN + "╠" + "═" * (width - 2) + "╣" + Colors.RESET)

        print(
            Colors.BLUE + Colors.BOLD
            + "║" + self.title.center(width - 2) + "║"
            + Colors.RESET
        )

        print(Colors.CYAN + "╠" + "═" * (width - 2) + "╣" + Colors.RESET)

        for option in self.options.values():
            entry = f"  [{option.key}] {option.label}"

            if option.description:
                entry += f"  {Colors.GRAY}- {option.description}{Colors.RESET}"

            available = width - 4
            if len(entry) > available:
                entry = entry[:available - 3] + "..."

            print(
                Colors.CYAN + "║" + Colors.RESET
                + entry.ljust(width - 2)
                + Colors.CYAN + "║" + Colors.RESET
            )

        print(Colors.CYAN + "╚" + "═" * (width - 2) + "╝" + Colors.RESET)
        print()

    def select(self, key: str) -> object:
        option = self.options.get(str(key).strip())

        if option is None:
            raise MenuError(f"Invalid menu option: {key}")

        return option.execute()

    def run_once(self) -> bool:
        self.display()

        try:
            choice = input(
                Colors.GREEN + Colors.BOLD + self.prompt + Colors.RESET
            ).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return False

        if choice.lower() in {"0", "q", "quit", "exit"}:
            return False

        try:
            result = self.select(choice)

            if result is not None:
                print(f"\n{Colors.GREEN}{result}{Colors.RESET}")

        except MenuError as exc:
            print(f"\n{Colors.RED}[ERROR] {exc}{Colors.RESET}")
        except Exception as exc:
            print(f"\n{Colors.RED}[ERROR] {exc}{Colors.RESET}")

        try:
            input(f"\n{Colors.GRAY}Press ENTER to continue...{Colors.RESET}")
        except (EOFError, KeyboardInterrupt):
            return False

        return True

    def run(self) -> None:
        while self.run_once():
            pass


class SubMenu(Menu):
    """Menu with an explicit return option."""

    def __init__(
        self,
        title: str,
        options: Optional[list[MenuOption]] = None,
    ) -> None:
        submenu_options = list(options or [])
        submenu_options.append(
            MenuOption("0", "Back", "Return to the previous menu.")
        )
        super().__init__(title, submenu_options)

    def run(self) -> None:
        while True:
            self.display()

            try:
                choice = input(
                    Colors.GREEN + Colors.BOLD + "Select an option: "
                    + Colors.RESET
                ).strip()
            except (EOFError, KeyboardInterrupt):
                print()
                return

            if choice in {"0", "q", "quit", "exit"}:
                return

            try:
                self.select(choice)
            except MenuError as exc:
                print(f"{Colors.RED}[ERROR] {exc}{Colors.RESET}")
            except Exception as exc:
                print(f"{Colors.RED}[ERROR] {exc}{Colors.RESET}")

            try:
                input("\nPress ENTER to continue...")
            except (EOFError, KeyboardInterrupt):
                return


class MainMenu(Menu):
    """NETSHADOW main navigation menu."""

    def __init__(self) -> None:
        super().__init__(
            title="MAIN MENU",
            options=[
                MenuOption("1", "Network Discovery", "Network information and discovery."),
                MenuOption("2", "Device Intelligence", "Device inventory and information."),
                MenuOption("3", "Security Center", "Security checks and recommendations."),
                MenuOption("4", "Live Monitoring", "Network metrics and availability."),
                MenuOption("5", "AI Intelligence", "Analysis and correlation."),
                MenuOption("6", "Reports & Export", "View and export reports."),
                MenuOption("7", "Settings", "Application configuration."),
                MenuOption("0", "Exit", "Close NETSHADOW."),
            ],
        )


MenuManager = Menu
InteractiveMenu = Menu

__all__ = [
    "MenuError",
    "Colors",
    "MenuOption",
    "Menu",
    "SubMenu",
    "MainMenu",
    "MenuManager",
    "InteractiveMenu",
]
