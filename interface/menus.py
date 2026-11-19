
"""Interactive menus for the NETSHADOW command-line interface."""

from __future__ import annotations

from typing import Callable, Optional


class MenuError(RuntimeError):
    """Raised when a menu operation fails."""


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

        if not key:
            raise ValueError("Menu option key cannot be empty.")

        if not label:
            raise ValueError("Menu option label cannot be empty.")

        self.key = key
        self.label = label
        self.description = str(description).strip()
        self.action = action

    def execute(self) -> object:
        """Execute the option action when available."""
        if self.action is None:
            return None

        return self.action()


class Menu:
    """A reusable interactive menu."""

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
        """Register a menu option."""
        if not isinstance(option, MenuOption):
            raise TypeError("option must be a MenuOption instance.")

        if option.key in self.options:
            raise MenuError(f"Duplicate menu option: {option.key}")

        self.options[option.key] = option

    def remove_option(self, key: str) -> bool:
        """Remove an option by key."""
        return self.options.pop(str(key), None) is not None

    def display(self) -> None:
        """Print the menu."""
        print()
        print("=" * 50)
        print(self.title.center(50))
        print("=" * 50)

        for option in self.options.values():
            description = (
                f" - {option.description}"
                if option.description
                else ""
            )
            print(f" [{option.key}] {option.label}{description}")

        print("=" * 50)

    def select(self, key: str) -> object:
        """Execute the selected option."""
        option = self.options.get(str(key).strip())

        if option is None:
            raise MenuError(f"Invalid menu option: {key}")

        return option.execute()

    def run_once(self) -> bool:
        """Display the menu and process one selection."""
        self.display()

        try:
            choice = input(self.prompt).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return False

        if choice.lower() in {"0", "q", "quit", "exit"}:
            return False

        try:
            self.select(choice)
        except MenuError as exc:
            print(f"[ERROR] {exc}")
        except Exception as exc:
            print(f"[ERROR] Menu action failed: {exc}")

        return True

    def run(self) -> None:
        """Run the menu until the user exits."""
        while self.run_once():
            pass


class MainMenu(Menu):
    """NETSHADOW main navigation menu."""

    def __init__(self) -> None:
        super().__init__(
            title="NETSHADOW - MAIN MENU",
            options=[
                MenuOption(
                    "1",
                    "Network information",
                    "View local network information.",
                ),
                MenuOption(
                    "2",
                    "Device management",
                    "View device management options.",
                ),
                MenuOption(
                    "3",
                    "Security audit",
                    "Review authorized security audit options.",
                ),
                MenuOption(
                    "4",
                    "Monitoring",
                    "View monitoring options.",
                ),
                MenuOption(
                    "5",
                    "Reports",
                    "View available reports.",
                ),
                MenuOption(
                    "6",
                    "Settings",
                    "View application settings.",
                ),
                MenuOption(
                    "0",
                    "Exit",
                    "Close the menu.",
                ),
            ],
        )


MenuManager = Menu
InteractiveMenu = Menu

__all__ = [
    "MenuError",
    "MenuOption",
    "Menu",
    "MainMenu",
    "MenuManager",
    "InteractiveMenu",
]
