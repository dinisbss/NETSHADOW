
"""Visual banners for NETSHADOW terminal interface."""

from __future__ import annotations

from typing import Optional


class BannerError(RuntimeError):
    """Raised when banner rendering fails."""


class Banner:
    """NETSHADOW terminal banner renderer."""

    DEFAULT_WIDTH = 64

    LOGO = r"""
 _   _ _____ _____ ____  _   _    _    ____   ___  _       _
| \ | | ____|_   _/ ___|| | | |  / \  |  _ \ / _ \| |     | |
|  \| |  _|   | | \___ \| |_| | / _ \ | | | | | | | |     | |
| |\  | |___  | |  ___) |  _  |/ ___ \| |_| | |_| | |___  | |___
|_| \_|_____| |_| |____/|_| |_/_/   \_\____/ \___/|_____| |_____|
"""

    def __init__(
        self,
        version: str = "1.0.0",
        width: int = DEFAULT_WIDTH,
        color: bool = False,
    ) -> None:
        if width < 20:
            raise ValueError("Banner width must be at least 20.")

        self.version = str(version)
        self.width = width
        self.color = color

    def _paint(self, text: str, color_code: str) -> str:
        if not self.color:
            return text

        return f"\033[{color_code}m{text}\033[0m"

    def render_logo(self) -> str:
        """Return the ASCII logo."""
        return self.LOGO.strip("\n")

    def render_header(self) -> str:
        """Return the main banner."""
        separator = "=" * self.width

        lines = [
            self._paint(separator, "36"),
            self._paint(
                "NETSHADOW".center(self.width),
                "1;36",
            ),
            self._paint(
                "NETWORK INTELLIGENCE & SECURITY AUDITING".center(
                    self.width
                ),
                "36",
            ),
            self._paint(
                f"Version {self.version}".center(self.width),
                "37",
            ),
            self._paint(separator, "36"),
        ]

        return "\n".join(lines)

    def render(self) -> str:
        """Return the complete startup banner."""
        return (
            self.render_logo()
            + "\n\n"
            + self.render_header()
        )

    def display(self) -> None:
        """Print the complete banner."""
        print(self.render())

    def display_compact(self) -> None:
        """Print a compact banner."""
        print(
            self._paint(
                f"NETSHADOW v{self.version}",
                "1;36",
            )
        )

    def display_section(self, title: str) -> None:
        """Display a section heading."""
        text = str(title).strip()

        if not text:
            raise ValueError("Section title cannot be empty.")

        separator = "-" * self.width

        print()
        print(self._paint(separator, "36"))
        print(self._paint(text.center(self.width), "1;36"))
        print(self._paint(separator, "36"))


class BannerManager:
    """Manage NETSHADOW banner presentation."""

    def __init__(
        self,
        version: str = "1.0.0",
        color: bool = False,
    ) -> None:
        self.banner = Banner(
            version=version,
            color=color,
        )

    def show(self) -> None:
        self.banner.display()

    def show_compact(self) -> None:
        self.banner.display_compact()

    def show_section(self, title: str) -> None:
        self.banner.display_section(title)


NetShadowBanner = Banner
NetShadowBannerManager = BannerManager

__all__ = [
    "BannerError",
    "Banner",
    "BannerManager",
    "NetShadowBanner",
    "NetShadowBannerManager",
]
