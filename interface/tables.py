
"""Terminal table utilities for NETSHADOW."""

from __future__ import annotations

from typing import Any, Iterable, Optional, Sequence


class TableError(RuntimeError):
    """Raised when table rendering fails."""


class Table:
    """A simple table renderer for terminal output."""

    def __init__(
        self,
        headers: Sequence[str],
        rows: Optional[Iterable[Sequence[Any]]] = None,
        title: Optional[str] = None,
        max_width: int = 40,
    ) -> None:
        if not headers:
            raise ValueError("Table must have at least one header.")

        if max_width < 8:
            raise ValueError("Maximum column width must be at least 8.")

        self.headers = [str(header) for header in headers]
        self.rows: list[list[str]] = []
        self.title = title
        self.max_width = max_width

        for row in rows or []:
            self.add_row(row)

    def add_row(self, row: Sequence[Any]) -> None:
        """Add a row after validating its number of columns."""
        if len(row) != len(self.headers):
            raise TableError(
                f"Expected {len(self.headers)} columns, got {len(row)}."
            )

        self.rows.append([
            "" if value is None else str(value)
            for value in row
        ])

    def add_rows(self, rows: Iterable[Sequence[Any]]) -> None:
        """Add multiple rows."""
        for row in rows:
            self.add_row(row)

    def clear(self) -> None:
        """Remove all table rows."""
        self.rows.clear()

    def _truncate(self, value: str, width: int) -> str:
        """Truncate long cell content."""
        if len(value) <= width:
            return value

        if width <= 3:
            return value[:width]

        return value[:width - 3] + "..."

    def _column_widths(self) -> list[int]:
        """Calculate column widths from headers and rows."""
        widths = []

        for index, header in enumerate(self.headers):
            content_width = max(
                [len(header)]
                + [len(row[index]) for row in self.rows]
            )

            widths.append(min(content_width, self.max_width))

        return widths

    @staticmethod
    def _separator(widths: Sequence[int]) -> str:
        return "+-" + "-+-".join(
            "-" * width for width in widths
        ) + "-+"

    def render(self) -> str:
        """Return the complete formatted table."""
        widths = self._column_widths()
        separator = self._separator(widths)

        lines = []

        if self.title:
            lines.append(str(self.title))
            lines.append(separator)

        lines.append(separator)

        header = "| " + " | ".join(
            self._truncate(value, widths[index]).ljust(widths[index])
            for index, value in enumerate(self.headers)
        ) + " |"

        lines.append(header)
        lines.append(separator)

        for row in self.rows:
            line = "| " + " | ".join(
                self._truncate(value, widths[index]).ljust(widths[index])
                for index, value in enumerate(row)
            ) + " |"

            lines.append(line)

        lines.append(separator)

        return "\n".join(lines)

    def display(self) -> None:
        """Print the formatted table."""
        print(self.render())

    def get_row_count(self) -> int:
        return len(self.rows)

    def get_column_count(self) -> int:
        return len(self.headers)


class TableBuilder:
    """Build tables from dictionaries."""

    @staticmethod
    def from_dicts(
        records: Iterable[dict[str, Any]],
        columns: Optional[Sequence[str]] = None,
        title: Optional[str] = None,
    ) -> Table:
        records = list(records)

        if columns is None:
            columns = list(records[0].keys()) if records else []

        if not columns:
            raise TableError(
                "Cannot build a table without columns."
            )

        table = Table(
            headers=columns,
            title=title,
        )

        for record in records:
            table.add_row([
                record.get(column, "")
                for column in columns
            ])

        return table


ConsoleTable = Table
TableManager = Table
NetShadowTables = Table
NetShadowTableBuilder = TableBuilder

__all__ = [
    "TableError",
    "Table",
    "TableBuilder",
    "ConsoleTable",
    "TableManager",
    "NetShadowTables",
    "NetShadowTableBuilder",
]
