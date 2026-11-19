
"""Report management commands for NETSHADOW."""

from __future__ import annotations

from typing import Any, Optional

from database.database import DatabaseManager
from database.repositories.report_repository import ReportRepository


class ReportCommandError(RuntimeError):
    """Raised when a report command fails."""


class ReportCommand:
    """Provides read-only access to stored report records."""

    def __init__(
        self,
        repository: Optional[ReportRepository] = None,
        database: Optional[DatabaseManager] = None,
    ) -> None:
        self.database = database
        self._owns_database = False

        if repository is not None:
            self.repository = repository
        else:
            if self.database is None:
                self.database = DatabaseManager()
                self._owns_database = True

            self.repository = ReportRepository(self.database)

    @staticmethod
    def _serialize(report: Any) -> dict[str, Any]:
        if isinstance(report, dict):
            return report.copy()

        if hasattr(report, "to_dict"):
            result = report.to_dict()
            if isinstance(result, dict):
                return result

        if hasattr(report, "__dict__"):
            return {
                key: value
                for key, value in vars(report).items()
                if not key.startswith("_")
            }

        raise ReportCommandError(
            "Unsupported report record format."
        )

    def list_reports(self) -> list[dict[str, Any]]:
        """Return all registered reports."""
        try:
            reports = self.repository.get_all()
            return [
                self._serialize(report)
                for report in reports or []
            ]
        except Exception as exc:
            raise ReportCommandError(
                f"Unable to retrieve reports: {exc}"
            ) from exc

    def get_report(self, report_id: int) -> dict[str, Any]:
        """Retrieve a report by database ID."""
        if isinstance(report_id, bool) or not isinstance(report_id, int):
            raise ValueError("Report ID must be an integer.")

        if report_id <= 0:
            raise ValueError("Report ID must be positive.")

        try:
            report = self.repository.get_by_id(report_id)

            if report is None:
                raise ReportCommandError(
                    f"Report {report_id} was not found."
                )

            return self._serialize(report)

        except ReportCommandError:
            raise
        except Exception as exc:
            raise ReportCommandError(
                f"Unable to retrieve report: {exc}"
            ) from exc

    def count_reports(self) -> int:
        """Return the number of registered reports."""
        try:
            return int(self.repository.count())
        except Exception as exc:
            raise ReportCommandError(
                f"Unable to count reports: {exc}"
            ) from exc

    def display_reports(self) -> None:
        """Display all registered reports."""
        reports = self.list_reports()

        print("\nNETSHADOW - REPORTS")
        print("=" * 65)

        if not reports:
            print("No reports registered.")
        else:
            for index, report in enumerate(reports, start=1):
                print(f"\nReport #{index}")

                for key, value in report.items():
                    print(f"  {key}: {value}")

                print("-" * 65)

        print(f"Total reports: {len(reports)}")
        print("=" * 65)

    def display_report(self, report_id: int) -> None:
        """Display details of one report."""
        report = self.get_report(report_id)

        print("\nNETSHADOW - REPORT DETAILS")
        print("=" * 50)

        for key, value in report.items():
            print(f"{key}: {value}")

        print("=" * 50)

    def display_summary(self) -> None:
        """Display report inventory summary."""
        print("\nREPORT INVENTORY")
        print("-" * 40)
        print(f"Registered reports: {self.count_reports()}")
        print("-" * 40)

    def close(self) -> None:
        """Close the database if this command owns it."""
        if self._owns_database and self.database is not None:
            self.database.close()
            self._owns_database = False



ReportCommands = ReportCommand
ReportsCommands = ReportCommand
ReportsManagerCommand = ReportCommand

__all__ = [
    "ReportCommandError",
    "ReportCommand",
    "ReportCommands",
    "ReportsCommands",
    "ReportsManagerCommand",
]
