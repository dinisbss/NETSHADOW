
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4


class ScanSchedulerError(Exception):
    """Erro do módulo Scan Scheduler."""


class ScheduleStatus(str, Enum):
    SCHEDULED = "scheduled"
    PAUSED = "paused"
    CANCELLED = "cancelled"
    COMPLETED = "completed"


@dataclass
class ScheduledTask:
    task_id: str
    name: str
    target: str
    scheduled_at: str
    status: ScheduleStatus
    created_at: str
    authorized: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "name": self.name,
            "target": self.target,
            "scheduled_at": self.scheduled_at,
            "status": self.status.value,
            "created_at": self.created_at,
            "authorized": self.authorized,
        }


class ScanScheduler:
    """Gere metadados de tarefas agendadas, sem executar scans."""

    def __init__(self) -> None:
        self._tasks: dict[str, ScheduledTask] = {}

    @staticmethod
    def _parse_datetime(value: str) -> datetime:
        if not isinstance(value, str) or not value.strip():
            raise ScanSchedulerError(
                "scheduled_at must be a valid ISO datetime"
            )

        try:
            parsed = datetime.fromisoformat(
                value.replace("Z", "+00:00")
            )
        except ValueError as exc:
            raise ScanSchedulerError(
                "Invalid scheduled_at datetime"
            ) from exc

        if parsed.tzinfo is None:
            raise ScanSchedulerError(
                "scheduled_at must include a timezone"
            )

        return parsed.astimezone(timezone.utc)

    def create(
        self,
        name: str,
        target: str,
        scheduled_at: str,
        authorized: bool = False,
    ) -> ScheduledTask:

        if not isinstance(name, str) or not name.strip():
            raise ScanSchedulerError(
                "Task name is required"
            )

        if not isinstance(target, str) or not target.strip():
            raise ScanSchedulerError(
                "Task target is required"
            )

        if not isinstance(authorized, bool):
            raise ScanSchedulerError(
                "authorized must be boolean"
            )

        scheduled = self._parse_datetime(scheduled_at)

        for task in self._tasks.values():
            if (
                task.target == target.strip()
                and task.scheduled_at == scheduled.isoformat()
                and task.status != ScheduleStatus.CANCELLED
            ):
                raise ScanSchedulerError(
                    "An equivalent task already exists"
                )

        now = datetime.now(timezone.utc)

        task = ScheduledTask(
            task_id=str(uuid4()),
            name=name.strip(),
            target=target.strip(),
            scheduled_at=scheduled.isoformat(),
            status=ScheduleStatus.SCHEDULED,
            created_at=now.isoformat(),
            authorized=authorized,
        )

        self._tasks[task.task_id] = task
        return task

    def get(self, task_id: str) -> ScheduledTask | None:
        return self._tasks.get(task_id)

    def get_all(self) -> list[ScheduledTask]:
        return list(self._tasks.values())

    def get_pending(self) -> list[ScheduledTask]:
        now = datetime.now(timezone.utc)

        return [
            task
            for task in self._tasks.values()
            if (
                task.status == ScheduleStatus.SCHEDULED
                and self._parse_datetime(
                    task.scheduled_at
                ) <= now
            )
        ]

    def pause(self, task_id: str) -> ScheduledTask:
        task = self._require_task(task_id)

        if task.status != ScheduleStatus.SCHEDULED:
            raise ScanSchedulerError(
                "Only scheduled tasks can be paused"
            )

        task.status = ScheduleStatus.PAUSED
        return task

    def resume(self, task_id: str) -> ScheduledTask:
        task = self._require_task(task_id)

        if task.status != ScheduleStatus.PAUSED:
            raise ScanSchedulerError(
                "Only paused tasks can be resumed"
            )

        task.status = ScheduleStatus.SCHEDULED
        return task

    def cancel(self, task_id: str) -> ScheduledTask:
        task = self._require_task(task_id)

        if task.status in {
            ScheduleStatus.CANCELLED,
            ScheduleStatus.COMPLETED,
        }:
            raise ScanSchedulerError(
                "Task cannot be cancelled"
            )

        task.status = ScheduleStatus.CANCELLED
        return task

    def mark_completed(self, task_id: str) -> ScheduledTask:
        task = self._require_task(task_id)

        if task.status != ScheduleStatus.SCHEDULED:
            raise ScanSchedulerError(
                "Only scheduled tasks can be completed"
            )

        task.status = ScheduleStatus.COMPLETED
        return task

    def _require_task(self, task_id: str) -> ScheduledTask:
        task = self.get(task_id)

        if task is None:
            raise ScanSchedulerError(
                f"Task not found: {task_id}"
            )

        return task

    def get_status(self) -> dict[str, int]:
        return {
            status.value: sum(
                task.status == status
                for task in self._tasks.values()
            )
            for status in ScheduleStatus
        }


__all__ = [
    "ScanSchedulerError",
    "ScheduleStatus",
    "ScheduledTask",
    "ScanScheduler",
]
