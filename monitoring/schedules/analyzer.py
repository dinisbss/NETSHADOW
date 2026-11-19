
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Mapping
from uuid import uuid4


class ScheduleError(Exception):
    """Erro do módulo de agendamento."""


class ScheduleStatus(str, Enum):
    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETED = "completed"
    CANCELLED = "cancelled"


@dataclass
class ScheduleExecution:
    execution_id: str
    scheduled_at: str
    recorded_at: str
    status: str
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "execution_id": self.execution_id,
            "scheduled_at": self.scheduled_at,
            "recorded_at": self.recorded_at,
            "status": self.status,
            "details": dict(self.details),
        }


@dataclass
class ScheduledTask:
    schedule_id: str
    name: str
    task_type: str
    interval_seconds: int
    next_run: str
    status: ScheduleStatus
    created_at: str
    updated_at: str
    max_executions: int | None = None
    execution_count: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)
    history: list[ScheduleExecution] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schedule_id": self.schedule_id,
            "name": self.name,
            "task_type": self.task_type,
            "interval_seconds": self.interval_seconds,
            "next_run": self.next_run,
            "status": self.status.value,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "max_executions": self.max_executions,
            "execution_count": self.execution_count,
            "metadata": dict(self.metadata),
            "history": [
                item.to_dict() for item in self.history
            ],
        }


class ScheduleAnalyzer:
    """Gere metadados de agendamento sem executar tarefas."""

    def __init__(self) -> None:
        self._tasks: dict[str, ScheduledTask] = {}

    @staticmethod
    def _parse_datetime(value: str) -> datetime:
        if not isinstance(value, str) or not value.strip():
            raise ScheduleError("Invalid datetime")

        try:
            parsed = datetime.fromisoformat(
                value.replace("Z", "+00:00")
            )
        except ValueError as exc:
            raise ScheduleError("Invalid datetime") from exc

        if parsed.tzinfo is None:
            raise ScheduleError(
                "Datetime must include timezone"
            )

        return parsed.astimezone(timezone.utc)

    @staticmethod
    def _status(value: ScheduleStatus | str) -> ScheduleStatus:
        try:
            return ScheduleStatus(value)
        except ValueError as exc:
            raise ScheduleError("Invalid schedule status") from exc

    def create(
        self,
        name: str,
        task_type: str,
        interval_seconds: int,
        start_at: str | None = None,
        max_executions: int | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> ScheduledTask:

        if not isinstance(name, str) or not name.strip():
            raise ScheduleError("Task name is required")

        if not isinstance(task_type, str) or not task_type.strip():
            raise ScheduleError("Task type is required")

        if (
            isinstance(interval_seconds, bool)
            or not isinstance(interval_seconds, int)
            or interval_seconds <= 0
        ):
            raise ScheduleError(
                "interval_seconds must be a positive integer"
            )

        if max_executions is not None and (
            isinstance(max_executions, bool)
            or not isinstance(max_executions, int)
            or max_executions <= 0
        ):
            raise ScheduleError(
                "max_executions must be a positive integer"
            )

        now = datetime.now(timezone.utc)

        next_run = (
            self._parse_datetime(start_at)
            if start_at is not None
            else now + timedelta(seconds=interval_seconds)
        )

        task = ScheduledTask(
            schedule_id=str(uuid4()),
            name=name.strip(),
            task_type=task_type.strip().lower(),
            interval_seconds=interval_seconds,
            next_run=next_run.isoformat(),
            status=ScheduleStatus.ACTIVE,
            created_at=now.isoformat(),
            updated_at=now.isoformat(),
            max_executions=max_executions,
            metadata=dict(metadata or {}),
        )

        self._tasks[task.schedule_id] = task
        return task

    def get(self, schedule_id: str) -> ScheduledTask | None:
        return self._tasks.get(schedule_id)

    def get_all(
        self,
        status: ScheduleStatus | str | None = None,
    ) -> list[ScheduledTask]:

        tasks = list(self._tasks.values())

        if status is not None:
            selected = self._status(status)
            tasks = [
                task for task in tasks
                if task.status == selected
            ]

        return tasks

    def pause(self, schedule_id: str) -> ScheduledTask:
        return self._change_status(
            schedule_id,
            ScheduleStatus.PAUSED,
        )

    def resume(self, schedule_id: str) -> ScheduledTask:
        task = self.get(schedule_id)

        if task is None:
            raise ScheduleError("Schedule not found")

        if task.status != ScheduleStatus.PAUSED:
            raise ScheduleError("Only paused tasks can resume")

        return self._change_status(
            schedule_id,
            ScheduleStatus.ACTIVE,
        )

    def cancel(self, schedule_id: str) -> ScheduledTask:
        return self._change_status(
            schedule_id,
            ScheduleStatus.CANCELLED,
        )

    def _change_status(
        self,
        schedule_id: str,
        status: ScheduleStatus,
    ) -> ScheduledTask:

        task = self.get(schedule_id)

        if task is None:
            raise ScheduleError("Schedule not found")

        if task.status in (
            ScheduleStatus.COMPLETED,
            ScheduleStatus.CANCELLED,
        ):
            raise ScheduleError("Schedule is already closed")

        task.status = status
        task.updated_at = datetime.now(timezone.utc).isoformat()

        return task

    def record_execution(
        self,
        schedule_id: str,
        execution_status: str = "completed",
        details: Mapping[str, Any] | None = None,
    ) -> ScheduleExecution:

        task = self.get(schedule_id)

        if task is None:
            raise ScheduleError("Schedule not found")

        if task.status != ScheduleStatus.ACTIVE:
            raise ScheduleError("Schedule is not active")

        now = datetime.now(timezone.utc)
        scheduled_at = self._parse_datetime(task.next_run)

        execution = ScheduleExecution(
            execution_id=str(uuid4()),
            scheduled_at=scheduled_at.isoformat(),
            recorded_at=now.isoformat(),
            status=str(execution_status).strip().lower(),
            details=dict(details or {}),
        )

        task.history.append(execution)
        task.execution_count += 1

        if (
            task.max_executions is not None
            and task.execution_count >= task.max_executions
        ):
            task.status = ScheduleStatus.COMPLETED
        else:
            next_run = scheduled_at + timedelta(
                seconds=task.interval_seconds
            )

            while next_run <= now:
                next_run += timedelta(
                    seconds=task.interval_seconds
                )

            task.next_run = next_run.isoformat()

        task.updated_at = now.isoformat()
        return execution

    def delete(self, schedule_id: str) -> bool:
        return self._tasks.pop(schedule_id, None) is not None

    def get_summary(self) -> dict[str, int]:
        tasks = list(self._tasks.values())

        return {
            "total": len(tasks),
            "active": sum(
                task.status == ScheduleStatus.ACTIVE
                for task in tasks
            ),
            "paused": sum(
                task.status == ScheduleStatus.PAUSED
                for task in tasks
            ),
            "completed": sum(
                task.status == ScheduleStatus.COMPLETED
                for task in tasks
            ),
            "cancelled": sum(
                task.status == ScheduleStatus.CANCELLED
                for task in tasks
            ),
            "total_executions": sum(
                task.execution_count for task in tasks
            ),
        }


__all__ = [
    "ScheduleError",
    "ScheduleStatus",
    "ScheduleExecution",
    "ScheduledTask",
    "ScheduleAnalyzer",
]
