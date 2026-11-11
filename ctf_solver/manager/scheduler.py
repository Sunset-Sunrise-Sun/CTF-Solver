"""Pure FIFO scheduler for the two-Worker concurrency cap.

No database access happens here so the ordering and capacity rules can be
tested deterministically. The Manager remains authoritative for the durable
queue; this module decides how many queued Tasks may start now.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from ..core.errors import ConfigError
from ..core.types import TaskRecord


@dataclass(frozen=True)
class SchedulerConfig:
    capacity: int = 2

    def __post_init__(self) -> None:
        if not 1 <= self.capacity <= 2:
            raise ConfigError(
                f"scheduler capacity must be 1 or 2 (frozen product contract), got {self.capacity}"
            )


class Scheduler:
    def __init__(self, capacity: int = 2) -> None:
        self.config = SchedulerConfig(capacity=capacity)

    @property
    def capacity(self) -> int:
        return self.config.capacity

    def admit(self, active_count: int, queued_tasks: Sequence[TaskRecord]) -> list[TaskRecord]:
        """Return the FIFO-ordered Tasks that may start now."""

        if active_count < 0:
            raise ValueError("active_count must be >= 0")
        free = max(0, self.capacity - active_count)
        if free == 0 or not queued_tasks:
            return []
        return list(queued_tasks[:free])

    @staticmethod
    def fifo_key(task: TaskRecord) -> tuple[int, str]:
        return (int(task.created_at), task.task_id)

    def order(self, tasks: Sequence[TaskRecord]) -> list[TaskRecord]:
        return sorted(tasks, key=self.fifo_key)

    def queue_position(self, task_id: str, queued_tasks: Sequence[TaskRecord]) -> int | None:
        ordered = self.order(queued_tasks)
        for index, task in enumerate(ordered, start=1):
            if task.task_id == task_id:
                return index
        return None
