"""Shared deterministic helpers for the Round 2 security test suites.

Everything here is offline and synthetic: a fixed clock, a temporary SQLite
database created through the real schema, a recording EvidenceSink, and a
fake-input console channel. No test ever touches a real TTY, network or model.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ctf_solver.core.config import SolverConfig
from ctf_solver.core.types import Category, TaskRecord, TaskStatus
from ctf_solver.manager.approval_grant_service import ApprovalGrantService
from ctf_solver.manager.store import ManagerStore
from ctf_solver.security.confirmation import ConsoleConfirmationChannel

#: Synthetic, non-resolving destination used only as a canonicality fixture.
SYNTHETIC_HOST = "ctf-target.example"
SYNTHETIC_PROFILE = "synthetic-local"
SYNTHETIC_TASK_ID = "t-security01"


class FixedClock:
    """Deterministic millisecond clock."""

    def __init__(self, now_ms: int = 1_700_000_000_000) -> None:
        self._now = int(now_ms)

    def now_ms(self) -> int:
        return self._now

    def advance(self, milliseconds: int) -> int:
        self._now += int(milliseconds)
        return self._now

    def set(self, milliseconds: int) -> int:
        self._now = int(milliseconds)
        return self._now


class RecordingEvidence:
    """Minimal in-memory EvidenceSink; records events in append order."""

    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    def append_event(
        self,
        *,
        task_id: str,
        worker_id: str | None = None,
        session_id: str | None = None,
        source: str,
        source_id: str | None = None,
        source_seq: int | None = None,
        event_type: str,
        payload: dict[str, Any],
        timestamp: int | None = None,
        record_id: str | None = None,
    ) -> str:
        record_id = record_id or f"ev-{len(self.events) + 1:04d}"
        self.events.append(
            {
                "record_id": record_id,
                "task_id": task_id,
                "worker_id": worker_id,
                "session_id": session_id,
                "source": source,
                "source_id": source_id,
                "source_seq": source_seq,
                "event_type": event_type,
                "payload": dict(payload),
                "timestamp": timestamp or 0,
            }
        )
        return record_id

    def of_type(self, event_type: str) -> list[dict[str, Any]]:
        return [event for event in self.events if event["event_type"] == event_type]


@dataclass
class SecurityEnvironment:
    tmp_path: Path
    config: SolverConfig
    clock: FixedClock
    store: ManagerStore
    evidence: RecordingEvidence
    service: ApprovalGrantService
    task: TaskRecord
    extra_tasks: dict[str, TaskRecord] = field(default_factory=dict)


def _make_task(
    store: ManagerStore,
    clock: FixedClock,
    tmp_path: Path,
    task_id: str,
    *,
    scope_profile: str = SYNTHETIC_PROFILE,
) -> TaskRecord:
    record = TaskRecord(
        task_id=task_id,
        conversation_id="conv-security",
        title="Synthetic security fixture",
        category=Category.MISC,
        workspace_path=str(tmp_path / "tasks" / task_id / "work"),
        source="synthetic-local",
        scope_profile=scope_profile,
        status=TaskStatus.CREATED,
        created_at=clock.now_ms(),
        updated_at=clock.now_ms(),
    )
    return store.create_task(record)


def build_environment(
    tmp_path: Path,
    *,
    extra_task_ids: tuple[str, ...] = (),
    task_id: str = SYNTHETIC_TASK_ID,
) -> SecurityEnvironment:
    """Create a real schema-1.1 SQLite store + approval/grant service in tmp_path."""

    clock = FixedClock()
    config = SolverConfig(root=tmp_path)
    paths = config.ensure_layout()
    store = ManagerStore(str(paths.db_path), clock=clock)
    evidence = RecordingEvidence()
    task = _make_task(store, clock, tmp_path, task_id)
    extra = {
        other: _make_task(store, clock, tmp_path, other) for other in extra_task_ids
    }
    service = ApprovalGrantService(store, evidence, clock, config)
    return SecurityEnvironment(
        tmp_path=tmp_path,
        config=config,
        clock=clock,
        store=store,
        evidence=evidence,
        service=service,
        task=task,
        extra_tasks=extra,
    )


def scripted_channel(
    clock: FixedClock,
    answers: list[Any],
    *,
    os_user: str | None = "human-owner",
    is_tty: bool | None = True,
    max_attempts: int = 3,
    inputs_seen: list[str] | None = None,
    output: list[str] | None = None,
) -> ConsoleConfirmationChannel:
    """Console channel whose input is a scripted list (never a real TTY)."""

    remaining = list(answers)
    prompts: list[str] = inputs_seen if inputs_seen is not None else []
    lines: list[str] = output if output is not None else []

    def _input(prompt: str) -> str:
        prompts.append(str(prompt))
        if not remaining:
            raise EOFError("scripted confirmation input exhausted")
        answer = remaining.pop(0)
        if isinstance(answer, BaseException):
            raise answer
        return str(answer)

    return ConsoleConfirmationChannel(
        clock,
        input_fn=_input,
        output_fn=lines.append,
        is_tty=is_tty,
        os_user=os_user,
        max_attempts=max_attempts,
    )


def approving_channel(
    clock: FixedClock,
    approval_digest: str,
    *,
    os_user: str | None = "human-owner",
    is_tty: bool | None = True,
    output: list[str] | None = None,
) -> ConsoleConfirmationChannel:
    """Channel that types the exact ``CONFIRM <digest[:8]>`` phrase."""

    return scripted_channel(
        clock,
        [f"CONFIRM {approval_digest[:8]}"],
        os_user=os_user,
        is_tty=is_tty,
        output=output,
    )


def rejecting_channel(
    clock: FixedClock,
    *,
    os_user: str | None = "human-owner",
    is_tty: bool | None = True,
) -> ConsoleConfirmationChannel:
    """Channel that types the exact ``REJECT`` phrase."""

    return scripted_channel(clock, ["REJECT"], os_user=os_user, is_tty=is_tty)


def request_remote_approval(
    environment: SecurityEnvironment,
    *,
    task_id: str | None = None,
    host: str = SYNTHETIC_HOST,
    port: int = 8443,
    protocol: str = "https",
    method: str = "POST",
    path: str = "/api/challenge",
    profile: str = SYNTHETIC_PROFILE,
    ttl_s: int | None = 600,
):
    return environment.service.request_approval(
        task_id or environment.task.task_id,
        action_kind="remote_target",
        details={
            "target": {
                "host": host,
                "port": port,
                "protocol": protocol,
                "method": method,
                "path": path,
            },
            "profile": profile,
        },
        ttl_s=ttl_s,
    )


def confirm_approval(environment: SecurityEnvironment, approval_id: str):
    approval = environment.store.get_approval(approval_id)
    assert approval is not None
    channel = approving_channel(environment.clock, approval.action_digest)
    return environment.service.confirm_approval(approval_id, channel=channel)


def new_confirmation(
    *,
    digest: str,
    os_user: str = "human-owner",
    channel: str = "local_console",
    confirmation_id: str | None = None,
    note: str = "",
    confirmed_at: int = 0,
):
    from ctf_solver.security.confirmation import HumanConfirmation

    return HumanConfirmation(
        channel=channel,
        os_user=os_user,
        confirmed_at=confirmed_at,
        confirmation_id=(
            str(uuid.uuid4()) if confirmation_id is None else str(confirmation_id)
        ),
        approval_digest=digest,
        note=note,
    )
