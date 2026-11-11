"""Shared deterministic fakes for the Broker/Runtime test suites.

These fakes satisfy the frozen ``ctf_solver.core.protocols`` contracts
(``PolicyRepository`` / ``EvidenceSink``) structurally and are imported by
``tests/test_broker_*.py`` and ``tests/test_runtime_*.py``. They write nothing
outside ``tmp_path`` and never touch the network, a model or a real Harness
session.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ctf_solver.core.canonical import file_sha256, sha256_hex
from ctf_solver.core.types import (
    ApprovalAction,
    ApprovalRecord,
    ApprovalStatus,
    ArtifactRef,
    Category,
    ExecutionStatus,
    ExecutionTier,
    ExecRequest,
    GrantRecord,
    GrantStatus,
    NetworkTarget,
    RuntimeOutcome,
    TaskRecord,
    TaskStatus,
    WorkerRecord,
    WorkerStatus,
)
from ctf_solver.policy.models import approval_action_digest, approval_details
from ctf_solver.runtime.catalog import RuntimeCatalog
from ctf_solver.runtime.executor import RuntimeExecutor
from ctf_solver.runtime.tools import ToolInvocation, ToolSpec

BASE_NOW_MS = 1_700_000_000_000
SESSION_ID = "session-1"
TASK_ID = "task-1"
WORKER_ID = "worker-1"
WORKER_TOKEN = "worker-token-1"
PUBLIC_HOST = "93.184.216.34"
PRIVATE_HOST = "10.0.0.5"
LOOPBACK_HOST = "127.0.0.1"


# ---------------------------------------------------------------------------
# Clock / repository / evidence fakes
# ---------------------------------------------------------------------------


class FakeClock:
    def __init__(self, now_ms: int = BASE_NOW_MS) -> None:
        self._now = int(now_ms)

    def now_ms(self) -> int:
        return self._now

    def advance(self, delta_ms: int) -> int:
        self._now += int(delta_ms)
        return self._now

    def set(self, now_ms: int) -> None:
        self._now = int(now_ms)


class FakeRepository:
    """In-memory PolicyRepository with atomic consume semantics."""

    def __init__(self, clock: FakeClock | None = None) -> None:
        self.clock = clock or FakeClock()
        self.tasks: dict[str, TaskRecord] = {}
        self.workers: dict[str, WorkerRecord] = {}
        self.workers_by_token: dict[str, WorkerRecord] = {}
        self.approvals: dict[str, ApprovalRecord] = {}
        self.grants: dict[str, GrantRecord] = {}
        self.executions: dict[str, dict[str, Any]] = {}
        self.inserts: list[dict[str, Any]] = []
        self.updates: list[tuple[str, dict[str, Any]]] = []

    # -- fixtures -----------------------------------------------------------

    def add_task(self, task: TaskRecord) -> TaskRecord:
        self.tasks[task.task_id] = task
        return task

    def add_worker(self, worker: WorkerRecord) -> WorkerRecord:
        self.workers[worker.worker_id] = worker
        self.workers_by_token[worker.worker_token] = worker
        return worker

    def add_approval(self, approval: ApprovalRecord) -> ApprovalRecord:
        self.approvals[approval.approval_id] = approval
        return approval

    def add_grant(self, grant: GrantRecord) -> GrantRecord:
        self.grants[grant.grant_id] = grant
        return grant

    # -- PolicyRepository ---------------------------------------------------

    def get_task(self, task_id: str) -> TaskRecord | None:
        return self.tasks.get(task_id)

    def get_worker(self, worker_id: str) -> WorkerRecord | None:
        return self.workers.get(worker_id)

    def get_worker_by_token(self, token: str) -> WorkerRecord | None:
        return self.workers_by_token.get(token)

    def get_approval(self, approval_id: str) -> ApprovalRecord | None:
        return self.approvals.get(approval_id)

    def get_grant(self, grant_id: str) -> GrantRecord | None:
        return self.grants.get(grant_id)

    def consume_grant_call(self, grant_id: str, now_ms: int) -> bool:
        grant = self.grants.get(grant_id)
        if grant is None:
            return False
        if grant.status is not GrantStatus.ACTIVE:
            return False
        if int(grant.expires_at) <= int(now_ms):
            grant.status = GrantStatus.EXPIRED
            return False
        if int(grant.calls_used) >= int(grant.max_calls):
            grant.status = GrantStatus.EXHAUSTED
            return False
        grant.calls_used += 1
        if grant.calls_used >= grant.max_calls:
            grant.status = GrantStatus.EXHAUSTED
        return True

    def consume_approval(self, approval_id: str, now_ms: int) -> bool:
        approval = self.approvals.get(approval_id)
        if approval is None:
            return False
        if approval.status is not ApprovalStatus.APPROVED:
            return False
        if approval.consumed_at is not None:
            return False
        if approval.expires_at is not None and int(approval.expires_at) <= int(now_ms):
            approval.status = ApprovalStatus.EXPIRED
            return False
        approval.consumed_at = int(now_ms)
        return True

    def record_execution(self, row: dict[str, Any]) -> None:
        stored = dict(row)
        self.inserts.append(stored)
        self.executions[stored["execution_id"]] = dict(stored)

    def update_execution(self, execution_id: str, updates: dict[str, Any]) -> None:
        copied = dict(updates)
        self.updates.append((execution_id, copied))
        self.executions.setdefault(execution_id, {}).update(copied)


class FakeEvidenceSink:
    """In-memory EvidenceSink capturing events and CAS artifacts."""

    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []
        self.artifacts: dict[str, bytes] = {}

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
        if record_id is None:
            record_id = f"ev-{len(self.events) + 1:04d}"
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
                "timestamp": int(timestamp or 0),
                "payload": payload,
            }
        )
        return record_id

    def store_artifact(
        self,
        data: bytes,
        *,
        media_type: str = "application/octet-stream",
        source: str = "",
    ) -> ArtifactRef:
        blob = bytes(data)
        digest = sha256_hex(blob)
        self.artifacts[digest] = blob
        return ArtifactRef(
            sha256=digest,
            size=len(blob),
            media_type=media_type,
            cas_path=f"cas/sha256/{digest}",
        )

    def events_of_type(self, event_type: str) -> list[dict[str, Any]]:
        return [event for event in self.events if event["event_type"] == event_type]


class RecordingExecutor(RuntimeExecutor):
    """RuntimeExecutor that records calls; returns a preset outcome."""

    def __init__(self, outcome: RuntimeOutcome | None = None, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.calls: list[tuple[str, list[str]]] = []
        self.outcome = outcome

    def execute(self, spec: ToolSpec, invocation: ToolInvocation) -> RuntimeOutcome:
        self.calls.append((spec.name, list(invocation.argv)))
        if self.outcome is not None:
            return self.outcome
        return super().execute(spec, invocation)


class ForbiddenExecutor(RuntimeExecutor):
    """RuntimeExecutor that fails loudly if a denied request reaches it."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.call_count = 0

    def execute(self, spec: ToolSpec, invocation: ToolInvocation) -> RuntimeOutcome:
        self.call_count += 1
        raise AssertionError("executor must never be called for a denied execution")


# ---------------------------------------------------------------------------
# Record factories
# ---------------------------------------------------------------------------


def make_workspace(tmp_path: Path, name: str = "work") -> Path:
    workspace = tmp_path / "tasks" / TASK_ID / name
    workspace.mkdir(parents=True, exist_ok=True)
    return workspace


def make_task(
    workspace: Path,
    *,
    task_id: str = TASK_ID,
    status: TaskStatus = TaskStatus.RUNNING,
    worker_id: str | None = WORKER_ID,
    session_id: str | None = SESSION_ID,
    scope_profile: str = "",
) -> TaskRecord:
    return TaskRecord(
        task_id=task_id,
        conversation_id="conv-1",
        title="synthetic challenge",
        category=Category.MISC,
        workspace_path=str(workspace),
        source="synthetic",
        scope_profile=scope_profile,
        acp_session_id=session_id,
        worker_id=worker_id,
        status=status,
        created_at=BASE_NOW_MS,
        updated_at=BASE_NOW_MS,
    )


def make_worker(
    workspace: Path,
    *,
    worker_id: str = WORKER_ID,
    task_id: str = TASK_ID,
    token: str = WORKER_TOKEN,
    status: WorkerStatus = WorkerStatus.READY,
    session_id: str = SESSION_ID,
    workspace_path: str | None = None,
) -> WorkerRecord:
    return WorkerRecord(
        worker_id=worker_id,
        task_id=task_id,
        acp_session_id=session_id,
        workspace_path=str(workspace_path if workspace_path is not None else workspace),
        status=status,
        worker_token=token,
        created_at=BASE_NOW_MS,
        updated_at=BASE_NOW_MS,
    )


@dataclass
class BoundTask:
    workspace: Path
    task: TaskRecord
    worker: WorkerRecord
    repository: FakeRepository
    clock: FakeClock

    def request(self, **overrides: Any) -> ExecRequest:
        return make_request(self.task, self.worker, **overrides)


def bind_task(
    tmp_path: Path,
    *,
    task_status: TaskStatus = TaskStatus.RUNNING,
    worker_status: WorkerStatus = WorkerStatus.READY,
    scope_profile: str = "",
    clock: FakeClock | None = None,
) -> BoundTask:
    clock = clock or FakeClock()
    workspace = make_workspace(tmp_path)
    task = make_task(workspace, status=task_status, scope_profile=scope_profile)
    worker = make_worker(workspace, status=worker_status)
    repository = FakeRepository(clock=clock)
    repository.add_task(task)
    repository.add_worker(worker)
    return BoundTask(
        workspace=workspace,
        task=task,
        worker=worker,
        repository=repository,
        clock=clock,
    )


def make_request(
    task: TaskRecord,
    worker: WorkerRecord,
    *,
    tool_name: str = "internal.file_hash",
    argv: list[str] | None = None,
    cwd: str | None = None,
    tool_version: str | None = None,
    input_files: list[dict[str, Any]] | None = None,
    output_paths: list[str] | None = None,
    network_target: NetworkTarget | None = None,
    network_grant_id: str | None = None,
    approval_id: str | None = None,
    timeout_s: float = 30.0,
    tier: ExecutionTier = ExecutionTier.TIER1_TRUSTED,
    max_output_bytes: int | None = None,
    step_id: str = "step-1",
) -> ExecRequest:
    return ExecRequest(
        task_id=task.task_id,
        worker_id=worker.worker_id,
        step_id=step_id,
        tool_name=tool_name,
        argv=list(argv) if argv is not None else ["input.txt"],
        cwd=cwd or task.workspace_path,
        tool_version=tool_version,
        input_files=list(input_files or []),
        output_paths=list(output_paths or []),
        network_target=network_target,
        network_grant_id=network_grant_id,
        approval_id=approval_id,
        timeout_s=timeout_s,
        tier=tier,
        max_output_bytes=max_output_bytes,
    )


def make_network_target(
    host: str = PUBLIC_HOST,
    port: int = 443,
    protocol: str = "https",
    method: str = "GET",
    path: str = "/",
) -> NetworkTarget:
    return NetworkTarget(host=host, port=port, protocol=protocol, method=method, path=path)


def make_approval(
    request: ExecRequest,
    *,
    approval_id: str = "appr-1",
    action_kind: str | ApprovalAction = ApprovalAction.TOOL_ACTION,
    status: ApprovalStatus = ApprovalStatus.APPROVED,
    expires_at: int | None = BASE_NOW_MS + 3_600_000,
    consumed_at: int | None = None,
    digest: str | None = None,
) -> ApprovalRecord:
    kind = action_kind.value if isinstance(action_kind, ApprovalAction) else str(action_kind)
    return ApprovalRecord(
        approval_id=approval_id,
        task_id=request.task_id,
        action_kind=kind,
        action_digest=digest if digest is not None else approval_action_digest(kind, request),
        status=status,
        requested_at=BASE_NOW_MS,
        decided_at=BASE_NOW_MS,
        approver="human",
        note="synthetic approval",
        payload={"details": approval_details(request)},
        expires_at=expires_at,
        consumed_at=consumed_at,
    )


def make_grant(
    *,
    grant_id: str = "grant-1",
    task_id: str = TASK_ID,
    competition_profile: str = "",
    host: str = PUBLIC_HOST,
    port: int = 443,
    protocol: str = "https",
    method: str = "GET",
    path_prefix: str = "/",
    expires_at: int = BASE_NOW_MS + 3_600_000,
    max_calls: int = 5,
    calls_used: int = 0,
    approver: str = "human",
    status: GrantStatus = GrantStatus.ACTIVE,
    grant_digest: str = "",
) -> GrantRecord:
    return GrantRecord(
        grant_id=grant_id,
        task_id=task_id,
        competition_profile=competition_profile,
        host=host,
        port=port,
        protocol=protocol,
        method=method,
        path_prefix=path_prefix,
        expires_at=expires_at,
        max_calls=max_calls,
        approver=approver,
        calls_used=calls_used,
        created_at=BASE_NOW_MS,
        status=status,
        grant_digest=grant_digest,
    )


# ---------------------------------------------------------------------------
# Tool/catalogue factories
# ---------------------------------------------------------------------------


def code_writing_tool(payload: bytes = b"artifact-bytes\n") -> ToolSpec:
    """Internal tool that writes one output file (used for output hashing)."""

    def _write(invocation: ToolInvocation) -> RuntimeOutcome:
        target = Path(invocation.cwd) / "out.txt"
        target.write_bytes(payload)
        return RuntimeOutcome(
            status=ExecutionStatus.COMPLETED,
            exit_code=0,
            stdout=b"wrote out.txt\n",
        )

    return ToolSpec(
        name="synth.write_output",
        display_name="Synthetic output writer",
        description="Test-only internal tool that writes out.txt into the workspace.",
        tier=ExecutionTier.TIER0_STATIC,
        version="1",
        internal=_write,
        max_output_bytes=64 * 1024,
    )


def network_stub_tool(
    *,
    name: str = "synth.network_probe",
    tier: ExecutionTier = ExecutionTier.TIER1_TRUSTED,
    requires_approval: ApprovalAction | None = None,
) -> ToolSpec:
    return ToolSpec(
        name=name,
        display_name="Synthetic network probe",
        description="Test-only network-capable tool used to exercise grant policy.",
        tier=tier,
        version="1",
        network=True,
        requires_approval=requires_approval,
        internal=lambda invocation: RuntimeOutcome(
            status=ExecutionStatus.COMPLETED, exit_code=0, stdout=b"synthetic network stub\n"
        ),
        arg_validator=lambda argv: None if argv else "argv must not be empty",
        max_output_bytes=64 * 1024,
    )


def needs_approval_tool(
    *, action: ApprovalAction = ApprovalAction.TOOL_ACTION
) -> ToolSpec:
    return ToolSpec(
        name="synth.needs_approval",
        display_name="Synthetic approval-gated tool",
        description="Test-only internal tool that requires a human approval.",
        tier=ExecutionTier.TIER0_STATIC,
        version="1",
        internal=lambda invocation: RuntimeOutcome(
            status=ExecutionStatus.COMPLETED, exit_code=0, stdout=b"approved\n"
        ),
        requires_approval=action,
        max_output_bytes=64 * 1024,
    )


def untrusted_code_tool(
    *, tier: ExecutionTier = ExecutionTier.TIER2_ISOLATED
) -> ToolSpec:
    return ToolSpec(
        name="synth.untrusted",
        display_name="Synthetic untrusted-code tool",
        description="Test-only tool flagged as executing challenge-provided code.",
        tier=tier,
        version="1",
        executes_challenge_code=True,
        internal=lambda invocation: RuntimeOutcome(
            status=ExecutionStatus.COMPLETED, exit_code=0, stdout=b"should never run\n"
        ),
        max_output_bytes=64 * 1024,
    )


def sleep_tool(*, name: str = "synth.sleep") -> ToolSpec:
    """Subprocess tool whose argv runs a sleeping Python interpreter."""

    return ToolSpec(
        name=name,
        display_name="Synthetic sleeping tool",
        description="Test-only subprocess tool that sleeps (timeout tests).",
        tier=ExecutionTier.TIER1_TRUSTED,
        version="1",
        executable=sys.executable,
        max_output_bytes=4096,
        default_timeout_s=5.0,
    )


def python_print_tool(*, name: str = "synth.print") -> ToolSpec:
    """Subprocess tool whose argv prints text (output-cap tests)."""

    return ToolSpec(
        name=name,
        display_name="Synthetic printing tool",
        description="Test-only subprocess tool that prints caller-provided argv.",
        tier=ExecutionTier.TIER1_TRUSTED,
        version="1",
        executable=sys.executable,
        max_output_bytes=1024 * 1024,
        default_timeout_s=10.0,
    )


def custom_catalog(*tools: ToolSpec, **kwargs: Any) -> RuntimeCatalog:
    return RuntimeCatalog(tools=list(tools), **kwargs)


def catalog_with(*extra_tools: ToolSpec, **kwargs: Any) -> RuntimeCatalog:
    """Builtin trusted tools plus test-only synthetic tools."""

    from ctf_solver.runtime.tools import build_builtin_tools

    return RuntimeCatalog(tools=[*build_builtin_tools(), *extra_tools], **kwargs)


def file_fixture(workspace: Path, name: str, data: bytes) -> Path:
    path = workspace / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def file_input(workspace: Path, name: str) -> dict[str, str]:
    path = workspace / name
    return {"path": name, "sha256": file_sha256(path)}


__all__ = [
    "BASE_NOW_MS",
    "BoundTask",
    "FakeClock",
    "FakeEvidenceSink",
    "FakeRepository",
    "ForbiddenExecutor",
    "LOOPBACK_HOST",
    "PRIVATE_HOST",
    "PUBLIC_HOST",
    "RecordingExecutor",
    "SESSION_ID",
    "TASK_ID",
    "WORKER_ID",
    "WORKER_TOKEN",
    "bind_task",
    "catalog_with",
    "code_writing_tool",
    "custom_catalog",
    "file_fixture",
    "file_input",
    "make_approval",
    "make_grant",
    "make_network_target",
    "make_request",
    "make_task",
    "make_worker",
    "make_workspace",
    "needs_approval_tool",
    "network_stub_tool",
    "python_print_tool",
    "sleep_tool",
    "untrusted_code_tool",
]
