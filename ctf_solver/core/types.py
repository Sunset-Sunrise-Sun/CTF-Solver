"""Shared domain types for CTF-Solver.

These types form the frozen contract between Manager, ACP Client, Broker,
Runtime, evidence pipeline and delivery modules. They are intentionally
serialisation-friendly (plain dicts in, plain dicts out) because they cross
process boundaries (stdio MCP, loopback IPC, SQLite rows).
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field, fields
from typing import Any, Mapping


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class Category(str, enum.Enum):
    WEB = "web"
    MISC = "misc"
    CRYPTO = "crypto"
    REVERSE = "reverse"
    PWN = "pwn"

    @classmethod
    def parse(cls, value: Any) -> "Category":
        if isinstance(value, cls):
            return value
        try:
            return cls(str(value).strip().lower())
        except ValueError as exc:  # pragma: no cover - message asserted in tests
            raise ValueError(
                f"unsupported category {value!r}; expected one of "
                f"{', '.join(item.value for item in cls)}"
            ) from exc


class TaskStatus(str, enum.Enum):
    CREATED = "created"
    QUEUED = "queued"
    STARTING = "starting"
    RUNNING = "running"
    PAUSED = "paused"
    AWAITING_APPROVAL = "awaiting_approval"
    BLOCKED = "blocked"
    CANCEL_REQUESTED = "cancel_requested"
    COMPLETION_PENDING = "completion_pending"
    CANCELLED = "cancelled"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    INTERRUPTED = "interrupted"


#: States in which a Task occupies one of the two Worker slots.
SLOT_OCCUPYING_TASK_STATUSES: frozenset[TaskStatus] = frozenset(
    {
        TaskStatus.STARTING,
        TaskStatus.RUNNING,
        TaskStatus.PAUSED,
        TaskStatus.AWAITING_APPROVAL,
        TaskStatus.BLOCKED,
        TaskStatus.CANCEL_REQUESTED,
        TaskStatus.COMPLETION_PENDING,
    }
)

#: States that end a Task's lifecycle; a new Task must be created for retries.
TERMINAL_TASK_STATUSES: frozenset[TaskStatus] = frozenset(
    {TaskStatus.CANCELLED, TaskStatus.COMPLETED, TaskStatus.PARTIAL, TaskStatus.FAILED}
)

#: Allowed durable Task state transitions. Anything else is rejected by the
#: Manager rather than silently ignored.
TASK_TRANSITIONS: dict[TaskStatus, frozenset[TaskStatus]] = {
    TaskStatus.CREATED: frozenset({TaskStatus.QUEUED, TaskStatus.CANCELLED, TaskStatus.FAILED}),
    TaskStatus.QUEUED: frozenset(
        {TaskStatus.STARTING, TaskStatus.CANCELLED, TaskStatus.FAILED, TaskStatus.INTERRUPTED}
    ),
    TaskStatus.STARTING: frozenset(
        {
            TaskStatus.RUNNING,
            TaskStatus.FAILED,
            TaskStatus.CANCELLED,
            TaskStatus.INTERRUPTED,
            TaskStatus.BLOCKED,
        }
    ),
    TaskStatus.RUNNING: frozenset(
        {
            TaskStatus.PAUSED,
            TaskStatus.AWAITING_APPROVAL,
            TaskStatus.BLOCKED,
            TaskStatus.CANCEL_REQUESTED,
            TaskStatus.COMPLETION_PENDING,
            TaskStatus.COMPLETED,
            TaskStatus.PARTIAL,
            TaskStatus.FAILED,
            TaskStatus.INTERRUPTED,
        }
    ),
    TaskStatus.PAUSED: frozenset(
        {
            TaskStatus.RUNNING,
            TaskStatus.CANCEL_REQUESTED,
            TaskStatus.COMPLETION_PENDING,
            TaskStatus.COMPLETED,
            TaskStatus.FAILED,
            TaskStatus.CANCELLED,
            TaskStatus.INTERRUPTED,
        }
    ),
    TaskStatus.AWAITING_APPROVAL: frozenset(
        {
            TaskStatus.RUNNING,
            TaskStatus.BLOCKED,
            TaskStatus.CANCEL_REQUESTED,
            TaskStatus.COMPLETION_PENDING,
            TaskStatus.COMPLETED,
            TaskStatus.FAILED,
            TaskStatus.INTERRUPTED,
        }
    ),
    TaskStatus.BLOCKED: frozenset(
        {
            TaskStatus.RUNNING,
            TaskStatus.CANCEL_REQUESTED,
            TaskStatus.COMPLETION_PENDING,
            TaskStatus.COMPLETED,
            TaskStatus.FAILED,
            TaskStatus.INTERRUPTED,
        }
    ),
    TaskStatus.CANCEL_REQUESTED: frozenset(
        {TaskStatus.CANCELLED, TaskStatus.FAILED, TaskStatus.INTERRUPTED}
    ),
    TaskStatus.COMPLETION_PENDING: frozenset(
        {
            TaskStatus.COMPLETED,
            TaskStatus.PARTIAL,
            TaskStatus.FAILED,
            TaskStatus.INTERRUPTED,
            # Used only to roll back when ACP session close fails before any
            # completion evidence is written.
            TaskStatus.RUNNING,
            TaskStatus.PAUSED,
            TaskStatus.BLOCKED,
            TaskStatus.AWAITING_APPROVAL,
        }
    ),
    TaskStatus.INTERRUPTED: frozenset({TaskStatus.CANCELLED, TaskStatus.FAILED}),
    TaskStatus.CANCELLED: frozenset(),
    TaskStatus.COMPLETED: frozenset(),
    TaskStatus.PARTIAL: frozenset(),
    TaskStatus.FAILED: frozenset(),
}


def can_transition(current: TaskStatus, target: TaskStatus) -> bool:
    return target in TASK_TRANSITIONS.get(current, frozenset())


class WorkerStatus(str, enum.Enum):
    STARTING = "starting"
    READY = "ready"
    RUNNING = "running"
    STOPPING = "stopping"
    STOPPED = "stopped"
    FAILED = "failed"
    CRASHED = "crashed"


#: Worker states that hold a concurrency slot.
SLOT_OCCUPYING_WORKER_STATUSES: frozenset[WorkerStatus] = frozenset(
    {
        WorkerStatus.STARTING,
        WorkerStatus.READY,
        WorkerStatus.RUNNING,
        WorkerStatus.STOPPING,
    }
)


class ExecutionTier(int, enum.Enum):
    TIER0_STATIC = 0
    TIER1_TRUSTED = 1
    TIER2_ISOLATED = 2


class ExecutionStatus(str, enum.Enum):
    COMPLETED = "completed"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    DENIED = "denied"
    BLOCKED = "blocked"
    UNKNOWN = "unknown"


class ApprovalStatus(str, enum.Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    CANCELLED = "cancelled"


class GrantStatus(str, enum.Enum):
    ACTIVE = "active"
    EXPIRED = "expired"
    EXHAUSTED = "exhausted"
    REVOKED = "revoked"


class FlagState(str, enum.Enum):
    NONE = "none"
    CANDIDATE = "candidate"
    USER_CONFIRMED = "user_confirmed"
    PLATFORM_VERIFIED = "platform_verified"


class CaptureStatus(str, enum.Enum):
    OK = "ok"
    BLANK = "blank"
    FAILED = "failed"


class ApprovalAction(str, enum.Enum):
    UNTRUSTED_CODE = "untrusted_code"
    SOFTWARE_INSTALL = "software_install"
    REMOTE_TARGET = "remote_target"
    TOOL_ACTION = "tool_action"


# ---------------------------------------------------------------------------
# Serialisation helpers
# ---------------------------------------------------------------------------


def _value(value: Any) -> Any:
    if isinstance(value, enum.Enum):
        return value.value
    return value


def _enum_or_none(enum_type: type[enum.Enum], value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, enum_type):
        return value
    return enum_type(value)


@dataclass
class TaskRecord:
    task_id: str
    conversation_id: str
    title: str
    category: Category
    workspace_path: str
    source: str = ""
    scope_profile: str = ""
    acp_session_id: str | None = None
    worker_id: str | None = None
    status: TaskStatus = TaskStatus.CREATED
    result_state: str = "unknown"
    flag_state: FlagState = FlagState.NONE
    flag_value: str | None = None
    created_at: int = 0
    updated_at: int = 0
    started_at: int | None = None
    ended_at: int | None = None
    evidence_head: str | None = None
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "conversation_id": self.conversation_id,
            "title": self.title,
            "category": self.category.value,
            "workspace_path": self.workspace_path,
            "source": self.source,
            "scope_profile": self.scope_profile,
            "acp_session_id": self.acp_session_id,
            "worker_id": self.worker_id,
            "status": self.status.value,
            "result_state": self.result_state,
            "flag_state": self.flag_state.value,
            "flag_value": self.flag_value,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "evidence_head": self.evidence_head,
            "notes": self.notes,
        }

    @classmethod
    def from_row(cls, row: Mapping[str, Any]) -> "TaskRecord":
        return cls(
            task_id=row["task_id"],
            conversation_id=row["conversation_id"],
            title=row["title"],
            category=Category(row["category"]),
            workspace_path=row["workspace_path"],
            source=row["source"] or "",
            scope_profile=row["scope_profile"] or "",
            acp_session_id=row["acp_session_id"],
            worker_id=row["worker_id"],
            status=TaskStatus(row["status"]),
            result_state=row["result_state"] or "unknown",
            flag_state=FlagState(row["flag_state"] or "none"),
            flag_value=row["flag_value"] if "flag_value" in row.keys() else None,
            created_at=int(row["created_at"]),
            updated_at=int(row["updated_at"]),
            started_at=row["started_at"],
            ended_at=row["ended_at"],
            evidence_head=row["evidence_head"],
            notes=row["notes"] or "",
        )


@dataclass
class WorkerRecord:
    worker_id: str
    task_id: str
    acp_session_id: str
    workspace_path: str
    status: WorkerStatus
    worker_token: str
    created_at: int = 0
    updated_at: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "worker_id": self.worker_id,
            "task_id": self.task_id,
            "acp_session_id": self.acp_session_id,
            "workspace_path": self.workspace_path,
            "status": self.status.value,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_row(cls, row: Mapping[str, Any]) -> "WorkerRecord":
        return cls(
            worker_id=row["worker_id"],
            task_id=row["task_id"],
            acp_session_id=row["acp_session_id"],
            workspace_path=row["workspace_path"],
            status=WorkerStatus(row["status"]),
            worker_token=row["worker_token"],
            created_at=int(row["created_at"]),
            updated_at=int(row["updated_at"]),
        )


@dataclass
class ApprovalRecord:
    approval_id: str
    task_id: str
    action_kind: str
    action_digest: str
    status: ApprovalStatus = ApprovalStatus.PENDING
    requested_at: int = 0
    decided_at: int | None = None
    approver: str | None = None
    note: str = ""
    payload: dict[str, Any] = field(default_factory=dict)
    expires_at: int | None = None
    consumed_at: int | None = None
    confirmation_channel: str | None = None
    confirmation_id: str | None = None
    confirmation_os_user: str | None = None
    confirmation_note: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "approval_id": self.approval_id,
            "task_id": self.task_id,
            "action_kind": self.action_kind,
            "action_digest": self.action_digest,
            "status": self.status.value,
            "requested_at": self.requested_at,
            "decided_at": self.decided_at,
            "approver": self.approver,
            "note": self.note,
            "payload": self.payload,
            "expires_at": self.expires_at,
            "consumed_at": self.consumed_at,
            "confirmation_channel": self.confirmation_channel,
            "confirmation_id": self.confirmation_id,
            "confirmation_os_user": self.confirmation_os_user,
            "confirmation_note": self.confirmation_note,
        }


@dataclass
class GrantRecord:
    grant_id: str
    task_id: str
    competition_profile: str
    host: str
    port: int
    protocol: str
    method: str
    path_prefix: str
    expires_at: int
    max_calls: int
    approver: str
    calls_used: int = 0
    created_at: int = 0
    status: GrantStatus = GrantStatus.ACTIVE
    grant_digest: str = ""
    approval_id: str | None = None
    confirmation_id: str | None = None
    confirmation_os_user: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "grant_id": self.grant_id,
            "task_id": self.task_id,
            "competition_profile": self.competition_profile,
            "host": self.host,
            "port": self.port,
            "protocol": self.protocol,
            "method": self.method,
            "path_prefix": self.path_prefix,
            "expires_at": self.expires_at,
            "max_calls": self.max_calls,
            "calls_used": self.calls_used,
            "approver": self.approver,
            "created_at": self.created_at,
            "status": self.status.value,
            "grant_digest": self.grant_digest,
            "approval_id": self.approval_id,
            "confirmation_id": self.confirmation_id,
            "confirmation_os_user": self.confirmation_os_user,
        }


@dataclass
class ArtifactRef:
    sha256: str
    size: int
    media_type: str = "application/octet-stream"
    cas_path: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "sha256": self.sha256,
            "size": self.size,
            "media_type": self.media_type,
            "cas_path": self.cas_path,
        }


@dataclass
class ImportedInput:
    """One challenge-supplied file imported into a Task workspace under Manager control."""

    rel_path: str
    sha256: str
    size: int
    media_type: str = "application/octet-stream"
    source_rel_path: str = ""
    imported_at: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "rel_path": self.rel_path,
            "sha256": self.sha256,
            "size": self.size,
            "media_type": self.media_type,
            "source_rel_path": self.source_rel_path,
            "imported_at": self.imported_at,
        }

    @classmethod
    def from_row(cls, row: Any) -> "ImportedInput":
        return cls(
            rel_path=row["rel_path"],
            sha256=row["sha256"],
            size=int(row["size"]),
            media_type=row["media_type"],
            source_rel_path=row["source_rel_path"] or "",
            imported_at=int(row["imported_at"]),
        )


@dataclass
class NetworkTarget:
    host: str
    port: int
    protocol: str
    method: str
    path: str = "/"

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "protocol": self.protocol,
            "method": self.method,
            "path": self.path,
        }

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any], *, default_port: int = 0) -> "NetworkTarget":
        host = str(data.get("host", "")).strip()
        if not host:
            raise ValueError("network target requires host")
        try:
            port = int(data.get("port", default_port))
        except (TypeError, ValueError) as exc:
            raise ValueError(f"invalid network target port: {data.get('port')!r}") from exc
        protocol = str(data.get("protocol", "tcp")).strip().lower()
        method = str(data.get("method", "")).strip().upper()
        path = str(data.get("path", "/"))
        if not path.startswith("/"):
            raise ValueError("network target path must start with '/'")
        return cls(host=host, port=port, protocol=protocol, method=method, path=path)


@dataclass
class ExecRequest:
    """Typed ``ctf-exec`` request as defined in docs/EXECUTION_CONTRACT.md."""

    task_id: str
    worker_id: str
    step_id: str
    tool_name: str
    argv: list[str]
    cwd: str
    tool_version: str | None = None
    input_files: list[dict[str, Any]] = field(default_factory=list)
    output_paths: list[str] = field(default_factory=list)
    network_grant_id: str | None = None
    approval_id: str | None = None
    network_target: NetworkTarget | None = None
    timeout_s: float = 30.0
    tier: ExecutionTier = ExecutionTier.TIER1_TRUSTED
    max_output_bytes: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "worker_id": self.worker_id,
            "step_id": self.step_id,
            "tool_name": self.tool_name,
            "tool_version": self.tool_version,
            "argv": list(self.argv),
            "cwd": self.cwd,
            "input_files": [dict(item) for item in self.input_files],
            "output_paths": list(self.output_paths),
            "network_grant_id": self.network_grant_id,
            "approval_id": self.approval_id,
            "network_target": self.network_target.to_dict() if self.network_target else None,
            "timeout_s": self.timeout_s,
            "tier": int(self.tier),
            "max_output_bytes": self.max_output_bytes,
        }

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "ExecRequest":
        from .errors import ValidationError

        if not isinstance(data, Mapping):
            raise ValidationError("ctf-exec request must be a JSON object")
        required = ("task_id", "worker_id", "step_id", "tool_name", "argv", "cwd")
        missing = [name for name in required if name not in data]
        if missing:
            raise ValidationError(
                f"ctf-exec request missing required field(s): {', '.join(missing)}",
                details={"missing": missing},
            )
        argv = data["argv"]
        if not isinstance(argv, list) or not all(isinstance(item, str) for item in argv):
            raise ValidationError("ctf-exec argv must be an array of strings (never a shell string)")
        input_files = data.get("input_files") or []
        if not isinstance(input_files, list) or not all(isinstance(item, Mapping) for item in input_files):
            raise ValidationError("ctf-exec input_files must be an array of objects")
        output_paths = data.get("output_paths") or []
        if not isinstance(output_paths, list) or not all(isinstance(item, str) for item in output_paths):
            raise ValidationError("ctf-exec output_paths must be an array of strings")
        tier_raw = data.get("tier", int(ExecutionTier.TIER1_TRUSTED))
        try:
            tier = ExecutionTier(int(tier_raw))
        except (TypeError, ValueError) as exc:
            raise ValidationError(f"invalid execution tier: {tier_raw!r}") from exc
        timeout_s = float(data.get("timeout_s", 30.0))
        if not 0.1 <= timeout_s <= 600.0:
            raise ValidationError("ctf-exec timeout_s must be within [0.1, 600]")
        network_target = None
        if data.get("network_target") is not None:
            try:
                network_target = NetworkTarget.from_mapping(data["network_target"])
            except ValueError as exc:
                raise ValidationError(f"invalid network_target: {exc}") from exc
        max_output = data.get("max_output_bytes")
        if max_output is not None:
            max_output = int(max_output)
            if max_output <= 0 or max_output > 64 * 1024 * 1024:
                raise ValidationError("max_output_bytes must be within (0, 64 MiB]")
        return cls(
            task_id=str(data["task_id"]),
            worker_id=str(data["worker_id"]),
            step_id=str(data["step_id"]),
            tool_name=str(data["tool_name"]),
            tool_version=(str(data["tool_version"]) if data.get("tool_version") else None),
            argv=[str(item) for item in argv],
            cwd=str(data["cwd"]),
            input_files=[dict(item) for item in input_files],
            output_paths=[str(item) for item in output_paths],
            network_grant_id=(
                str(data["network_grant_id"]) if data.get("network_grant_id") else None
            ),
            approval_id=(str(data["approval_id"]) if data.get("approval_id") else None),
            network_target=network_target,
            timeout_s=timeout_s,
            tier=tier,
            max_output_bytes=max_output,
        )


@dataclass
class BrokerDecision:
    allowed: bool
    reason_code: str
    reason: str = ""
    tool: dict[str, Any] | None = None
    effective_tier: ExecutionTier = ExecutionTier.TIER0_STATIC
    approval_id: str | None = None
    network_grant_id: str | None = None
    grant_call_consumed: bool = False

    @classmethod
    def deny(cls, reason: Any, message: str = "", **extra: Any) -> "BrokerDecision":
        code = reason.value if isinstance(reason, enum.Enum) else str(reason)
        return cls(allowed=False, reason_code=code, reason=message, **extra)

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "reason_code": self.reason_code,
            "reason": self.reason,
            "tool": self.tool,
            "effective_tier": int(self.effective_tier),
            "approval_id": self.approval_id,
            "network_grant_id": self.network_grant_id,
            "grant_call_consumed": self.grant_call_consumed,
        }


@dataclass
class RuntimeOutcome:
    status: ExecutionStatus
    exit_code: int | None = None
    stdout: bytes = b""
    stderr: bytes = b""
    started_at: int = 0
    ended_at: int = 0
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "exit_code": self.exit_code,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "stdout_bytes": len(self.stdout),
            "stderr_bytes": len(self.stderr),
            "stdout_truncated": self.stdout_truncated,
            "stderr_truncated": self.stderr_truncated,
            "error": self.error,
        }


@dataclass
class ExecutionResult:
    """Response contract for one ``ctf-exec`` call (see EXECUTION_CONTRACT.md)."""

    execution_id: str
    task_id: str
    worker_id: str
    step_id: str
    tool_name: str
    tool_version: str | None
    argv: list[str]
    cwd: str
    status: ExecutionStatus
    started_at: int
    ended_at: int
    exit_code: int | None = None
    input_files: list[dict[str, Any]] = field(default_factory=list)
    output_files: list[dict[str, Any]] = field(default_factory=list)
    stdout_sha256: str | None = None
    stderr_sha256: str | None = None
    stdout_preview: str = ""
    stderr_preview: str = ""
    screenshot_paths: list[str] = field(default_factory=list)
    network_grant_id: str | None = None
    approval_id: str | None = None
    reason_code: str = ""
    reason: str = ""
    request: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "execution_id": self.execution_id,
            "task_id": self.task_id,
            "worker_id": self.worker_id,
            "step_id": self.step_id,
            "tool_name": self.tool_name,
            "tool_version": self.tool_version,
            "argv": list(self.argv),
            "cwd": self.cwd,
            "status": self.status.value,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "exit_code": self.exit_code,
            "input_files": [dict(item) for item in self.input_files],
            "output_files": [dict(item) for item in self.output_files],
            "stdout_sha256": self.stdout_sha256,
            "stderr_sha256": self.stderr_sha256,
            "stdout_preview": self.stdout_preview,
            "stderr_preview": self.stderr_preview,
            "screenshot_paths": list(self.screenshot_paths),
            "network_grant_id": self.network_grant_id,
            "approval_id": self.approval_id,
            "reason_code": self.reason_code,
            "reason": self.reason,
            "request": self.request,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ExecutionResult":
        return cls(
            execution_id=str(data["execution_id"]),
            task_id=str(data["task_id"]),
            worker_id=str(data["worker_id"]),
            step_id=str(data["step_id"]),
            tool_name=str(data["tool_name"]),
            tool_version=data.get("tool_version"),
            argv=[str(item) for item in data.get("argv", [])],
            cwd=str(data["cwd"]),
            status=ExecutionStatus(data["status"]),
            started_at=int(data.get("started_at", 0)),
            ended_at=int(data.get("ended_at", 0)),
            exit_code=data.get("exit_code"),
            input_files=[dict(item) for item in data.get("input_files", [])],
            output_files=[dict(item) for item in data.get("output_files", [])],
            stdout_sha256=data.get("stdout_sha256"),
            stderr_sha256=data.get("stderr_sha256"),
            stdout_preview=data.get("stdout_preview", ""),
            stderr_preview=data.get("stderr_preview", ""),
            screenshot_paths=list(data.get("screenshot_paths", [])),
            network_grant_id=data.get("network_grant_id"),
            approval_id=data.get("approval_id"),
            reason_code=data.get("reason_code", ""),
            reason=data.get("reason", ""),
            request=dict(data.get("request", {})),
        )


@dataclass
class ScreenshotRecord:
    screenshot_id: str
    task_id: str
    scope: str
    captured_at: int
    status: CaptureStatus
    worker_id: str | None = None
    step_id: str | None = None
    session_id: str | None = None
    sha256: str | None = None
    width: int | None = None
    height: int | None = None
    media_type: str = "image/png"
    failure_reason: str = ""
    execution_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "screenshot_id": self.screenshot_id,
            "task_id": self.task_id,
            "worker_id": self.worker_id,
            "step_id": self.step_id,
            "session_id": self.session_id,
            "scope": self.scope,
            "captured_at": self.captured_at,
            "status": self.status.value,
            "sha256": self.sha256,
            "width": self.width,
            "height": self.height,
            "media_type": self.media_type,
            "failure_reason": self.failure_reason,
            "execution_id": self.execution_id,
        }

    @classmethod
    def from_row(cls, row: Mapping[str, Any]) -> "ScreenshotRecord":
        return cls(
            screenshot_id=row["screenshot_id"],
            task_id=row["task_id"],
            worker_id=row["worker_id"],
            step_id=row["step_id"],
            session_id=row["session_id"],
            scope=row["scope"],
            captured_at=int(row["captured_at"]),
            status=CaptureStatus(row["status"]),
            sha256=row["sha256"],
            width=row["width"],
            height=row["height"],
            media_type=row["media_type"],
            failure_reason=row["failure_reason"] or "",
            execution_id=row["execution_id"],
        )


@dataclass
class CaptureResult:
    ok: bool
    png_bytes: bytes
    width: int = 0
    height: int = 0
    blank: bool = False
    error: str = ""
    method: str = ""
    captured_at: int = 0

    @property
    def status(self) -> CaptureStatus:
        if self.ok and not self.blank:
            return CaptureStatus.OK
        if self.ok and self.blank:
            return CaptureStatus.BLANK
        return CaptureStatus.FAILED


@dataclass
class ChainStatus:
    ok: bool
    records: int
    head_hash: str
    error: str = ""
    broken_at_seq: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "records": self.records,
            "head_hash": self.head_hash,
            "error": self.error,
            "broken_at_seq": self.broken_at_seq,
        }


@dataclass
class ExportInfo:
    kind: str
    path: str
    sha256: str
    size: int
    entries: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "path": self.path,
            "sha256": self.sha256,
            "size": self.size,
            "entries": self.entries,
        }
