"""Cross-module protocols ("contracts") frozen for Round 1.

Each module depends on these structural protocols instead of importing
another module's concrete implementation. This keeps write scopes disjoint
while guaranteeing that Manager, ACP, Broker/Runtime, evidence and delivery
compose at runtime.
"""

from __future__ import annotations

import time
from typing import Any, Callable, Protocol, runtime_checkable

from .types import (
    ApprovalRecord,
    ArtifactRef,
    CaptureResult,
    ExecRequest,
    ExecutionResult,
    ExportInfo,
    GrantRecord,
    ScreenshotRecord,
    TaskRecord,
    WorkerRecord,
)


class Clock(Protocol):
    def now_ms(self) -> int: ...


class SystemClock:
    """Wall-clock implementation (milliseconds since the Unix epoch)."""

    def now_ms(self) -> int:
        return int(time.time() * 1000)


@runtime_checkable
class AcpSessionClient(Protocol):
    """The Manager-facing ACP client surface (one managed ACP Server process)."""

    state: str

    def start(self) -> None:
        """Spawn the ACP server process and complete ``initialize``."""

    def stop(self, timeout_s: float = 10.0) -> None:
        """Close the transport and terminate the managed process."""

    def is_alive(self) -> bool: ...

    def diagnostics(self) -> dict[str, Any]: ...

    def new_session(self, cwd: str, mcp_servers: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        """Call ``session/new`` and return the raw result (contains sessionId)."""

    def list_sessions(self, cwd: str | None = None) -> dict[str, Any]: ...

    def resume_session(self, session_id: str, cwd: str) -> dict[str, Any]: ...

    def close_session(self, session_id: str) -> None: ...

    def cancel_session(self, session_id: str) -> None: ...

    def prompt(self, session_id: str, content: list[dict[str, Any]]) -> dict[str, Any]:
        """Round 1 gate: raises ModelCallNotAuthorized unless explicitly enabled."""

    def set_session_update_handler(self, handler: Callable[[dict[str, Any]], None] | None) -> None: ...

    def set_permission_handler(
        self, handler: Callable[[dict[str, Any]], dict[str, Any]] | None
    ) -> None: ...


AcpClientFactory = Callable[[], AcpSessionClient]


@runtime_checkable
class EvidenceSink(Protocol):
    """Minimal sink used by the execution pipeline to record durable evidence."""

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
    ) -> str: ...

    def store_artifact(
        self,
        data: bytes,
        *,
        media_type: str = "application/octet-stream",
        source: str = "",
    ) -> ArtifactRef: ...


@runtime_checkable
class PolicyRepository(Protocol):
    """Authoritative Manager state queried by the Broker and Runtime pipeline."""

    def get_task(self, task_id: str) -> TaskRecord | None: ...

    def get_worker(self, worker_id: str) -> WorkerRecord | None: ...

    def get_worker_by_token(self, token: str) -> WorkerRecord | None: ...

    def get_approval(self, approval_id: str) -> ApprovalRecord | None: ...

    def get_grant(self, grant_id: str) -> GrantRecord | None: ...

    def consume_grant_call(self, grant_id: str, now_ms: int) -> bool: ...

    def consume_approval(self, approval_id: str, now_ms: int) -> bool: ...

    def record_execution(self, row: dict[str, Any]) -> None: ...

    def update_execution(self, execution_id: str, updates: dict[str, Any]) -> None: ...


@runtime_checkable
class ExecutionPipelineProtocol(Protocol):
    """Broker + Runtime orchestration entry used by Manager IPC / tests."""

    def execute(self, request: ExecRequest, worker_token: str) -> ExecutionResult: ...


@runtime_checkable
class ScreenCapturer(Protocol):
    def capture(self, *, scope: str, workdir: str | None = None) -> CaptureResult: ...


@runtime_checkable
class DeliverablesProtocol(Protocol):
    def build_writeup(self, task: TaskRecord) -> ExportInfo: ...

    def export_evidence_zip(self, task: TaskRecord) -> ExportInfo: ...


@runtime_checkable
class ManagerControl(Protocol):
    """Manager control API exposed through MCP tool calls."""

    def create_task(
        self,
        *,
        title: str,
        category: str,
        conversation_id: str,
        source: str = "",
        scope_profile: str = "",
        notes: str = "",
    ) -> TaskRecord: ...

    def list_tasks(self, *, status: str | None = None, conversation_id: str | None = None) -> list[TaskRecord]: ...

    def get_task(self, task_id: str) -> TaskRecord: ...

    def get_task_status(self, task_id: str) -> dict[str, Any]: ...

    def continue_task(self, task_id: str, message: str = "") -> dict[str, Any]: ...

    def pause_task(self, task_id: str, reason: str = "") -> dict[str, Any]: ...

    def cancel_task(self, task_id: str, reason: str = "") -> dict[str, Any]: ...

    def request_approval(
        self,
        task_id: str,
        *,
        action_kind: str,
        details: dict[str, Any],
        ttl_s: int | None = None,
    ) -> ApprovalRecord: ...

    def decide_approval(
        self,
        approval_id: str,
        *,
        approved: bool,
        approver: str,
        note: str = "",
    ) -> ApprovalRecord: ...

    def list_approvals(self, *, task_id: str | None = None) -> list[ApprovalRecord]: ...

    def create_network_grant(
        self,
        task_id: str,
        *,
        competition_profile: str,
        host: str,
        port: int,
        protocol: str = "tcp",
        method: str = "GET",
        path_prefix: str = "/",
        ttl_s: int = 3600,
        max_calls: int = 10,
        approver: str,
    ) -> GrantRecord: ...

    def revoke_grant(self, grant_id: str) -> GrantRecord: ...

    def list_grants(self, *, task_id: str | None = None) -> list[GrantRecord]: ...

    def record_candidate_flag(self, task_id: str, *, flag: str, source: str) -> dict[str, Any]: ...

    def take_screenshot(
        self,
        task_id: str,
        *,
        step_id: str | None = None,
        scope: str = "desktop",
    ) -> ScreenshotRecord: ...

    def ingest_session_log(
        self,
        task_id: str,
        *,
        path: str,
        worker_id: str | None = None,
    ) -> dict[str, Any]: ...

    def export_events(self, task_id: str) -> ExportInfo: ...

    def build_writeup(self, task_id: str) -> ExportInfo: ...

    def export_evidence_zip(self, task_id: str) -> ExportInfo: ...

    def recover(self) -> dict[str, Any]: ...

    def runtime_status(self) -> dict[str, Any]: ...

    def shutdown(self) -> None: ...
