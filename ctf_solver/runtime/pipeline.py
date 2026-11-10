"""Broker + Runtime execution pipeline for typed ``ctf-exec``.

Flow (docs/INTERFACES.md section 5.3):

- every call is authorized by the Broker first; a denied call returns
  ``status=denied`` with the stable reason code, records an ``executions`` row
  and an ``execution_denied`` evidence event, and **never** touches the
  executor (a denied call is always distinguishable from a started process);
- an allowed call records a ``running`` executions row plus an
  ``execution_started`` event, executes, stores stdout/stderr bytes in CAS via
  the :class:`ctf_solver.core.protocols.EvidenceSink`, hashes requested output
  files into ``output_files``, then writes the final row/result and an
  ``execution_completed`` / ``execution_failed`` event;
- runtime evidence always uses ``source="runtime"``, ``source_id``
  ``execution:<execution_id>`` and ``source_seq`` 1 for start / 2 for finish.

The event payloads carry the frozen minimum key set from INTERFACES section
4.6 (``execution_id``, ``status``, ``exit_code``, ``reason_code``,
``stdout_sha256``, ``stderr_sha256``, ``stdout_preview``, ``stderr_preview``,
plus tool/argv/cwd/tier/step fields), with extra evidence keys allowed.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from ..core.canonical import canonical_json, file_sha256, sha256_hex
from ..core.errors import CtfSolverError, DenyReason
from ..core.ids import new_id
from ..core.paths import ensure_relative_safe, is_within, resolve_path
from ..core.protocols import Clock, EvidenceSink, PolicyRepository, SystemClock
from ..core.types import (
    BrokerDecision,
    ExecutionResult,
    ExecutionStatus,
    ExecRequest,
    RuntimeOutcome,
    WorkerRecord,
)
from ..policy.broker import Broker
from .executor import RuntimeExecutor
from .tools import ToolInvocation

__all__ = ["ExecutionPipeline", "PREVIEW_CHARS"]

#: Maximum characters of decoded stdout/stderr echoed in the response.
PREVIEW_CHARS = 4096

_SOURCE = "runtime"


def _preview(data: bytes) -> str:
    """Return a bounded, deterministic UTF-8 preview of captured bytes."""

    if not data:
        return ""
    text = data[: PREVIEW_CHARS * 4].decode("utf-8", errors="replace")
    if len(text) > PREVIEW_CHARS:
        return text[:PREVIEW_CHARS] + "\u2026[truncated]"
    return text


class ExecutionPipeline:
    """Authorize and execute one typed ``ctf-exec`` request."""

    def __init__(
        self,
        repository: PolicyRepository,
        evidence: EvidenceSink,
        broker: Broker,
        executor: RuntimeExecutor,
        clock: Clock | None = None,
    ) -> None:
        if repository is None or evidence is None:
            raise ValueError("ExecutionPipeline requires a repository and an evidence sink")
        if not isinstance(broker, Broker):
            raise ValueError("ExecutionPipeline requires a policy Broker")
        if not isinstance(executor, RuntimeExecutor):
            raise ValueError("ExecutionPipeline requires a RuntimeExecutor")
        self.repository = repository
        self.evidence = evidence
        self.broker = broker
        self.executor = executor
        self.clock: Clock = clock or SystemClock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def execute(self, request: ExecRequest, worker_token: str) -> ExecutionResult:
        execution_id = new_id("exec")
        decision = self._authorize(request, worker_token)
        worker = self._lookup_worker(worker_token)
        if not decision.allowed:
            return self._finish_denied(execution_id, request, decision, worker)
        return self._execute_allowed(execution_id, request, decision, worker)

    # ------------------------------------------------------------------
    # Denied path
    # ------------------------------------------------------------------

    def _finish_denied(
        self,
        execution_id: str,
        request: ExecRequest,
        decision: BrokerDecision,
        worker: WorkerRecord | None,
    ) -> ExecutionResult:
        timestamp = self.clock.now_ms()
        tool_version = request.tool_version
        # No execution tier was granted (the call never ran), so the audit row
        # records the tier the caller requested rather than a granted tier.
        tier = int(request.tier)
        result = ExecutionResult(
            execution_id=execution_id,
            task_id=request.task_id,
            worker_id=request.worker_id,
            step_id=request.step_id,
            tool_name=request.tool_name,
            tool_version=tool_version,
            argv=list(request.argv),
            cwd=request.cwd,
            status=ExecutionStatus.DENIED,
            started_at=timestamp,
            ended_at=timestamp,
            exit_code=None,
            input_files=[dict(item) for item in request.input_files],
            output_files=[],
            stdout_sha256=None,
            stderr_sha256=None,
            stdout_preview="",
            stderr_preview="",
            screenshot_paths=[],
            network_grant_id=request.network_grant_id,
            approval_id=request.approval_id,
            reason_code=decision.reason_code,
            reason=decision.reason,
            request=request.to_dict(),
        )
        warnings = self._record_execution(
            self._execution_row(
                execution_id=execution_id,
                request=request,
                tool_version=tool_version,
                tier=tier,
                status=ExecutionStatus.DENIED.value,
                started_at=timestamp,
                ended_at=timestamp,
                exit_code=None,
                reason_code=decision.reason_code,
                reason=decision.reason,
                stdout_sha256=None,
                stderr_sha256=None,
                stdout_preview="",
                stderr_preview="",
                result_json=canonical_json(result.to_dict()),
            )
        )
        payload = self._event_payload(
            execution_id=execution_id,
            status=ExecutionStatus.DENIED.value,
            request=request,
            tool_version=tool_version,
            tier=tier,
            exit_code=None,
            reason_code=decision.reason_code,
            stdout_sha256=None,
            stderr_sha256=None,
            stdout_preview="",
            stderr_preview="",
            extra={
                "reason": decision.reason,
                "denied": True,
                "network_grant_id": request.network_grant_id,
                "approval_id": request.approval_id,
                "storage_warnings": warnings,
            },
        )
        self._append_event(
            task_id=request.task_id,
            worker=worker,
            source_seq=1,
            event_type="execution_denied",
            payload=payload,
            timestamp=timestamp,
            fallback_worker_id=request.worker_id,
        )
        return result

    # ------------------------------------------------------------------
    # Allowed path
    # ------------------------------------------------------------------

    def _execute_allowed(
        self,
        execution_id: str,
        request: ExecRequest,
        decision: BrokerDecision,
        worker: WorkerRecord | None,
    ) -> ExecutionResult:
        started_at = self.clock.now_ms()
        spec = self.broker.catalog.get(request.tool_name)
        decision_tool = decision.tool or {}
        tool_version = decision_tool.get("version") or request.tool_version or (
            spec.version if spec is not None else None
        )
        tier = int(decision.effective_tier)
        invocation = ToolInvocation(
            argv=list(request.argv),
            cwd=request.cwd,
            input_files=[dict(item) for item in request.input_files],
            output_paths=list(request.output_paths),
            timeout_s=float(request.timeout_s),
            max_output_bytes=request.max_output_bytes,
            request=request,
        )
        warnings = self._record_execution(
            self._execution_row(
                execution_id=execution_id,
                request=request,
                tool_version=tool_version,
                tier=tier,
                status="running",
                started_at=started_at,
                ended_at=None,
                exit_code=None,
                reason_code="",
                reason="",
                stdout_sha256=None,
                stderr_sha256=None,
                stdout_preview="",
                stderr_preview="",
                result_json="{}",
            )
        )
        start_payload = self._event_payload(
            execution_id=execution_id,
            status="running",
            request=request,
            tool_version=tool_version,
            tier=tier,
            exit_code=None,
            reason_code="",
            stdout_sha256=None,
            stderr_sha256=None,
            stdout_preview="",
            stderr_preview="",
            extra={
                "approval_id": decision.approval_id,
                "network_grant_id": decision.network_grant_id,
                "input_files": [dict(item) for item in request.input_files],
                "output_paths": list(request.output_paths),
                "timeout_s": float(request.timeout_s),
                "storage_warnings": warnings,
            },
        )
        self._append_event(
            task_id=request.task_id,
            worker=worker,
            source_seq=1,
            event_type="execution_started",
            payload=start_payload,
            timestamp=started_at,
            fallback_worker_id=request.worker_id,
        )

        outcome = self._run(spec, invocation, started_at)
        ended_at = outcome.ended_at or self.clock.now_ms()
        stdout_preview = _preview(outcome.stdout)
        stderr_preview = _preview(outcome.stderr)
        stdout_sha256 = sha256_hex(outcome.stdout)
        stderr_sha256 = sha256_hex(outcome.stderr)
        stdout_artifact = self.evidence.store_artifact(
            outcome.stdout,
            media_type="text/plain; charset=utf-8",
            source=f"execution:{execution_id}:stdout",
        )
        stderr_artifact = self.evidence.store_artifact(
            outcome.stderr,
            media_type="text/plain; charset=utf-8",
            source=f"execution:{execution_id}:stderr",
        )
        output_files = self._hash_output_files(request, worker)
        reason_code = ""
        result = ExecutionResult(
            execution_id=execution_id,
            task_id=request.task_id,
            worker_id=request.worker_id,
            step_id=request.step_id,
            tool_name=request.tool_name,
            tool_version=tool_version,
            argv=list(request.argv),
            cwd=request.cwd,
            status=outcome.status,
            started_at=started_at,
            ended_at=ended_at,
            exit_code=outcome.exit_code,
            input_files=[dict(item) for item in request.input_files],
            output_files=output_files,
            stdout_sha256=stdout_sha256,
            stderr_sha256=stderr_sha256,
            stdout_preview=stdout_preview,
            stderr_preview=stderr_preview,
            screenshot_paths=[],
            network_grant_id=decision.network_grant_id,
            approval_id=decision.approval_id,
            reason_code=reason_code,
            reason=outcome.error,
            request=request.to_dict(),
        )
        update_warnings = self._update_execution(
            execution_id,
            {
                "tool_version": tool_version,
                "status": result.status.value,
                "exit_code": result.exit_code,
                "reason_code": reason_code,
                "reason": result.reason,
                "ended_at": ended_at,
                "stdout_sha256": stdout_sha256,
                "stderr_sha256": stderr_sha256,
                "stdout_preview": stdout_preview,
                "stderr_preview": stderr_preview,
                "result_json": canonical_json(result.to_dict()),
            },
        )
        event_type = (
            "execution_completed"
            if result.status is ExecutionStatus.COMPLETED
            else "execution_failed"
        )
        finish_payload = self._event_payload(
            execution_id=execution_id,
            status=result.status.value,
            request=request,
            tool_version=tool_version,
            tier=tier,
            exit_code=result.exit_code,
            reason_code=reason_code,
            stdout_sha256=stdout_sha256,
            stderr_sha256=stderr_sha256,
            stdout_preview=stdout_preview,
            stderr_preview=stderr_preview,
            extra={
                "started_at": started_at,
                "ended_at": ended_at,
                "duration_ms": max(0, int(ended_at) - int(started_at)),
                "stdout_bytes": len(outcome.stdout),
                "stderr_bytes": len(outcome.stderr),
                "stdout_truncated": bool(outcome.stdout_truncated),
                "stderr_truncated": bool(outcome.stderr_truncated),
                "stdout_artifact": stdout_artifact.to_dict(),
                "stderr_artifact": stderr_artifact.to_dict(),
                "output_files": output_files,
                "error": outcome.error,
                "approval_id": decision.approval_id,
                "network_grant_id": decision.network_grant_id,
                "storage_warnings": update_warnings,
            },
        )
        self._append_event(
            task_id=request.task_id,
            worker=worker,
            source_seq=2,
            event_type=event_type,
            payload=finish_payload,
            timestamp=ended_at,
            fallback_worker_id=request.worker_id,
        )
        return result

    # ------------------------------------------------------------------
    # Execution helpers
    # ------------------------------------------------------------------

    def _authorize(self, request: ExecRequest, worker_token: str) -> BrokerDecision:
        try:
            return self.broker.authorize(request, worker_token)
        except Exception as exc:  # pragma: no cover - Broker already fails closed
            return BrokerDecision.deny(
                DenyReason.INTERNAL_ERROR,
                f"broker authorization failure: {type(exc).__name__}: {exc}",
            )

    def _run(
        self, spec: Any, invocation: ToolInvocation, started_at: int
    ) -> RuntimeOutcome:
        if spec is None:
            return RuntimeOutcome(
                status=ExecutionStatus.FAILED,
                started_at=started_at,
                ended_at=self.clock.now_ms(),
                error="tool is not present in the runtime catalogue",
            )
        try:
            outcome = self.executor.execute(spec, invocation)
        except Exception as exc:  # pragma: no cover - executor fails closed
            return RuntimeOutcome(
                status=ExecutionStatus.FAILED,
                started_at=started_at,
                ended_at=self.clock.now_ms(),
                error=f"runtime executor failure: {type(exc).__name__}: {exc}",
            )
        if not isinstance(outcome, RuntimeOutcome):
            return RuntimeOutcome(
                status=ExecutionStatus.FAILED,
                started_at=started_at,
                ended_at=self.clock.now_ms(),
                error="runtime executor returned an invalid outcome",
            )
        if not outcome.started_at:
            outcome.started_at = started_at
        if not outcome.ended_at:
            outcome.ended_at = self.clock.now_ms()
        return outcome

    def _hash_output_files(
        self, request: ExecRequest, worker: WorkerRecord | None
    ) -> list[dict[str, Any]]:
        try:
            base = resolve_path(request.cwd)
        except (OSError, ValueError):
            base = Path(request.cwd)
        if worker is not None and worker.workspace_path:
            try:
                root = resolve_path(worker.workspace_path)
            except (OSError, ValueError):
                root = base
        else:
            root = base
        entries: list[dict[str, Any]] = []
        for raw_path in request.output_paths:
            entry: dict[str, Any] = {
                "path": str(raw_path),
                "exists": False,
                "sha256": None,
                "size": 0,
            }
            try:
                relative = ensure_relative_safe(raw_path)
                candidate = resolve_path(str(base / relative))
            except (OSError, ValueError) as exc:
                entry["error"] = f"invalid output path: {exc}"
                entries.append(entry)
                continue
            if not is_within(candidate, root):
                entry["error"] = "outside_workspace"
                entries.append(entry)
                continue
            try:
                if not candidate.is_file():
                    entry["error"] = "missing"
                    entries.append(entry)
                    continue
                entry.update(
                    {
                        "exists": True,
                        "sha256": file_sha256(candidate),
                        "size": int(candidate.stat().st_size),
                        "relative_path": relative,
                    }
                )
            except OSError as exc:
                entry["error"] = f"unreadable: {exc}"
            entries.append(entry)
        return entries

    # ------------------------------------------------------------------
    # Evidence helpers
    # ------------------------------------------------------------------

    def _event_payload(
        self,
        *,
        execution_id: str,
        status: str,
        request: ExecRequest,
        tool_version: str | None,
        tier: int,
        exit_code: int | None,
        reason_code: str,
        stdout_sha256: str | None,
        stderr_sha256: str | None,
        stdout_preview: str,
        stderr_preview: str,
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            # Frozen minimum keys (INTERFACES section 4.6) plus the union the
            # Lead fixed for every runtime event.
            "execution_id": execution_id,
            "status": status,
            "tool_name": request.tool_name,
            "tool_version": tool_version,
            "argv": list(request.argv),
            "cwd": request.cwd,
            "tier": int(tier),
            "step_id": request.step_id,
            "exit_code": exit_code,
            "reason_code": reason_code,
            "stdout_sha256": stdout_sha256,
            "stderr_sha256": stderr_sha256,
            "stdout_preview": stdout_preview,
            "stderr_preview": stderr_preview,
            "task_id": request.task_id,
            "worker_id": request.worker_id,
            "request": request.to_dict(),
        }
        if extra:
            payload.update(extra)
        return payload

    def _append_event(
        self,
        *,
        task_id: str,
        worker: WorkerRecord | None,
        source_seq: int,
        event_type: str,
        payload: dict[str, Any],
        timestamp: int,
        fallback_worker_id: str | None = None,
    ) -> str:
        worker_id = worker.worker_id if worker is not None else fallback_worker_id
        session_id = worker.acp_session_id if worker is not None else None
        execution_id = str(payload["execution_id"])
        return self.evidence.append_event(
            task_id=task_id,
            worker_id=worker_id,
            session_id=session_id,
            source=_SOURCE,
            source_id=f"execution:{execution_id}",
            source_seq=source_seq,
            event_type=event_type,
            payload=payload,
            timestamp=timestamp,
        )

    def _lookup_worker(self, worker_token: str) -> WorkerRecord | None:
        if not isinstance(worker_token, str) or not worker_token:
            return None
        try:
            worker = self.repository.get_worker_by_token(worker_token)
        except (CtfSolverError, sqlite3.Error, OSError):
            return None
        return worker if isinstance(worker, WorkerRecord) else None

    # ------------------------------------------------------------------
    # Persistence helpers
    # ------------------------------------------------------------------

    def _execution_row(self, **values: Any) -> dict[str, Any]:
        request: ExecRequest = values.pop("request")
        row = {
            "execution_id": values["execution_id"],
            "task_id": request.task_id,
            "worker_id": request.worker_id,
            "step_id": request.step_id,
            "tool_name": request.tool_name,
            "tool_version": values["tool_version"],
            "argv_json": canonical_json(list(request.argv)),
            "cwd": request.cwd,
            "tier": values["tier"],
            "status": values["status"],
            "exit_code": values["exit_code"],
            "reason_code": values["reason_code"],
            "reason": values["reason"],
            "started_at": values["started_at"],
            "ended_at": values["ended_at"],
            "stdout_sha256": values["stdout_sha256"],
            "stderr_sha256": values["stderr_sha256"],
            "stdout_preview": values["stdout_preview"],
            "stderr_preview": values["stderr_preview"],
            "network_grant_id": request.network_grant_id,
            "approval_id": request.approval_id,
            "request_json": canonical_json(request.to_dict()),
            "result_json": values["result_json"],
        }
        return row

    def _record_execution(self, row: dict[str, Any]) -> list[str]:
        try:
            self.repository.record_execution(dict(row))
        except (CtfSolverError, sqlite3.Error, OSError) as exc:
            return [f"record_execution failed: {type(exc).__name__}: {exc}"]
        return []

    def _update_execution(self, execution_id: str, updates: dict[str, Any]) -> list[str]:
        try:
            self.repository.update_execution(execution_id, dict(updates))
        except (CtfSolverError, sqlite3.Error, OSError) as exc:
            return [f"update_execution failed: {type(exc).__name__}: {exc}"]
        return []
