"""Manager service: Task/Worker lifecycle, FIFO scheduling, control API and IPC.

The Manager is the authoritative control plane. It is not a second model loop:
it creates ACP sessions, persists mappings, schedules at most two Workers,
enforces the state machine, delegates execution to the Broker/Runtime pipeline,
and delegates evidence/delivery to the evidence store and deliverables.
"""

from __future__ import annotations

import sys
import threading
import uuid
from pathlib import Path
from typing import Any

from ..core.canonical import canonical_json, sha256_hex, sha256_text
from ..core.config import SolverConfig
from ..core.errors import (
    AcpError,
    ConfigError,
    DenyReason,
    IpcError,
    NotFoundError,
    StateError,
    StorageError,
    ValidationError,
)
from ..core.ids import new_id, new_worker_token, validate_step_id
from ..core.paths import is_within
from ..core.protocols import (
    AcpClientFactory,
    AcpSessionClient,
    Clock,
    DeliverablesProtocol,
    EvidenceSink,
    ExecutionPipelineProtocol,
    ManagerControl,
    ScreenCapturer,
    SystemClock,
)
from ..core.types import (
    ApprovalAction,
    ApprovalRecord,
    ApprovalStatus,
    CaptureStatus,
    Category,
    ExecRequest,
    ExecutionResult,
    ExportInfo,
    FlagState,
    GrantRecord,
    GrantStatus,
    ScreenshotRecord,
    TaskRecord,
    TaskStatus,
    WorkerRecord,
    WorkerStatus,
)
from .ipc import ManagerIpcServer
from .scheduler import Scheduler
from .store import ManagerStore

ROUND1_LIMITS = {
    "model_calls": "blocked (no session/prompt; ADR-020)",
    "untrusted_challenge_code": "blocked (Tier 2 OS isolation unavailable)",
    "real_ctf_targets": "blocked (synthetic data only in this round)",
    "main_conversation_entrypoint": "BLOCKED pending a supported project-scoped Manager tool path (Round 2)",
    "session_log_negative_delivery_test": "BLOCKED (requires a model request)",
}


class ManagerService(ManagerControl):
    def __init__(
        self,
        config: SolverConfig,
        store: ManagerStore,
        acp_factory: AcpClientFactory | None,
        evidence: EvidenceSink | Any,
        pipeline: ExecutionPipelineProtocol,
        deliverables: DeliverablesProtocol,
        capturer: ScreenCapturer,
        clock: Clock | None = None,
    ) -> None:
        self.config = config
        self.store = store
        self.acp_factory = acp_factory
        self.evidence = evidence
        self.pipeline = pipeline
        self.deliverables = deliverables
        self.capturer = capturer
        self.clock = clock or SystemClock()
        self.scheduler = Scheduler(config.max_active_workers)
        self._lock = threading.RLock()
        self._acp: AcpSessionClient | None = None
        self._acp_ready = False
        self._acp_error = ""
        self._ipc: ManagerIpcServer | None = None
        self._started = False
        self._event_errors: list[str] = []
        self._session_updates: dict[str, list[dict[str, Any]]] = {}

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    @property
    def ipc_url(self) -> str | None:
        return self._ipc.url if self._ipc is not None else None

    def start(self) -> dict[str, Any]:
        with self._lock:
            if self._started:
                return self.runtime_status()
            paths = self.config.ensure_layout()
            self._ipc = ManagerIpcServer(self, host="127.0.0.1", port=0)
            self._ipc.start()
            if self.acp_factory is None:
                self._acp_error = "no ACP client factory configured"
            else:
                try:
                    self._acp = self.acp_factory()
                    self._acp.set_permission_handler(self._on_permission_request)
                    self._acp.set_session_update_handler(self._on_session_update)
                    self._acp.start()
                    self._acp_ready = True
                except Exception as exc:  # noqa: BLE001 - control plane stays usable
                    self._acp_ready = False
                    self._acp_error = f"{type(exc).__name__}: {exc}"
            self._started = True
            self.recover()
            self.pump()
            status = self.runtime_status()
            status["paths"] = {
                "root": str(paths.root),
                "db": str(paths.db_path),
                "cas": str(paths.cas_dir),
                "tasks": str(paths.tasks_dir),
            }
            return status

    def shutdown(self) -> None:
        with self._lock:
            ipc = self._ipc
            self._ipc = None
            acp = self._acp
            self._acp = None
            self._acp_ready = False
            self._started = False
        if ipc is not None:
            ipc.stop()
        if acp is not None:
            try:
                acp.stop(timeout_s=self.config.stop_timeout_s)
            except Exception:  # noqa: BLE001
                pass
        close_evidence = getattr(self.evidence, "close", None)
        if callable(close_evidence):
            try:
                close_evidence()
            except Exception:  # noqa: BLE001
                pass

    # ACP callbacks -----------------------------------------------------

    def _on_permission_request(self, params: dict[str, Any]) -> dict[str, Any]:
        """Round 1 policy: reject ACP host-tool permission requests.

        Worker execution goes through the typed ``ctf-exec`` MCP server and the
        Manager Broker, never through arbitrary ACP host tools. A rejected
        request is recorded for diagnostics; it is not silently allowed.
        """

        try:
            self._emit(
                params.get("sessionId") or "",
                "acp_permission_rejected",
                {"session_id": params.get("sessionId"), "tool_call": params.get("toolCall")},
            )
        except Exception:  # noqa: BLE001
            pass
        return {"outcome": {"outcome": "cancelled"}}

    def _on_session_update(self, params: dict[str, Any]) -> None:
        session_id = str(params.get("sessionId", ""))
        bucket = self._session_updates.setdefault(session_id, [])
        bucket.append(params)
        if len(bucket) > 200:
            del bucket[:100]

    # ------------------------------------------------------------------
    # Evidence helpers
    # ------------------------------------------------------------------

    def _emit(
        self,
        task_id: str,
        event_type: str,
        payload: dict[str, Any],
        *,
        worker_id: str | None = None,
        session_id: str | None = None,
    ) -> None:
        try:
            self.evidence.append_event(
                task_id=task_id,
                worker_id=worker_id,
                session_id=session_id,
                source="manager",
                source_id=f"manager:{event_type}:{uuid.uuid4().hex}",
                event_type=event_type,
                payload=payload,
                timestamp=self.clock.now_ms(),
            )
        except Exception as exc:  # noqa: BLE001 - evidence failures are recorded, not hidden
            self._event_errors.append(f"{event_type}: {type(exc).__name__}: {exc}")
            return
        self._refresh_evidence_head(task_id)

    def _refresh_evidence_head(self, task_id: str) -> None:
        """Persist the current evidence-chain head on the durable Task row."""

        try:
            chain_head = self.evidence.chain_head()
        except Exception:  # noqa: BLE001
            return
        head_hash = chain_head[1] if isinstance(chain_head, tuple) and len(chain_head) == 2 else None
        if not head_hash:
            return
        try:
            task = self.store.get_task(task_id)
            if task is not None and task.evidence_head != head_hash:
                self.store.update_task_fields(task_id, evidence_head=head_hash)
        except Exception as exc:  # noqa: BLE001
            self._event_errors.append(f"evidence_head {task_id}: {exc}")

    # ------------------------------------------------------------------
    # Scheduling
    # ------------------------------------------------------------------

    def pump(self) -> None:
        with self._lock:
            if not self._started or not self._acp_ready or self._acp is None:
                return
            if not self._acp.is_alive():
                self.handle_acp_failure("ACP server process exited unexpectedly")
                return
            active = self.store.count_active_slots()
            queued = self.store.list_queued()
            for task in self.scheduler.admit(active, queued):
                try:
                    self._start_task(task)
                except Exception as exc:  # noqa: BLE001 - one failure must not corrupt others
                    self._fail_start(task.task_id, f"{type(exc).__name__}: {exc}")
                    continue
                active = self.store.count_active_slots()

    def _worker_mcp_spec(self, worker_token: str) -> list[dict[str, Any]]:
        ipc_url = self.ipc_url
        if not ipc_url:
            raise ConfigError("Manager IPC endpoint is not started; cannot provide ctf-exec MCP server")
        return [
            {
                "name": "ctf-exec",
                "command": sys.executable,
                "args": ["-m", "ctf_solver.mcp.exec_server"],
                "env": {
                    "CTF_SOLVER_IPC_URL": ipc_url,
                    "CTF_SOLVER_WORKER_TOKEN": worker_token,
                    "PYTHONPATH": str(Path(__file__).resolve().parents[2]),
                    "PYTHONUTF8": "1",
                },
                "cwd": "",
            }
        ]

    def _start_task(self, task: TaskRecord) -> None:
        workspace = Path(task.workspace_path)
        workspace.mkdir(parents=True, exist_ok=True)
        self.store.set_task_status(task.task_id, TaskStatus.STARTING)
        worker_id = new_id("w")
        worker_token = new_worker_token()
        mcp_servers = self._worker_mcp_spec(worker_token)
        mcp_servers[0]["cwd"] = str(workspace)
        assert self._acp is not None
        result = self._acp.new_session(cwd=str(workspace.resolve()), mcp_servers=mcp_servers)
        if not isinstance(result, dict) or not result.get("sessionId"):
            raise StorageError(f"ACP session/new returned no sessionId: {result!r}")
        session_id = str(result["sessionId"])
        now = self.clock.now_ms()
        worker = WorkerRecord(
            worker_id=worker_id,
            task_id=task.task_id,
            acp_session_id=session_id,
            workspace_path=str(workspace),
            status=WorkerStatus.READY,
            worker_token=worker_token,
            created_at=now,
            updated_at=now,
        )
        self.store.activate_task(task.task_id, worker=worker)
        self.store.set_worker_status(worker_id, WorkerStatus.RUNNING)
        self._emit(
            task.task_id,
            "task_started",
            {
                "worker_id": worker_id,
                "session_id": session_id,
                "workspace": str(workspace),
                "mcp_server": "ctf-exec",
            },
            worker_id=worker_id,
            session_id=session_id,
        )

    def _fail_start(self, task_id: str, reason: str) -> None:
        try:
            task = self.store.get_task(task_id)
            if task is None:
                return
            if task.status in {TaskStatus.QUEUED, TaskStatus.STARTING}:
                self.store.set_task_status(
                    task_id,
                    TaskStatus.FAILED,
                    result_state="start_failed",
                    ended_at=self.clock.now_ms(),
                    notes=reason[:2000],
                )
                self._emit(task_id, "task_failed", {"reason": reason, "phase": "start"})
        except Exception:  # noqa: BLE001
            pass

    def handle_acp_failure(self, reason: str) -> dict[str, Any]:
        interrupted: list[str] = []
        with self._lock:
            self._acp_ready = False
            self._acp_error = reason
            for task in self.store.list_active_tasks():
                try:
                    worker = self.store.get_worker_for_task(task.task_id)
                    if worker is not None:
                        self.store.set_worker_status(worker.worker_id, WorkerStatus.CRASHED)
                    self.store.set_task_status(
                        task.task_id,
                        TaskStatus.INTERRUPTED,
                        result_state="acp_failure",
                        ended_at=self.clock.now_ms(),
                        notes=reason[:2000],
                    )
                    self._emit(
                        task.task_id,
                        "task_interrupted",
                        {"reason": reason, "quiescent": False},
                        worker_id=worker.worker_id if worker else None,
                    )
                    interrupted.append(task.task_id)
                except Exception as exc:  # noqa: BLE001
                    self._event_errors.append(f"interrupt {task.task_id}: {exc}")
        return {"interrupted": interrupted, "reason": reason}

    def recover(self) -> dict[str, Any]:
        """Reload durable state; never create duplicate sessions for a Task."""

        recovered: list[dict[str, Any]] = []
        with self._lock:
            for task in self.store.list_active_tasks():
                worker = self.store.get_worker_for_task(task.task_id)
                if worker is not None:
                    try:
                        self.store.set_worker_status(worker.worker_id, WorkerStatus.STOPPED)
                    except Exception:  # noqa: BLE001
                        pass
                previous = task.status.value
                try:
                    self.store.set_task_status(
                        task.task_id,
                        TaskStatus.INTERRUPTED,
                        result_state="recovered_interrupted",
                        ended_at=self.clock.now_ms(),
                        notes=(
                            "Manager restart: the previous ACP server process no longer exists; "
                            "the Task was NOT resumed or duplicated in Round 1."
                        ),
                    )
                    self._emit(
                        task.task_id,
                        "task_interrupted",
                        {"reason": "manager_restart", "previous_status": previous, "resumed": False},
                        worker_id=worker.worker_id if worker else None,
                    )
                except StateError as exc:
                    self._event_errors.append(f"recover {task.task_id}: {exc}")
                recovered.append(
                    {
                        "task_id": task.task_id,
                        "previous_status": previous,
                        "status": TaskStatus.INTERRUPTED.value,
                        "session_duplicate_created": False,
                    }
                )
            queued = [task.task_id for task in self.store.list_queued()]
        return {"interrupted": recovered, "queued": queued}

    # ------------------------------------------------------------------
    # Control API: Tasks
    # ------------------------------------------------------------------

    def create_task(
        self,
        *,
        title: str,
        category: str,
        conversation_id: str,
        source: str = "",
        scope_profile: str = "",
        notes: str = "",
        supplied_files: list[str] | None = None,
    ) -> TaskRecord:
        if not str(title).strip():
            raise ValidationError("Task title must not be empty")
        if not str(conversation_id).strip():
            raise ValidationError("Task conversation_id must not be empty")
        parsed_category = Category.parse(category)
        task_id = new_id("t")
        workspace = self.config.paths.task_workspace(task_id)
        workspace.mkdir(parents=True, exist_ok=True)
        now = self.clock.now_ms()
        record = TaskRecord(
            task_id=task_id,
            conversation_id=str(conversation_id),
            title=str(title).strip(),
            category=parsed_category,
            workspace_path=str(workspace),
            source=str(source),
            scope_profile=str(scope_profile),
            status=TaskStatus.CREATED,
            created_at=now,
            updated_at=now,
            notes=str(notes),
        )
        self.store.create_task(record)
        self._emit(
            task_id,
            "task_created",
            {
                "title": record.title,
                "category": record.category.value,
                "conversation_id": record.conversation_id,
                "source": record.source,
                "scope_profile": record.scope_profile,
                "supplied_files": list(supplied_files or []),
            },
        )
        self.store.set_task_status(task_id, TaskStatus.QUEUED)
        self.pump()
        return self.store.require_task(task_id)

    def list_tasks(
        self, *, status: str | None = None, conversation_id: str | None = None
    ) -> list[TaskRecord]:
        return self.store.list_tasks(status=status, conversation_id=conversation_id)

    def get_task(self, task_id: str) -> TaskRecord:
        return self.store.require_task(task_id)

    def get_task_status(self, task_id: str) -> dict[str, Any]:
        self._refresh_evidence_head(task_id)
        task = self.store.require_task(task_id)
        worker = self.store.get_worker_for_task(task_id)
        queued = self.store.list_queued()
        chain_head = (0, "")
        chain_status: dict[str, Any] | None = None
        try:
            chain_head = self.evidence.chain_head()
            chain_status = self.evidence.chain_status().to_dict()
        except Exception:  # noqa: BLE001
            pass
        return {
            "task": task.to_dict(),
            "worker": worker.to_dict() if worker is not None else None,
            "queue_position": self.scheduler.queue_position(task_id, queued),
            "approvals": [record.to_dict() for record in self.store.list_approvals(task_id=task_id)],
            "grants": [record.to_dict() for record in self.store.list_grants(task_id=task_id)],
            "executions": self.store.list_executions(task_id, limit=10),
            "screenshots": [
                record.to_dict() for record in self.store.list_screenshots(task_id)
            ],
            "evidence": {
                "chain_head_seq": chain_head[0] if chain_head else 0,
                "chain_head_hash": chain_head[1] if chain_head else "",
                "chain_status": chain_status,
            },
        }

    def continue_task(self, task_id: str, message: str = "") -> dict[str, Any]:
        task = self.store.require_task(task_id)
        if task.status in {
            TaskStatus.CANCELLED,
            TaskStatus.COMPLETED,
            TaskStatus.PARTIAL,
            TaskStatus.FAILED,
            TaskStatus.INTERRUPTED,
        }:
            raise StateError(f"Task {task_id} is terminal ({task.status.value}) and cannot continue")
        self._emit(
            task_id,
            "model_call_suppressed",
            {
                "message_length": len(message or ""),
                "round": 1,
                "reason": "session/prompt is not authorized in Round 1 (ADR-020)",
            },
            worker_id=task.worker_id,
            session_id=task.acp_session_id,
        )
        return {
            "task_id": task_id,
            "accepted": True,
            "model_call_suppressed": True,
            "message_length": len(message or ""),
            "status": task.status.value,
            "acp_session_id": task.acp_session_id,
            "note": (
                "Round 1 records the continuation and does not issue session/prompt or any "
                "model call; model-mediated continuation is a Round 2 gate."
            ),
        }

    def pause_task(self, task_id: str, reason: str = "") -> dict[str, Any]:
        with self._lock:
            task = self.store.require_task(task_id)
            if task.status is TaskStatus.QUEUED:
                raise StateError("a queued Task cannot be paused; it is not running")
            if task.status is not TaskStatus.RUNNING:
                raise StateError(f"only a running Task can be paused (status={task.status.value})")
            worker = self.store.get_worker_for_task(task_id)
            if worker is None:
                raise StateError(f"Task {task_id} has no Worker session to pause")
            if self._acp is None or not self._acp_ready:
                raise AcpError("ACP client is not available; cannot request pause")
            self._acp.cancel_session(worker.acp_session_id)
            self.store.set_worker_status(worker.worker_id, WorkerStatus.READY)
            self.store.set_task_status(task_id, TaskStatus.PAUSED, notes=f"pause: {reason}"[:2000])
            self._emit(
                task_id,
                "task_paused",
                {"reason": reason, "session_id": worker.acp_session_id, "os_kill": False},
                worker_id=worker.worker_id,
                session_id=worker.acp_session_id,
            )
            return {
                "task_id": task_id,
                "status": TaskStatus.PAUSED.value,
                "session_id": worker.acp_session_id,
                "os_kill": False,
                "note": "ACP cancel stops the current turn; it is not an OS process kill.",
            }

    def cancel_task(self, task_id: str, reason: str = "") -> dict[str, Any]:
        with self._lock:
            task = self.store.require_task(task_id)
            if task.status in {
                TaskStatus.CANCELLED,
                TaskStatus.COMPLETED,
                TaskStatus.PARTIAL,
                TaskStatus.FAILED,
            }:
                raise StateError(f"Task {task_id} is already terminal ({task.status.value})")
            if task.status is TaskStatus.QUEUED:
                self.store.set_task_status(
                    task_id, TaskStatus.CANCELLED, ended_at=self.clock.now_ms()
                )
                self._emit(task_id, "task_cancelled", {"reason": reason, "quiescent": True})
                self.pump()
                return {"task_id": task_id, "status": TaskStatus.CANCELLED.value, "quiescent": True}
            if task.status is TaskStatus.CREATED:
                self.store.set_task_status(task_id, TaskStatus.CANCELLED, ended_at=self.clock.now_ms())
                return {"task_id": task_id, "status": TaskStatus.CANCELLED.value, "quiescent": True}
            if task.status is TaskStatus.STARTING:
                self.store.set_task_status(
                    task_id, TaskStatus.CANCELLED, ended_at=self.clock.now_ms(), notes=reason[:2000]
                )
                self._emit(task_id, "task_cancelled", {"reason": reason, "quiescent": True})
                self.pump()
                return {"task_id": task_id, "status": TaskStatus.CANCELLED.value, "quiescent": True}

            if task.status is not TaskStatus.CANCEL_REQUESTED:
                self.store.set_task_status(
                    task_id, TaskStatus.CANCEL_REQUESTED, notes=f"cancel: {reason}"[:2000]
                )
                self._emit(task_id, "task_cancel_requested", {"reason": reason})
            worker = self.store.get_worker_for_task(task_id)
            diagnostics: dict[str, Any] = {}
            quiescent = False
            if worker is not None and self._acp is not None:
                try:
                    self._acp.cancel_session(worker.acp_session_id)
                except AcpError as exc:
                    diagnostics["cancel_error"] = str(exc)
                try:
                    self._acp.close_session(worker.acp_session_id)
                    quiescent = True
                except AcpError as exc:
                    diagnostics["close_error"] = str(exc)
            elif worker is None:
                quiescent = True
            if quiescent:
                worker_id = worker.worker_id if worker else None
                if worker is not None:
                    try:
                        self.store.set_worker_status(worker.worker_id, WorkerStatus.STOPPED)
                    except Exception:  # noqa: BLE001
                        pass
                self.store.set_task_status(
                    task_id, TaskStatus.CANCELLED, ended_at=self.clock.now_ms()
                )
                self._emit(
                    task_id,
                    "task_cancelled",
                    {"reason": reason, "quiescent": True, "os_kill": False},
                    worker_id=worker_id,
                    session_id=worker.acp_session_id if worker else None,
                )
                self.pump()
                return {
                    "task_id": task_id,
                    "status": TaskStatus.CANCELLED.value,
                    "quiescent": True,
                    "diagnostics": diagnostics,
                    "note": "ACP cancel/close confirmed; no OS process kill was used.",
                }
            return {
                "task_id": task_id,
                "status": TaskStatus.CANCEL_REQUESTED.value,
                "quiescent": False,
                "diagnostics": diagnostics,
                "note": (
                    "Cancellation is NOT confirmed: session close failed. The Worker slot stays "
                    "held until quiescence is verified."
                ),
            }

    # ------------------------------------------------------------------
    # Control API: approvals / grants / flag
    # ------------------------------------------------------------------

    def request_approval(
        self,
        task_id: str,
        *,
        action_kind: str,
        details: dict[str, Any],
        ttl_s: int | None = None,
    ) -> ApprovalRecord:
        self.store.require_task(task_id)
        try:
            kind = ApprovalAction(str(action_kind))
        except ValueError as exc:
            raise ValidationError(f"unknown approval action_kind: {action_kind!r}") from exc
        digest = sha256_hex(canonical_json({"action_kind": kind.value, "details": details}).encode("utf-8"))
        now = self.clock.now_ms()
        record = ApprovalRecord(
            approval_id=new_id("apr"),
            task_id=task_id,
            action_kind=kind.value,
            action_digest=digest,
            status=ApprovalStatus.PENDING,
            requested_at=now,
            payload=dict(details),
            expires_at=(now + int(ttl_s) * 1000) if ttl_s else None,
        )
        self.store.create_approval(record)
        self._emit(
            task_id,
            "approval_requested",
            {
                "approval_id": record.approval_id,
                "action_kind": record.action_kind,
                "action_digest": record.action_digest,
                "expires_at": record.expires_at,
            },
        )
        return record

    def decide_approval(
        self, approval_id: str, *, approved: bool, approver: str, note: str = ""
    ) -> ApprovalRecord:
        record = self.store.decide_approval(
            approval_id, approved=approved, approver=approver, note=note
        )
        self._emit(
            record.task_id,
            "approval_decided",
            {
                "approval_id": record.approval_id,
                "action_kind": record.action_kind,
                "action_digest": record.action_digest,
                "approved": record.status is ApprovalStatus.APPROVED,
                "approver": record.approver,
            },
        )
        return record

    def list_approvals(self, *, task_id: str | None = None) -> list[ApprovalRecord]:
        return self.store.list_approvals(task_id=task_id)

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
        approver: str = "",
    ) -> GrantRecord:
        self.store.require_task(task_id)
        if not str(host).strip():
            raise ValidationError("network grant host must not be empty")
        if not 1 <= int(port) <= 65535:
            raise ValidationError("network grant port must be within 1..65535")
        if int(ttl_s) <= 0 or int(max_calls) <= 0:
            raise ValidationError("network grant ttl_s and max_calls must be positive")
        if not str(approver).strip():
            raise ValidationError("network grant requires an explicit human approver")
        if not str(path_prefix).startswith("/"):
            raise ValidationError("network grant path_prefix must start with '/'")
        now = self.clock.now_ms()
        grant = GrantRecord(
            grant_id=new_id("grant"),
            task_id=task_id,
            competition_profile=str(competition_profile),
            host=str(host).strip().lower(),
            port=int(port),
            protocol=str(protocol).lower(),
            method=str(method).upper(),
            path_prefix=str(path_prefix),
            expires_at=now + int(ttl_s) * 1000,
            max_calls=int(max_calls),
            approver=str(approver),
            created_at=now,
            status=GrantStatus.ACTIVE,
        )
        grant.grant_digest = sha256_hex(
            canonical_json(
                {
                    "task_id": task_id,
                    "profile": grant.competition_profile,
                    "host": grant.host,
                    "port": grant.port,
                    "protocol": grant.protocol,
                    "method": grant.method,
                    "path_prefix": grant.path_prefix,
                    "expires_at": grant.expires_at,
                    "max_calls": grant.max_calls,
                    "approver": grant.approver,
                }
            ).encode("utf-8")
        )
        self.store.create_grant(grant)
        self._emit(
            task_id,
            "grant_created",
            {
                "grant_id": grant.grant_id,
                "host": grant.host,
                "port": grant.port,
                "protocol": grant.protocol,
                "method": grant.method,
                "expires_at": grant.expires_at,
                "max_calls": grant.max_calls,
                "profile": grant.competition_profile,
            },
        )
        return grant

    def revoke_grant(self, grant_id: str) -> GrantRecord:
        grant = self.store.set_grant_status(grant_id, GrantStatus.REVOKED)
        self._emit(grant.task_id, "grant_revoked", {"grant_id": grant_id, "reason": "revoked_by_user"})
        return grant

    def list_grants(self, *, task_id: str | None = None) -> list[GrantRecord]:
        return self.store.list_grants(task_id=task_id)

    def record_candidate_flag(self, task_id: str, *, flag: str, source: str) -> dict[str, Any]:
        task = self.store.require_task(task_id)
        if task.status in {
            TaskStatus.CANCELLED,
            TaskStatus.COMPLETED,
            TaskStatus.PARTIAL,
            TaskStatus.FAILED,
            TaskStatus.INTERRUPTED,
        }:
            raise StateError(f"Task {task_id} is terminal ({task.status.value})")
        if not str(flag).strip():
            raise ValidationError("candidate Flag must not be empty")
        digest = sha256_text(str(flag))
        self.store.record_flag_candidate(task_id, flag_digest=digest, flag_value=str(flag))
        self._emit(
            task_id,
            "flag_candidate",
            {
                "flag_sha256": digest,
                "source": str(source),
                "flag_state": FlagState.CANDIDATE.value,
                "submitted": False,
            },
        )
        return {
            "task_id": task_id,
            "flag_state": FlagState.CANDIDATE.value,
            "flag_sha256": digest,
            "source": str(source),
            "submitted": False,
            "note": "Candidate only. The user confirms and submits the Flag; no submission was made.",
        }

    # ------------------------------------------------------------------
    # Control API: screenshots / evidence / delivery
    # ------------------------------------------------------------------

    def take_screenshot(
        self, task_id: str, *, step_id: str | None = None, scope: str = "desktop"
    ) -> ScreenshotRecord:
        task = self.store.require_task(task_id)
        if step_id is not None:
            validate_step_id(step_id)
        worker = self.store.get_worker_for_task(task_id)
        result = self.capturer.capture(scope=scope, workdir=task.workspace_path)
        now = self.clock.now_ms()
        screenshot_id = new_id("shot")
        record = ScreenshotRecord(
            screenshot_id=screenshot_id,
            task_id=task_id,
            worker_id=worker.worker_id if worker else task.worker_id,
            step_id=step_id,
            session_id=task.acp_session_id,
            scope=scope,
            captured_at=result.captured_at or now,
            status=result.status,
            width=result.width or None,
            height=result.height or None,
            failure_reason=result.error if result.status is not CaptureStatus.OK else "",
        )
        if result.status is CaptureStatus.OK:
            artifact = self.evidence.store_artifact(
                result.png_bytes, media_type="image/png", source=f"screenshot:{task_id}"
            )
            record.sha256 = artifact.sha256
        else:
            record.sha256 = None
            if result.status is CaptureStatus.BLANK:
                record.failure_reason = (
                    record.failure_reason
                    or "blank capture rejected (no spatial variation); not stored as evidence"
                )
        self.store.record_screenshot(record)
        record_screenshot = getattr(self.evidence, "record_screenshot", None)
        if callable(record_screenshot):
            try:
                record_screenshot(record)
            except Exception as exc:  # noqa: BLE001 - screenshot metadata is already in the store
                self._event_errors.append(f"screenshot record: {exc}")
        event_type = "screenshot_captured" if result.status is CaptureStatus.OK else "screenshot_failed"
        self._emit(
            task_id,
            event_type,
            {
                "screenshot_id": screenshot_id,
                "sha256": record.sha256,
                "width": record.width,
                "height": record.height,
                "scope": scope,
                "status": record.status.value,
                "failure_reason": record.failure_reason,
                "step_id": step_id,
            },
            worker_id=record.worker_id,
            session_id=record.session_id,
        )
        return record

    def ingest_session_log(
        self, task_id: str, *, path: str, worker_id: str | None = None
    ) -> dict[str, Any]:
        task = self.store.require_task(task_id)
        log_path = Path(path)
        if not log_path.is_file():
            raise ValidationError(f"session log file not found: {path}")
        worker = self.store.get_worker_for_task(task_id)
        resolved_worker = worker_id or (worker.worker_id if worker else task.worker_id)
        session_id = task.acp_session_id or (worker.acp_session_id if worker else None)
        ingest = getattr(self.evidence, "ingest_session_log_file", None)
        if not callable(ingest):
            raise StorageError("evidence store does not support session-log ingestion")
        report = ingest(
            task_id=task_id,
            worker_id=resolved_worker,
            session_id=session_id,
            path=str(log_path),
        )
        payload = report.to_dict() if hasattr(report, "to_dict") else dict(report or {})
        self._emit(
            task_id,
            "evidence_ingested",
            {
                "path": str(log_path),
                "frames": payload.get("frames"),
                "records": payload.get("appended", payload.get("decoded_records")),
                "gaps": len(payload.get("gaps", []) or []),
                "raw_sha256": payload.get("raw_sha256"),
            },
            worker_id=resolved_worker,
            session_id=session_id,
        )
        return payload

    def export_events(self, task_id: str) -> ExportInfo:
        task = self.store.require_task(task_id)
        out_path = self.config.paths.task_evidence_dir(task_id) / "events.jsonl"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        info = self.evidence.export_events_jsonl(task_id=task_id, out_path=str(out_path))
        self.store.record_export(info)
        return info

    def build_writeup(self, task_id: str) -> ExportInfo:
        self._refresh_evidence_head(task_id)
        task = self.store.require_task(task_id)
        return self.deliverables.build_writeup(task)

    def export_evidence_zip(self, task_id: str) -> ExportInfo:
        self._refresh_evidence_head(task_id)
        task = self.store.require_task(task_id)
        return self.deliverables.export_evidence_zip(task)

    # ------------------------------------------------------------------
    # IPC surface
    # ------------------------------------------------------------------

    def ipc_worker_info(self, token: str) -> dict[str, Any]:
        worker = self.store.get_worker_by_token(token)
        if worker is None:
            raise IpcError(
                "invalid Worker token", reason_code=DenyReason.UNKNOWN_WORKER.value
            )
        task = self.store.get_task(worker.task_id)
        return {
            "worker_id": worker.worker_id,
            "task_id": worker.task_id,
            "session_id": worker.acp_session_id,
            "workspace": worker.workspace_path,
            "status": worker.status.value,
            "task_status": task.status.value if task else None,
        }

    def ipc_exec(self, token: str, params: dict[str, Any]) -> dict[str, Any]:
        worker = self.store.get_worker_by_token(token)
        if worker is None:
            raise IpcError(
                "invalid Worker token", reason_code=DenyReason.UNKNOWN_WORKER.value
            )
        request = ExecRequest.from_mapping(params)
        if request.worker_id != worker.worker_id or request.task_id != worker.task_id:
            raise IpcError(
                "Worker identity does not match the authenticated token",
                reason_code=DenyReason.WORKER_MISMATCH.value,
            )
        result = self.pipeline.execute(request, token)
        return result.to_dict()

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------

    def runtime_status(self) -> dict[str, Any]:
        acp_diagnostics: dict[str, Any] = {"state": "stopped"}
        alive = False
        if self._acp is not None:
            try:
                acp_diagnostics = self._acp.diagnostics()
                alive = self._acp.is_alive()
            except Exception as exc:  # noqa: BLE001
                acp_diagnostics = {"state": "error", "error": str(exc)}
        if self._started and self._acp is not None and not alive and self._acp_ready:
            self.handle_acp_failure("ACP server process is no longer alive")
            acp_diagnostics = {"state": "crashed", "error": self._acp_error}
        chain_head: Any = None
        try:
            chain_head = self.evidence.chain_head()
        except Exception:  # noqa: BLE001
            pass
        return {
            "acp": {
                "diagnostics": acp_diagnostics,
                "ready": self._acp_ready,
                "error": self._acp_error,
                "alive": alive,
            },
            "ipc_url": self.ipc_url,
            "active_workers": self.store.count_active_slots(),
            "queued_tasks": len(self.store.list_queued()),
            "db_path": str(self.config.paths.db_path),
            "cas_dir": str(self.config.paths.cas_dir),
            "chain_head": chain_head,
            "event_errors": list(self._event_errors[-10:]),
            "round1_limits": dict(ROUND1_LIMITS),
        }

    def close(self) -> None:
        self.shutdown()
        self.store.close()
