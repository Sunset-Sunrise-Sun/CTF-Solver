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
from typing import Any, Mapping

from ..core.canonical import canonical_json, sha256_hex, sha256_text
from ..core.config import SolverConfig
from ..core.errors import (
    AcpError,
    AcpUnavailableError,
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
    SLOT_OCCUPYING_TASK_STATUSES,
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

ROUND2_SECURITY = {
    "approval_decide_via_mcp": "removed (model can only request approval)",
    "grant_create_via_mcp": "removed (requires a human-confirmed approval via local console)",
    "human_confirmation_channel": "local interactive console only (TTY required; non-TTY fails closed)",
    "session_log_ingest": "manager registry only (no model-supplied file path)",
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
        self._diagnostics: list[dict[str, Any]] = []
        self._session_updates: dict[str, list[dict[str, Any]]] = {}
        self._approval_service: Any = None
        self._intake_service: Any = None
        self._session_resolver: Any = None
        #: Tasks currently in the completion pipeline: no new execution/flag is
        #: accepted while the ACP session is being closed.
        self._completing: set[str] = set()

    # ------------------------------------------------------------------
    # Lazy Round 2 collaborators
    # ------------------------------------------------------------------

    @property
    def approval_service(self) -> Any:
        """Human-confirmation approval/grant use cases (local console channel)."""

        if self._approval_service is None:
            from .approval_grant_service import ApprovalGrantService

            self._approval_service = ApprovalGrantService(
                self.store, self.evidence, self.clock, self.config
            )
        return self._approval_service

    @property
    def intake_service(self) -> Any:
        if self._intake_service is None:
            from ..intake import IntakeService

            self._intake_service = IntakeService(self.config.intake_root, clock=self.clock)
        return self._intake_service

    @property
    def session_resolver(self) -> Any:
        if self._session_resolver is None:
            from .session_logs import SessionLogResolver

            self._session_resolver = SessionLogResolver(
                self.config.session_log_root, self.store, clock=self.clock
            )
        return self._session_resolver

    def _diagnostic(self, code: str, message: str, **details: Any) -> None:
        self._diagnostics.append(
            {"code": code, "message": message, "details": details, "at": self.clock.now_ms()}
        )
        if len(self._diagnostics) > 200:
            del self._diagnostics[:100]

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
            self.config.ensure_runtime_dirs()
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
        """Round 2 policy: reject ACP host-tool permission requests.

        Worker execution goes through the typed ``ctf-exec`` MCP server and the
        Manager Broker, never through arbitrary ACP host tools. The request's
        ``sessionId`` is reverse-mapped through the Manager's own session
        registry; an unknown session is recorded as a system diagnostic and is
        never attributed to an arbitrary/incorrect Task.
        """

        session_id = str(params.get("sessionId") or "")
        worker = None
        if session_id:
            lookup = getattr(self.store, "get_worker_by_session", None)
            if callable(lookup):
                try:
                    worker = lookup(session_id)
                except Exception as exc:  # noqa: BLE001
                    self._diagnostic("session_lookup_error", str(exc), session_id=session_id)
        if worker is None:
            self._diagnostic(
                "acp_permission_unknown_session",
                "ACP permission request for a session not present in the Manager registry; "
                "request rejected and not attributed to any Task",
                session_id=session_id or None,
                tool_call=params.get("toolCall"),
            )
        else:
            self._emit(
                worker.task_id,
                "acp_permission_rejected",
                {
                    "session_id": session_id,
                    "worker_id": worker.worker_id,
                    "tool_call": params.get("toolCall"),
                },
                worker_id=worker.worker_id,
                session_id=session_id,
            )
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
        """Persist the current evidence-chain head on a non-completed Task row.

        A completed Task's ``evidence_head`` is its immutable historical
        ``task_completed`` anchor. Ordinary queries/writeup/export refresh the
        head only through ``update_evidence_head_if_not_completed``, whose
        condition is evaluated atomically inside the SQL UPDATE; a refresh can
        therefore never overwrite a completion snapshot, even under a race.
        """

        try:
            chain_head = self.evidence.chain_head()
        except Exception:  # noqa: BLE001
            return
        head_hash = chain_head[1] if isinstance(chain_head, tuple) and len(chain_head) == 2 else None
        if not head_hash:
            return
        try:
            conditional = getattr(self.store, "update_evidence_head_if_not_completed", None)
            if callable(conditional):
                conditional(task_id, head_hash)
                return
            # Fallback for non-production repository doubles: never touch a
            # completed Task, and still attempt a read-check-update.
            task = self.store.get_task(task_id)
            if (
                task is not None
                and task.status is not TaskStatus.COMPLETED
                and task.evidence_head != head_hash
            ):
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

    def _worker_mcp_spec(self, worker_token: str, task_id: str) -> list[dict[str, Any]]:
        ipc_url = self.ipc_url
        if not ipc_url:
            raise ConfigError("Manager IPC endpoint is not started; cannot provide ctf-exec MCP server")
        env: dict[str, str] = {
            "CTF_SOLVER_IPC_URL": ipc_url,
            "CTF_SOLVER_WORKER_TOKEN": worker_token,
            "CTF_SOLVER_TASK_ID": task_id,
            "PYTHONPATH": str(Path(__file__).resolve().parents[2]),
            "PYTHONUTF8": "1",
        }
        handshake_dir = (self.config.extra.get("mcp_handshake_dir") or "").strip()
        if handshake_dir:
            env["CTF_SOLVER_MCP_HANDSHAKE_FILE"] = str(
                Path(handshake_dir) / f"{task_id}.json"
            )
        # ACP v1 ``session/new.mcpServers`` standard environment is an ordered
        # array of {name, value} entries (verified against the installed Harness
        # ACP server source and a live zero-model-call mount trial); a plain JSON
        # object is silently not mounted.
        env_entries = [{"name": key, "value": value} for key, value in env.items()]
        return [
            {
                "name": "ctf-exec",
                "command": sys.executable,
                "args": ["-m", "ctf_solver.mcp.exec_server"],
                "env": env_entries,
                "cwd": "",
            }
        ]

    def _start_task(self, task: TaskRecord) -> None:
        workspace = Path(task.workspace_path)
        workspace.mkdir(parents=True, exist_ok=True)
        self.store.set_task_status(task.task_id, TaskStatus.STARTING)
        worker_id = new_id("w")
        worker_token = new_worker_token()
        mcp_servers = self._worker_mcp_spec(worker_token, task.task_id)
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
        """Reload durable state; never create duplicate sessions for a Task.

        A previous process may have crashed in ``completion_pending`` (after the
        ACP session was closed, possibly after the completion event was written
        but before the final status). Recovery finalizes only when the durable
        completion evidence is present and valid; otherwise it marks the Task
        interrupted with a diagnostic and never reports it completed.
        """

        recovered: list[dict[str, Any]] = []
        with self._lock:
            for task in self.store.list_active_tasks():
                worker = self.store.get_worker_for_task(task.task_id)
                previous = task.status.value
                if task.status is TaskStatus.COMPLETION_PENDING:
                    try:
                        finalized = self._recover_completion_pending(task, worker)
                        recovered.append(finalized)
                    except Exception as exc:  # noqa: BLE001
                        self._diagnostic(
                            "completion_recovery_failed", str(exc), task_id=task.task_id
                        )
                        self._event_errors.append(
                            f"recover completion {task.task_id}: {exc}"
                        )
                        recovered.append(
                            {
                                "task_id": task.task_id,
                                "previous_status": previous,
                                "status": task.status.value,
                                "session_duplicate_created": False,
                                "error": f"{type(exc).__name__}: {exc}",
                            }
                        )
                    continue
                try:
                    interrupted = self.store.finalize_task_interruption(
                        task.task_id,
                        expected_status=task.status,
                        result_state="recovered_interrupted",
                        ended_at=self.clock.now_ms(),
                        notes=(
                            "Manager restart: the previous ACP server process no longer exists; "
                            "the Task was NOT resumed or duplicated."
                        ),
                        worker_id=worker.worker_id if worker else None,
                    )
                    self._emit(
                        task.task_id,
                        "task_interrupted",
                        {"reason": "manager_restart", "previous_status": previous, "resumed": False},
                        worker_id=worker.worker_id if worker else None,
                    )
                    recovered.append(
                        {
                            "task_id": task.task_id,
                            "previous_status": previous,
                            "status": interrupted.status.value,
                            "session_duplicate_created": False,
                        }
                    )
                except Exception as exc:  # noqa: BLE001 - preserve real state, report failure
                    self._diagnostic(
                        "recovery_interruption_failed",
                        str(exc),
                        task_id=task.task_id,
                        worker_id=worker.worker_id if worker else None,
                    )
                    self._event_errors.append(
                        f"recover {task.task_id}: {type(exc).__name__}: {exc}"
                    )
                    current = self.store.require_task(task.task_id)
                    recovered.append(
                        {
                            "task_id": task.task_id,
                            "previous_status": previous,
                            "status": current.status.value,
                            "session_duplicate_created": False,
                            "error": f"{type(exc).__name__}: {exc}",
                        }
                    )
            queued = [task.task_id for task in self.store.list_queued()]
        return {"interrupted": recovered, "queued": queued}

    def _recover_completion_pending(
        self, task: TaskRecord, worker: WorkerRecord | None
    ) -> dict[str, Any]:
        """Finalize or safely interrupt a completion interrupted by a crash."""

        task_id = task.task_id
        previous = task.status.value
        events: list[dict[str, Any]] = []
        evidence_ok = False
        try:
            events = self._completion_events(task_id)
            if len(events) == 1:
                self._require_chain_intact(task_id)
            evidence_ok = len(events) == 1
        except Exception:  # noqa: BLE001
            evidence_ok = False

        payload: Mapping[str, Any] = {}
        anchor = ""
        if evidence_ok:
            candidate = events[0].get("payload")
            if isinstance(candidate, Mapping):
                payload = candidate
            anchor = str(events[0].get("record_hash") or "").strip().lower()
        result_state = str(payload.get("result_state") or "")
        ended_at = payload.get("ended_at")
        can_complete = (
            evidence_ok
            and worker is not None
            and str(events[0].get("task_id") or "") == task_id
            and result_state not in {"", "unknown"}
            and isinstance(ended_at, int)
            and int(ended_at) > 0
            and len(anchor) == 64
        )

        if can_complete:
            try:
                self._verify_chain_anchor(task_id, anchor)
                self._persist_evidence_head_strict(task_id, anchor)
                completed = self.store.finalize_task_completion(
                    task_id,
                    worker_id=worker.worker_id,
                    result_state=result_state,
                    ended_at=int(ended_at),
                    notes="completion recovered from durable evidence after restart",
                )
                self._verify_completed_task_evidence(completed)
                self._diagnostic(
                    "completion_recovered",
                    "recovered completion_pending with durable completion evidence",
                    task_id=task_id,
                )
                return {
                    "task_id": task_id,
                    "previous_status": previous,
                    "status": TaskStatus.COMPLETED.value,
                    "result_state": result_state,
                    "ended_at": int(ended_at),
                    "session_duplicate_created": False,
                    "recovered_completion": True,
                }
            except Exception as exc:  # noqa: BLE001 - keep pending + slot protection
                self._diagnostic(
                    "completion_recovery_finalize_failed", str(exc), task_id=task_id
                )
                self._event_errors.append(
                    f"completion recovery {task_id}: {type(exc).__name__}: {exc}"
                )
                return {
                    "task_id": task_id,
                    "previous_status": previous,
                    "status": TaskStatus.COMPLETION_PENDING.value,
                    "session_duplicate_created": False,
                    "recovered_completion": False,
                    "error": f"{type(exc).__name__}: {exc}",
                }
            finally:
                pass

        # No trustworthy completion evidence: never report completed. Task and
        # Worker are interrupted/stopped atomically; any failure keeps the pending
        # Task and its occupied slot untouched and is reported honestly.
        try:
            interrupted = self.store.finalize_task_interruption(
                task_id,
                expected_status=TaskStatus.COMPLETION_PENDING,
                result_state="completion_interrupted",
                ended_at=self.clock.now_ms(),
                notes=(
                    "Manager restart during completion: completion evidence was missing or "
                    "invalid; the Task was NOT marked completed and can be investigated."
                ),
                worker_id=worker.worker_id if worker else None,
            )
        except Exception as exc:  # noqa: BLE001 - keep pending + slot protection
            self._diagnostic(
                "completion_recovery_interruption_failed",
                str(exc),
                task_id=task_id,
            )
            self._event_errors.append(
                f"recover completion interruption {task_id}: "
                f"{type(exc).__name__}: {exc}"
            )
            return {
                "task_id": task_id,
                "previous_status": previous,
                "status": TaskStatus.COMPLETION_PENDING.value,
                "session_duplicate_created": False,
                "recovered_completion": False,
                "error": f"{type(exc).__name__}: {exc}",
            }
        self._emit(
            task_id,
            "task_interrupted",
            {
                "reason": "completion_recovery_without_evidence",
                "previous_status": previous,
                "resumed": False,
                "session_duplicate_created": False,
            },
            worker_id=worker.worker_id if worker else None,
            session_id=interrupted.acp_session_id,
        )
        return {
            "task_id": task_id,
            "previous_status": previous,
            "status": TaskStatus.INTERRUPTED.value,
            "session_duplicate_created": False,
            "recovered_completion": False,
        }

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
        # A Task is only useful if a Worker can actually start. Previously a
        # failed ACP startup still allowed creation and the Task sat queued
        # forever with a green exit code. Fail before persistence instead.
        if not self._started:
            raise AcpUnavailableError(
                "Manager is not started; refusing to create a Task that cannot run",
                details={"reason_code": "acp_unavailable", "acp_ready": False},
            )
        if self._acp is None or not self._acp_ready:
            raise AcpUnavailableError(
                f"Manager ACP is unavailable ({self._acp_error or 'unknown ACP error'}); "
                "refusing to create a Task that cannot leave the queue",
                details={
                    "reason_code": "acp_unavailable",
                    "acp_ready": False,
                    "acp_error": self._acp_error,
                },
            )
        if not self._acp.is_alive():
            self.handle_acp_failure("ACP server process is not alive; refusing new Task")
            raise AcpUnavailableError(
                "ACP server process exited; refusing to create a Task that cannot run",
                details={
                    "reason_code": "acp_unavailable",
                    "acp_ready": False,
                    "acp_error": self._acp_error,
                },
            )
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
        imported: list[dict[str, Any]] = []
        if supplied_files:
            try:
                inputs = self.intake_service.import_files(
                    task_id=task_id,
                    workspace=workspace,
                    supplied_files=list(supplied_files),
                )
            except Exception as exc:
                self.store.set_task_status(
                    task_id,
                    TaskStatus.FAILED,
                    result_state="intake_failed",
                    ended_at=self.clock.now_ms(),
                    notes=f"challenge input import failed: {type(exc).__name__}: {exc}"[:2000],
                )
                self._emit(
                    task_id,
                    "task_failed",
                    {
                        "phase": "intake",
                        "reason": f"{type(exc).__name__}: {exc}",
                        "reason_code": getattr(exc, "reason_code", "intake_error"),
                    },
                )
                raise
            for item in inputs:
                imported.append(item.to_dict() if hasattr(item, "to_dict") else dict(item))
            recorder = getattr(self.store, "record_task_inputs", None)
            if callable(recorder):
                recorder(task_id, inputs)
        self._emit(
            task_id,
            "task_created",
            {
                "title": record.title,
                "category": record.category.value,
                "conversation_id": record.conversation_id,
                "source": record.source,
                "scope_profile": record.scope_profile,
                "supplied_files": [item["rel_path"] for item in imported],
                "supplied_inputs": imported,
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
        inputs: list[dict[str, Any]] = []
        lister = getattr(self.store, "list_task_inputs", None)
        if callable(lister):
            try:
                inputs = [
                    item.to_dict() if hasattr(item, "to_dict") else dict(item)
                    for item in lister(task_id)
                ]
            except Exception as exc:  # noqa: BLE001
                self._diagnostic("task_inputs_read_error", str(exc), task_id=task_id)
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
            "inputs": inputs,
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
            if task.status is TaskStatus.COMPLETION_PENDING:
                raise StateError(
                    f"Task {task_id} completion is pending; retry complete_task instead of cancel"
                )
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
    # Task completion lifecycle (Round 2 P0-4)
    # ------------------------------------------------------------------

    _COMPLETION_ACTIVE_STATUSES = frozenset(
        {
            TaskStatus.RUNNING,
            TaskStatus.PAUSED,
            TaskStatus.AWAITING_APPROVAL,
            TaskStatus.BLOCKED,
        }
    )

    def _completion_events(self, task_id: str) -> list[dict[str, Any]]:
        lister = getattr(self.evidence, "list_events", None)
        if not callable(lister):
            raise StateError(
                "the evidence store cannot list completion events; refusing to complete"
            )
        try:
            events = lister(task_id=task_id, event_type="task_completed")
        except Exception as exc:  # noqa: BLE001
            raise StateError(
                f"could not read task_completed evidence: {type(exc).__name__}: {exc}"
            ) from exc
        return [dict(event) for event in (events or []) if isinstance(event, Mapping)]

    def _require_chain_intact(self, task_id: str) -> str:
        status_reader = getattr(self.evidence, "chain_status", None)
        if not callable(status_reader):
            raise StateError("the evidence store cannot verify the hash chain")
        try:
            status = status_reader()
        except Exception as exc:  # noqa: BLE001
            raise StateError(
                f"evidence chain status failed: {type(exc).__name__}: {exc}"
            ) from exc
        if not bool(getattr(status, "ok", False)):
            raise StateError(
                f"Task {task_id} evidence hash chain is not intact; refusing to complete"
            )
        try:
            head = self.evidence.chain_head()
        except Exception as exc:  # noqa: BLE001
            raise StateError(
                f"evidence chain head is unavailable: {type(exc).__name__}: {exc}"
            ) from exc
        head_hash = head[1] if isinstance(head, tuple) and len(head) == 2 else ""
        if not head_hash:
            raise StateError("evidence chain has no head hash; refusing to complete")
        return str(head_hash)

    def _persist_evidence_head_strict(self, task_id: str, head_hash: str) -> None:
        try:
            self.store.update_task_fields(task_id, evidence_head=head_hash)
            persisted = self.store.require_task(task_id)
        except Exception as exc:  # noqa: BLE001
            raise StorageError(
                f"could not persist evidence_head for Task {task_id}: "
                f"{type(exc).__name__}: {exc}"
            ) from exc
        if str(persisted.evidence_head or "") != str(head_hash):
            raise StorageError(
                f"evidence_head persistence verification failed for Task {task_id}"
            )

    def _completion_event_payload(
        self, task_id: str, worker: WorkerRecord, result_state: str
    ) -> tuple[dict[str, Any], str]:
        events = self._completion_events(task_id)
        if len(events) > 1:
            raise StateError(
                f"Task {task_id} has {len(events)} task_completed events; exactly one "
                "is required"
            )
        if events:
            event = events[0]
            if str(event.get("task_id") or "") != str(task_id):
                raise StateError("task_completed evidence belongs to another Task")
            payload = event.get("payload") if isinstance(event.get("payload"), Mapping) else {}
            if payload.get("result_state") != result_state:
                raise StateError(
                    "existing task_completed evidence has a different result_state; "
                    "refusing to complete"
                )
            if not isinstance(payload.get("ended_at"), int) or int(payload["ended_at"]) <= 0:
                raise StateError("existing task_completed evidence has no valid ended_at")
            anchor = str(event.get("record_hash") or "").strip().lower()
            if not anchor:
                raise StateError(
                    "existing task_completed evidence has no record hash; cannot verify "
                    "the historical chain anchor"
                )
            return dict(payload), anchor

        ended_at = int(self.clock.now_ms())
        payload = {
            "status": TaskStatus.COMPLETED.value,
            "result_state": result_state,
            "ended_at": ended_at,
            "session_id": worker.acp_session_id,
            "session_closed": True,
            "worker_id": worker.worker_id,
        }
        try:
            self.evidence.append_event(
                task_id=task_id,
                worker_id=worker.worker_id,
                session_id=worker.acp_session_id,
                source="manager",
                source_id=f"manager:task_completed:{uuid.uuid4().hex}",
                event_type="task_completed",
                payload=payload,
                timestamp=ended_at,
            )
        except Exception as exc:  # noqa: BLE001 - evidence is mandatory here
            raise StorageError(
                f"task_completed evidence append failed: {type(exc).__name__}: {exc}",
                details={"task_id": task_id, "phase": "task_completed_append"},
            ) from exc
        # Verify the event really is in the chain and keep its own hash as the
        # immutable Task completion anchor (NOT the later global head).
        self._require_chain_intact(task_id)
        events = self._completion_events(task_id)
        if len(events) != 1:
            raise StorageError(
                f"task_completed evidence verification failed: {len(events)} event(s)",
                details={"task_id": task_id, "phase": "task_completed_verify"},
            )
        anchor = str(events[0].get("record_hash") or "").strip().lower()
        if not anchor:
            raise StorageError(
                "task_completed evidence has no record hash; cannot establish an anchor",
                details={"task_id": task_id, "phase": "task_completed_anchor"},
            )
        return payload, anchor

    def _verify_chain_anchor(self, task_id: str, anchor_hash: str) -> str:
        anchor = str(anchor_hash or "").strip().lower()
        if len(anchor) != 64:
            raise StateError(
                f"Task {task_id} has no valid historical evidence-head anchor"
            )
        verifier = getattr(self.evidence, "verify_chain_anchor", None)
        if not callable(verifier):
            raise StateError(
                "the evidence store cannot verify historical chain anchors; refusing "
                "to trust a Task completion snapshot"
            )
        self._require_chain_intact(task_id)
        try:
            valid = bool(verifier(anchor))
        except Exception as exc:  # noqa: BLE001
            raise StateError(
                f"historical evidence-head verification failed: "
                f"{type(exc).__name__}: {exc}"
            ) from exc
        if not valid:
            raise StateError(
                f"Task {task_id} historical evidence head is not present in the "
                "current intact evidence chain"
            )
        return anchor

    def _verify_completed_task_evidence(self, task: TaskRecord) -> dict[str, Any]:
        """Verify a completed Task against its historical chain snapshot.

        The global append-only head legitimately advances when other Tasks write
        evidence. The correct invariant is therefore: the Task's saved
        ``evidence_head`` must be the record hash of its unique completion event
        and must still exist inside the current valid chain; the current global
        head may be later.
        """

        anchor = self._verify_chain_anchor(task.task_id, task.evidence_head or "")
        events = self._completion_events(task.task_id)
        if len(events) != 1:
            raise StateError(
                f"completed Task {task.task_id} lacks exactly one task_completed event "
                f"({len(events)} found); refusing to report completion"
            )
        event = events[0]
        event_anchor = str(event.get("record_hash") or "").strip().lower()
        if event_anchor != anchor:
            raise StateError(
                "completed Task evidence_head does not match its completion event anchor"
            )
        payload = event.get("payload") if isinstance(event.get("payload"), Mapping) else {}
        if payload.get("result_state") != task.result_state:
            raise StateError("completed Task result_state and evidence disagree")
        if int(payload.get("ended_at") or 0) != int(task.ended_at or 0):
            raise StateError("completed Task ended_at and evidence disagree")
        return dict(payload)

    def _finalize_completion(
        self,
        task_id: str,
        worker: WorkerRecord,
        result_state: str,
        note: str,
        *,
        session_already_closed: bool,
    ) -> dict[str, Any]:
        """Finish a completion from ``completion_pending`` with mandatory evidence.

        Ordering: durable completion event + historical anchor verification →
        strict evidence_head persistence → atomic SQLite transaction setting the
        Task ``completed`` and the Worker ``stopped`` (slot release) → optional
        FIFO pump. If the transaction fails, both Task and Worker are rolled back,
        the Task stays ``completion_pending`` and the Worker keeps the slot.
        """

        task = self.store.require_task(task_id)
        if task.status is not TaskStatus.COMPLETION_PENDING:
            raise StateError(
                f"Task {task_id} is not completion_pending (status={task.status.value})"
            )
        if task.result_state != result_state:
            raise StateError(
                "completion_pending result_state changed; refusing to complete"
            )
        if worker.task_id != task_id or worker.acp_session_id != task.acp_session_id:
            raise StateError("Worker/session ownership no longer matches the Task")

        # Revoke grants before the completion event; idempotent on retry.
        revoked: list[str] = []
        for grant in self.store.list_grants(task_id=task_id):
            if grant.status is GrantStatus.ACTIVE:
                try:
                    self.revoke_grant(grant.grant_id)
                    revoked.append(grant.grant_id)
                except Exception as exc:  # noqa: BLE001
                    raise StorageError(
                        f"could not revoke grant {grant.grant_id} before completion: "
                        f"{type(exc).__name__}: {exc}",
                        details={"task_id": task_id, "phase": "grant_revocation"},
                    ) from exc

        payload, anchor = self._completion_event_payload(task_id, worker, result_state)
        ended_at = int(payload["ended_at"])
        # Mandatory: the saved historical snapshot must be the completion event
        # hash and must be inside the current intact chain.
        self._verify_chain_anchor(task_id, anchor)
        self._persist_evidence_head_strict(task_id, anchor)

        # Atomic final state: Task completed + Worker stopped (slot release) only
        # together. Failure rolls both back, so the slot cannot be freed early.
        try:
            completed = self.store.finalize_task_completion(
                task_id,
                worker_id=worker.worker_id,
                result_state=result_state,
                ended_at=ended_at,
                notes=(note or "Task completed through the Manager lifecycle"),
            )
        except Exception as exc:  # noqa: BLE001
            self._diagnostic(
                "task_completion_finalize_failed",
                str(exc),
                task_id=task_id,
                worker_id=worker.worker_id,
            )
            raise StorageError(
                f"final completion state could not be persisted atomically: "
                f"{type(exc).__name__}: {exc}",
                details={"task_id": task_id, "phase": "task_worker_finalize"},
            ) from exc
        # Re-verify against the immutable historical anchor (the global head may
        # have advanced; it is not the Task snapshot).
        try:
            self._verify_completed_task_evidence(completed)
        except Exception as exc:  # noqa: BLE001
            self._diagnostic(
                "task_completion_post_verify_failed", str(exc), task_id=task_id
            )
            raise StorageError(
                f"completion post-write evidence verification failed: "
                f"{type(exc).__name__}: {exc}",
                details={"task_id": task_id, "phase": "completion_post_verify"},
            ) from exc
        snapshot = {
            "task_id": task_id,
            "status": TaskStatus.COMPLETED.value,
            "result_state": completed.result_state,
            "ended_at": completed.ended_at,
            "worker_stopped": True,
            "session_closed": bool(session_already_closed),
            "slot_released": True,
            "revoked_grants": revoked,
            "evidence_head": completed.evidence_head,
            "already_completed": False,
        }
        try:
            self.pump()
        except Exception as exc:  # noqa: BLE001 - completion state is already durable
            self._diagnostic(
                "completion_fifo_pump_failed", str(exc), task_id=task_id
            )
        return snapshot

    def _completion_preconditions(
        self, task: TaskRecord, worker: WorkerRecord, *, allow_missing_session_log: bool
    ) -> None:
        task_id = task.task_id
        pending_approvals = [
            record
            for record in self.store.list_approvals(task_id=task_id)
            if record.status is ApprovalStatus.PENDING
        ]
        if pending_approvals:
            raise StateError(
                f"Task {task_id} has {len(pending_approvals)} pending approval(s); "
                "resolve them before completing"
            )
        unfinished = self.store.count_unfinished_executions(task_id)
        if unfinished:
            raise StateError(
                f"Task {task_id} has {unfinished} unfinished execution(s); "
                "wait for them to settle before completing"
            )
        if not allow_missing_session_log and not self._has_ingested_session_log(task_id):
            raise StateError(
                f"Task {task_id} has no ingested session log; ingest the real "
                "Harness session evidence before completing"
            )
        security_diagnostics = [
            item
            for item in self._diagnostics
            if item.get("code") in {"acp_permission_unknown_session", "session_lookup_error"}
        ]
        if security_diagnostics:
            raise StateError(
                f"Task {task_id} has unresolved ACP security diagnostics; resolve them "
                "before completing"
            )
        if self._event_errors:
            raise StateError(
                "the Manager has unresolved evidence errors; refusing to declare completion"
            )
        self._refresh_evidence_head(task_id)
        refreshed = self.store.require_task(task_id)
        if not refreshed.evidence_head:
            raise StateError(
                f"Task {task_id} has no persisted evidence head; refusing to complete"
            )
        self._require_chain_intact(task_id)
        if not worker.task_id or worker.task_id != task_id:
            raise StateError(f"Task {task_id} has no matching Worker; refusing to complete")
        if not task.acp_session_id or worker.acp_session_id != task.acp_session_id:
            raise StateError(
                f"Task {task_id} Worker/session ownership does not match; refusing to complete"
            )

    def complete_task(
        self,
        task_id: str,
        *,
        result_state: str,
        note: str = "",
        allow_missing_session_log: bool = False,
    ) -> dict[str, Any]:
        """Complete a Task with mandatory, durable completion evidence.

        The Task first enters the slot-holding intermediate state
        ``completion_pending``; the ACP session is closed; then the
        ``task_completed`` event and ``evidence_head`` must be durably persisted
        before the Worker slot is released and the Task becomes ``completed``.
        Any failure yields a retryable pending state (or the original state when
        session close failed) and never reports success without evidence.
        """

        from ..security.textsafe import UnsafeTextError, normalize_field

        try:
            normalized_result = normalize_field(
                result_state,
                field="result_state",
                max_length=64,
                pattern=r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}",
                pattern_description="result-state token",
            )
        except UnsafeTextError as exc:
            raise ValidationError(str(exc)) from exc
        if normalized_result == "unknown":
            raise ValidationError("result_state must describe the outcome, not 'unknown'")
        safe_note = str(note or "")

        with self._lock:
            task = self.store.require_task(task_id)
            worker = self.store.get_worker_for_task(task_id)
            if task.status is TaskStatus.COMPLETED:
                # Idempotent, but only if the durable completion evidence exists.
                self._verify_completed_task_evidence(task)
                return {
                    "task_id": task_id,
                    "status": TaskStatus.COMPLETED.value,
                    "result_state": task.result_state,
                    "ended_at": task.ended_at,
                    "worker_stopped": worker is None or worker.status is WorkerStatus.STOPPED,
                    "session_closed": True,
                    "slot_released": True,
                    "already_completed": True,
                }
            if task_id in self._completing:
                raise StateError(f"Task {task_id} completion is already in progress")
            if task.status is TaskStatus.COMPLETION_PENDING:
                if not task.result_state or task.result_state == "unknown":
                    raise StateError(
                        f"Task {task_id} has no concrete pending result_state; "
                        "refusing to finalize"
                    )
                if normalized_result != task.result_state:
                    raise StateError(
                        "completion_pending result_state does not match the requested "
                        "result_state; retry with the original value"
                    )
                if worker is None:
                    raise StateError(
                        f"Task {task_id} completion_pending has no Worker mapping"
                    )
                self._completing.add(task_id)
                try:
                    return self._finalize_completion(
                        task_id,
                        worker,
                        task.result_state,
                        safe_note,
                        session_already_closed=True,
                    )
                finally:
                    self._completing.discard(task_id)
            if task.status not in self._COMPLETION_ACTIVE_STATUSES:
                raise StateError(
                    f"Task {task_id} status {task.status.value} cannot be completed; "
                    "only an active Task can"
                )
            if worker is None:
                raise StateError(
                    f"Task {task_id} has no Worker/session mapping; refusing to complete"
                )
            self._completion_preconditions(
                task, worker, allow_missing_session_log=allow_missing_session_log
            )
            if self._acp is None or not self._acp_ready or not self._acp.is_alive():
                raise AcpError(
                    "ACP client is not ready; cannot confirm session close for completion",
                    details={"task_id": task_id, "reason_code": "completion_acp_unavailable"},
                )

            previous_status = task.status
            self._completing.add(task_id)
            try:
                # Durable intermediate state: holds the Worker slot, refuses new
                # executions, is never reported as completed, and survives restart.
                self.store.set_task_status(
                    task_id,
                    TaskStatus.COMPLETION_PENDING,
                    result_state=normalized_result,
                    notes=(safe_note or "completion started")[:2000],
                )
                try:
                    self._acp.close_session(worker.acp_session_id)
                except Exception as exc:  # noqa: BLE001 - roll back, keep slot
                    try:
                        self.store.set_task_status(
                            task_id,
                            previous_status,
                            notes=f"completion aborted (session close failed): {exc}"[:2000],
                        )
                    except Exception as rollback_exc:  # noqa: BLE001
                        self._diagnostic(
                            "task_completion_rollback_failed",
                            str(rollback_exc),
                            task_id=task_id,
                        )
                    self._diagnostic(
                        "task_completion_session_close_failed",
                        str(exc),
                        task_id=task_id,
                        session_id=worker.acp_session_id,
                    )
                    raise AcpError(
                        "ACP session close failed; the Task remains "
                        f"{previous_status.value} and the Worker slot is still held",
                        details={
                            "task_id": task_id,
                            "session_id": worker.acp_session_id,
                            "worker_id": worker.worker_id,
                            "reason_code": "session_close_failed",
                            "task_status": previous_status.value,
                            "slot_released": False,
                        },
                    ) from exc
                return self._finalize_completion(
                    task_id,
                    worker,
                    normalized_result,
                    safe_note,
                    session_already_closed=True,
                )
            finally:
                self._completing.discard(task_id)

    def _has_ingested_session_log(self, task_id: str) -> bool:
        lister = getattr(self.evidence, "list_events", None)
        if not callable(lister):
            return False
        try:
            events = lister(task_id=task_id, event_type="evidence_ingested", limit=1)
        except Exception:  # noqa: BLE001 - absence must fail closed
            return False
        return bool(events)

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
        return self.approval_service.request_approval(
            task_id, action_kind=action_kind, details=details, ttl_s=ttl_s
        )

    def confirm_approval(
        self,
        approval_id: str,
        *,
        channel: Any,
        reject: bool = False,
        note: str = "",
    ) -> ApprovalRecord:
        """Local-console human confirmation path (never exposed through MCP)."""

        return self.approval_service.confirm_approval(
            approval_id, channel=channel, reject=reject, note=note
        )

    def decide_approval(self, approval_id: str, *, approved: bool = False, approver: str = "", note: str = "") -> ApprovalRecord:
        raise StateError(
            "approvals cannot be decided by the Agent/MCP; a human must confirm "
            "through the local interactive console channel (ctf-solver approval confirm)"
        )

    def list_approvals(self, *, task_id: str | None = None) -> list[ApprovalRecord]:
        return self.approval_service.list_approvals(task_id=task_id)

    def create_grant_from_approval(
        self,
        approval_id: str,
        *,
        competition_profile: str,
        host: str,
        port: int,
        protocol: str = "tcp",
        method: str = "GET",
        path_prefix: str = "/",
        ttl_s: int | None = None,
        max_calls: int | None = None,
    ) -> GrantRecord:
        return self.approval_service.create_grant_from_approval(
            approval_id,
            competition_profile=competition_profile,
            host=host,
            port=port,
            protocol=protocol,
            method=method,
            path_prefix=path_prefix,
            ttl_s=ttl_s,
            max_calls=max_calls,
        )

    def create_network_grant(self, task_id: str, **kwargs: Any) -> GrantRecord:
        raise StateError(
            "network grants cannot be created directly by the Agent/MCP; they require a "
            "human-confirmed remote_target approval and the local console channel"
        )

    def revoke_grant(self, grant_id: str) -> GrantRecord:
        return self.approval_service.revoke_grant(grant_id)

    def list_grants(self, *, task_id: str | None = None) -> list[GrantRecord]:
        return self.approval_service.list_grants(task_id=task_id)

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
        if task.status is TaskStatus.COMPLETION_PENDING or task_id in self._completing:
            raise StateError(f"Task {task_id} is completing; no new candidate Flag is accepted")
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
        self, task_id: str, *, worker_id: str | None = None
    ) -> dict[str, Any]:
        """Ingest the Task's real Harness session log.

        The log path is **never** supplied by the caller. It is resolved only
        from the Manager's own Task/Worker/session registry under the managed
        Harness ``sessions`` root; unknown/ambiguous/symlinked/out-of-root logs
        fail closed.
        """

        self.store.require_task(task_id)
        resolved = self.session_resolver.resolve(task_id, worker_id=worker_id)
        ingest = getattr(self.evidence, "ingest_session_log_file", None)
        if not callable(ingest):
            raise StorageError("evidence store does not support session-log ingestion")
        report = ingest(
            task_id=task_id,
            worker_id=resolved.worker_id,
            session_id=resolved.session_id,
            path=str(resolved.path),
        )
        payload = report.to_dict() if hasattr(report, "to_dict") else dict(report or {})
        self._emit(
            task_id,
            "evidence_ingested",
            {
                "session_id": resolved.session_id,
                "frames": payload.get("frames"),
                "records": payload.get("appended", payload.get("decoded_records")),
                "gaps": len(payload.get("gaps", []) or []),
                "raw_sha256": payload.get("raw_sha256"),
            },
            worker_id=resolved.worker_id,
            session_id=resolved.session_id,
        )
        # Do not echo local filesystem paths through the control surface.
        payload.pop("raw_path", None)
        payload.pop("path", None)
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
        # A Task that is completing or terminal must not accept new execution
        # requests anymore (Round 2 P0-4). This check is authoritative inside
        # the Manager process that owns the IPC endpoint.
        task = self.store.get_task(worker.task_id)
        if task is None:
            raise IpcError("Worker Task no longer exists", reason_code="task_missing")
        if task.task_id in self._completing or task.status is TaskStatus.COMPLETION_PENDING:
            raise IpcError(
                "Task is completing; new execution requests are refused",
                reason_code="task_completing",
            )
        if task.status not in SLOT_OCCUPYING_TASK_STATUSES:
            raise IpcError(
                f"Task status {task.status.value} does not accept execution requests",
                reason_code="task_terminal",
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
            "session_log_root": str(self.config.session_log_root),
            "intake_root": str(self.config.intake_root),
            "diagnostics": list(self._diagnostics[-20:]),
            "security": dict(ROUND2_SECURITY),
            "chain_head": chain_head,
            "event_errors": list(self._event_errors[-10:]),
            "round1_limits": dict(ROUND1_LIMITS),
        }

    def close(self) -> None:
        self.shutdown()
        self.store.close()
