"""Durable Manager state repository (SQLite), implementing PolicyRepository.

All Task/Worker/approval/grant/execution state lives here. Evidence events are
appended by the evidence store; this repository only owns Manager state tables.
"""

from __future__ import annotations

import json
import threading
from contextlib import contextmanager
from typing import Any, Iterator

from ..core.canonical import canonical_json, file_sha256
from ..core.errors import NotFoundError, StateError, StorageError
from ..core.protocols import Clock, SystemClock
from ..core.types import (
    ApprovalRecord,
    ApprovalStatus,
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
    can_transition,
)
from ..storage.db import open_database, transaction


class ManagerStore:
    def __init__(self, db_path: str, clock: Clock | None = None) -> None:
        self.db_path = str(db_path)
        self.clock = clock or SystemClock()
        self._lock = threading.RLock()
        self.conn = open_database(self.db_path)

    def close(self) -> None:
        with self._lock:
            try:
                self.conn.close()
            except Exception:  # noqa: BLE001
                pass

    @contextmanager
    def _tx(self) -> Iterator[None]:
        with self._lock:
            with transaction(self.conn):
                yield

    # ------------------------------------------------------------------
    # Tasks
    # ------------------------------------------------------------------

    def create_task(self, record: TaskRecord) -> TaskRecord:
        now = self.clock.now_ms()
        record.created_at = record.created_at or now
        record.updated_at = now
        with self._tx():
            self.conn.execute(
                "INSERT INTO tasks(task_id, conversation_id, title, category, source, scope_profile,"
                " workspace_path, acp_session_id, worker_id, status, result_state, flag_state,"
                " flag_value, created_at, updated_at, started_at, ended_at, evidence_head, notes)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    record.task_id,
                    record.conversation_id,
                    record.title,
                    record.category.value,
                    record.source,
                    record.scope_profile,
                    record.workspace_path,
                    record.acp_session_id,
                    record.worker_id,
                    record.status.value,
                    record.result_state,
                    record.flag_state.value,
                    None,
                    record.created_at,
                    record.updated_at,
                    record.started_at,
                    record.ended_at,
                    record.evidence_head,
                    record.notes,
                ),
            )
        return self.get_task(record.task_id)  # type: ignore[return-value]

    def get_task(self, task_id: str) -> TaskRecord | None:
        with self._lock:
            row = self.conn.execute("SELECT * FROM tasks WHERE task_id = ?", (task_id,)).fetchone()
        return TaskRecord.from_row(row) if row is not None else None

    def require_task(self, task_id: str) -> TaskRecord:
        task = self.get_task(task_id)
        if task is None:
            raise NotFoundError(f"unknown task: {task_id}")
        return task

    def list_tasks(
        self, *, status: str | None = None, conversation_id: str | None = None
    ) -> list[TaskRecord]:
        query = "SELECT * FROM tasks"
        clauses: list[str] = []
        params: list[Any] = []
        if status is not None:
            clauses.append("status = ?")
            params.append(status)
        if conversation_id is not None:
            clauses.append("conversation_id = ?")
            params.append(conversation_id)
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY created_at, task_id"
        with self._lock:
            rows = self.conn.execute(query, params).fetchall()
        return [TaskRecord.from_row(row) for row in rows]

    def list_queued(self) -> list[TaskRecord]:
        return self.list_tasks(status=TaskStatus.QUEUED.value)

    def set_task_status(
        self,
        task_id: str,
        target: TaskStatus,
        *,
        result_state: str | None = None,
        started_at: int | None = None,
        ended_at: int | None = None,
        notes: str | None = None,
    ) -> TaskRecord:
        with self._tx():
            task = self.require_task(task_id)
            if task.status is target:
                return task
            if not can_transition(task.status, target):
                raise StateError(
                    f"illegal Task transition {task.status.value} -> {target.value} for {task_id}"
                )
            now = self.clock.now_ms()
            self.conn.execute(
                "UPDATE tasks SET status = ?, updated_at = ?,"
                " result_state = COALESCE(?, result_state),"
                " started_at = COALESCE(?, started_at),"
                " ended_at = COALESCE(?, ended_at),"
                " notes = COALESCE(?, notes)"
                " WHERE task_id = ?",
                (
                    target.value,
                    now,
                    result_state,
                    started_at,
                    ended_at,
                    notes,
                    task_id,
                ),
            )
        return self.require_task(task_id)

    def update_task_fields(self, task_id: str, **fields: Any) -> TaskRecord:
        allowed = {
            "worker_id",
            "acp_session_id",
            "evidence_head",
            "result_state",
            "scope_profile",
            "notes",
        }
        unknown = set(fields) - allowed
        if unknown:
            raise StorageError(f"unsupported Task fields: {', '.join(sorted(unknown))}")
        if not fields:
            return self.require_task(task_id)
        assignments = ", ".join(f"{name} = ?" for name in fields)
        params = list(fields.values()) + [self.clock.now_ms(), task_id]
        with self._tx():
            self.conn.execute(
                f"UPDATE tasks SET {assignments}, updated_at = ? WHERE task_id = ?", params
            )
        return self.require_task(task_id)

    def activate_task(
        self,
        task_id: str,
        *,
        worker: WorkerRecord,
    ) -> tuple[TaskRecord, WorkerRecord]:
        """Persist Worker/session/workspace mapping and mark the Task running atomically."""

        with self._tx():
            task = self.require_task(task_id)
            if task.status is not TaskStatus.STARTING:
                raise StateError(f"Task {task_id} is not STARTING (status={task.status.value})")
            now = self.clock.now_ms()
            self.conn.execute(
                "INSERT INTO workers(worker_id, task_id, acp_session_id, workspace_path, status,"
                " worker_token, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?)",
                (
                    worker.worker_id,
                    worker.task_id,
                    worker.acp_session_id,
                    worker.workspace_path,
                    worker.status.value,
                    worker.worker_token,
                    worker.created_at or now,
                    now,
                ),
            )
            self.conn.execute(
                "UPDATE tasks SET worker_id = ?, acp_session_id = ?, status = ?, started_at = ?,"
                " updated_at = ? WHERE task_id = ?",
                (
                    worker.worker_id,
                    worker.acp_session_id,
                    TaskStatus.RUNNING.value,
                    now,
                    now,
                    task_id,
                ),
            )
        return self.require_task(task_id), self.require_worker(worker.worker_id)

    def record_flag_candidate(
        self, task_id: str, *, flag_digest: str, flag_value: str | None = None
    ) -> TaskRecord:
        with self._tx():
            task = self.require_task(task_id)
            if task.flag_state in (FlagState.USER_CONFIRMED, FlagState.PLATFORM_VERIFIED):
                raise StateError("a confirmed Flag state cannot be downgraded to candidate")
            self.conn.execute(
                "UPDATE tasks SET flag_state = ?, flag_value = ?, updated_at = ? WHERE task_id = ?",
                (
                    FlagState.CANDIDATE.value,
                    flag_value if flag_value is not None else task.flag_value,
                    self.clock.now_ms(),
                    task_id,
                ),
            )
        return self.require_task(task_id)

    def confirm_flag(self, task_id: str, *, state: FlagState) -> TaskRecord:
        with self._tx():
            self.require_task(task_id)
            self.conn.execute(
                "UPDATE tasks SET flag_state = ?, updated_at = ? WHERE task_id = ?",
                (state.value, self.clock.now_ms(), task_id),
            )
        return self.require_task(task_id)

    def count_active_slots(self) -> int:
        placeholders = ",".join("?" for _ in _SLOT_WORKER_STATUSES)
        with self._lock:
            row = self.conn.execute(
                f"SELECT COUNT(*) AS n FROM workers WHERE status IN ({placeholders})",
                tuple(status.value for status in _SLOT_WORKER_STATUSES),
            ).fetchone()
        return int(row["n"])

    # ------------------------------------------------------------------
    # Workers
    # ------------------------------------------------------------------

    def create_worker(self, worker: WorkerRecord) -> WorkerRecord:
        now = self.clock.now_ms()
        worker.created_at = worker.created_at or now
        worker.updated_at = now
        with self._tx():
            self.conn.execute(
                "INSERT INTO workers(worker_id, task_id, acp_session_id, workspace_path, status,"
                " worker_token, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?)",
                (
                    worker.worker_id,
                    worker.task_id,
                    worker.acp_session_id,
                    worker.workspace_path,
                    worker.status.value,
                    worker.worker_token,
                    worker.created_at,
                    worker.updated_at,
                ),
            )
        return self.require_worker(worker.worker_id)

    def get_worker(self, worker_id: str) -> WorkerRecord | None:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM workers WHERE worker_id = ?", (worker_id,)
            ).fetchone()
        return WorkerRecord.from_row(row) if row is not None else None

    def require_worker(self, worker_id: str) -> WorkerRecord:
        worker = self.get_worker(worker_id)
        if worker is None:
            raise NotFoundError(f"unknown worker: {worker_id}")
        return worker

    def get_worker_by_token(self, token: str) -> WorkerRecord | None:
        if not token:
            return None
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM workers WHERE worker_token = ?", (token,)
            ).fetchone()
        return WorkerRecord.from_row(row) if row is not None else None

    def get_worker_for_task(self, task_id: str) -> WorkerRecord | None:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM workers WHERE task_id = ?", (task_id,)
            ).fetchone()
        return WorkerRecord.from_row(row) if row is not None else None

    def set_worker_status(self, worker_id: str, status: WorkerStatus) -> WorkerRecord:
        with self._tx():
            self.conn.execute(
                "UPDATE workers SET status = ?, updated_at = ? WHERE worker_id = ?",
                (status.value, self.clock.now_ms(), worker_id),
            )
        return self.require_worker(worker_id)

    def list_workers(self) -> list[WorkerRecord]:
        with self._lock:
            rows = self.conn.execute("SELECT * FROM workers ORDER BY created_at").fetchall()
        return [WorkerRecord.from_row(row) for row in rows]

    def list_active_tasks(self) -> list[TaskRecord]:
        placeholders = ",".join("?" for _ in _SLOT_TASK_STATUSES)
        with self._lock:
            rows = self.conn.execute(
                f"SELECT * FROM tasks WHERE status IN ({placeholders}) ORDER BY created_at, task_id",
                tuple(status.value for status in _SLOT_TASK_STATUSES),
            ).fetchall()
        return [TaskRecord.from_row(row) for row in rows]

    # ------------------------------------------------------------------
    # Approvals
    # ------------------------------------------------------------------

    def create_approval(self, approval: ApprovalRecord) -> ApprovalRecord:
        with self._tx():
            self.conn.execute(
                "INSERT INTO approvals(approval_id, task_id, action_kind, action_digest, status,"
                " requested_at, decided_at, approver, note, payload_json, expires_at, consumed_at)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    approval.approval_id,
                    approval.task_id,
                    approval.action_kind,
                    approval.action_digest,
                    approval.status.value,
                    approval.requested_at,
                    approval.decided_at,
                    approval.approver,
                    approval.note,
                    canonical_json(approval.payload),
                    approval.expires_at,
                    approval.consumed_at,
                ),
            )
        return self.get_approval(approval.approval_id)  # type: ignore[return-value]

    def get_approval(self, approval_id: str) -> ApprovalRecord | None:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM approvals WHERE approval_id = ?", (approval_id,)
            ).fetchone()
        return _approval_from_row(row) if row is not None else None

    def decide_approval(
        self, approval_id: str, *, approved: bool, approver: str, note: str = ""
    ) -> ApprovalRecord:
        if not approver or not str(approver).strip():
            raise StateError("an approval decision requires an explicit human approver")
        with self._tx():
            record = self.get_approval(approval_id)
            if record is None:
                raise NotFoundError(f"unknown approval: {approval_id}")
            if record.status is not ApprovalStatus.PENDING:
                raise StateError(f"approval {approval_id} is already {record.status.value}")
            now = self.clock.now_ms()
            if record.expires_at is not None and record.expires_at <= now:
                self.conn.execute(
                    "UPDATE approvals SET status = ?, note = ? WHERE approval_id = ?",
                    (ApprovalStatus.EXPIRED.value, note, approval_id),
                )
                raise StateError(f"approval {approval_id} has expired")
            status = ApprovalStatus.APPROVED if approved else ApprovalStatus.REJECTED
            self.conn.execute(
                "UPDATE approvals SET status = ?, decided_at = ?, approver = ?, note = ?"
                " WHERE approval_id = ?",
                (status.value, now, approver, note, approval_id),
            )
        return self.get_approval(approval_id)  # type: ignore[return-value]

    def list_approvals(self, *, task_id: str | None = None) -> list[ApprovalRecord]:
        query = "SELECT * FROM approvals"
        params: list[Any] = []
        if task_id is not None:
            query += " WHERE task_id = ?"
            params.append(task_id)
        query += " ORDER BY requested_at, approval_id"
        with self._lock:
            rows = self.conn.execute(query, params).fetchall()
        return [_approval_from_row(row) for row in rows]

    def consume_approval(self, approval_id: str, now_ms: int) -> bool:
        """Atomically validate and consume a one-shot approval."""

        with self._tx():
            record = self.get_approval(approval_id)
            if record is None:
                return False
            if record.status is not ApprovalStatus.APPROVED:
                return False
            if record.consumed_at is not None:
                return False
            if record.expires_at is not None and record.expires_at <= now_ms:
                return False
            self.conn.execute(
                "UPDATE approvals SET consumed_at = ? WHERE approval_id = ? AND consumed_at IS NULL",
                (now_ms, approval_id),
            )
            row = self.conn.execute(
                "SELECT consumed_at FROM approvals WHERE approval_id = ?", (approval_id,)
            ).fetchone()
            return row is not None and row["consumed_at"] == now_ms

    # ------------------------------------------------------------------
    # Network grants
    # ------------------------------------------------------------------

    def create_grant(self, grant: GrantRecord) -> GrantRecord:
        with self._tx():
            self.conn.execute(
                "INSERT INTO network_grants(grant_id, task_id, competition_profile, host, port,"
                " protocol, method, path_prefix, expires_at, max_calls, calls_used, approver,"
                " created_at, status, grant_digest)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    grant.grant_id,
                    grant.task_id,
                    grant.competition_profile,
                    grant.host,
                    grant.port,
                    grant.protocol,
                    grant.method,
                    grant.path_prefix,
                    grant.expires_at,
                    grant.max_calls,
                    grant.calls_used,
                    grant.approver,
                    grant.created_at,
                    grant.status.value,
                    grant.grant_digest,
                ),
            )
        return self.get_grant(grant.grant_id)  # type: ignore[return-value]

    def get_grant(self, grant_id: str) -> GrantRecord | None:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM network_grants WHERE grant_id = ?", (grant_id,)
            ).fetchone()
        return _grant_from_row(row) if row is not None else None

    def list_grants(self, *, task_id: str | None = None) -> list[GrantRecord]:
        query = "SELECT * FROM network_grants"
        params: list[Any] = []
        if task_id is not None:
            query += " WHERE task_id = ?"
            params.append(task_id)
        query += " ORDER BY created_at, grant_id"
        with self._lock:
            rows = self.conn.execute(query, params).fetchall()
        return [_grant_from_row(row) for row in rows]

    def set_grant_status(self, grant_id: str, status: GrantStatus) -> GrantRecord:
        with self._tx():
            self.conn.execute(
                "UPDATE network_grants SET status = ? WHERE grant_id = ?",
                (status.value, grant_id),
            )
        record = self.get_grant(grant_id)
        if record is None:
            raise NotFoundError(f"unknown grant: {grant_id}")
        return record

    def consume_grant_call(self, grant_id: str, now_ms: int) -> bool:
        """Atomically validate and increment a grant's call counter."""

        with self._tx():
            row = self.conn.execute(
                "SELECT * FROM network_grants WHERE grant_id = ?", (grant_id,)
            ).fetchone()
            if row is None:
                return False
            grant = _grant_from_row(row)
            if grant.status is not GrantStatus.ACTIVE:
                return False
            if grant.expires_at <= now_ms:
                self.conn.execute(
                    "UPDATE network_grants SET status = ? WHERE grant_id = ?",
                    (GrantStatus.EXPIRED.value, grant_id),
                )
                return False
            if grant.calls_used >= grant.max_calls:
                self.conn.execute(
                    "UPDATE network_grants SET status = ? WHERE grant_id = ?",
                    (GrantStatus.EXHAUSTED.value, grant_id),
                )
                return False
            self.conn.execute(
                "UPDATE network_grants SET calls_used = calls_used + 1 WHERE grant_id = ?",
                (grant_id,),
            )
        return True

    # ------------------------------------------------------------------
    # Executions / screenshots / exports
    # ------------------------------------------------------------------

    def record_execution(self, row: dict[str, Any]) -> None:
        # The execution pipeline supplies pre-serialized ``request_json`` /
        # ``result_json`` columns; tolerate both those and object-valued
        # ``request`` / ``result`` keys so the durable ledger never silently
        # degrades to "{}".
        def _json_value(prefixed: str, plain: str) -> str:
            value = row.get(prefixed, row.get(plain, {}))
            if isinstance(value, str):
                return value or "{}"
            return json.dumps(value if value is not None else {}, ensure_ascii=False)

        request_json = _json_value("request_json", "request")
        result_json = _json_value("result_json", "result")
        with self._tx():
            self.conn.execute(
                "INSERT INTO executions(execution_id, task_id, worker_id, step_id, tool_name,"
                " tool_version, argv_json, cwd, tier, status, exit_code, reason_code, reason,"
                " started_at, ended_at, stdout_sha256, stderr_sha256, stdout_preview,"
                " stderr_preview, network_grant_id, approval_id, request_json, result_json)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    row["execution_id"],
                    row["task_id"],
                    row["worker_id"],
                    row["step_id"],
                    row["tool_name"],
                    row.get("tool_version"),
                    json.dumps(row.get("argv", []), ensure_ascii=False),
                    row["cwd"],
                    int(row.get("tier", 0)),
                    row["status"],
                    row.get("exit_code"),
                    row.get("reason_code", ""),
                    row.get("reason", ""),
                    int(row.get("started_at", self.clock.now_ms())),
                    row.get("ended_at"),
                    row.get("stdout_sha256"),
                    row.get("stderr_sha256"),
                    row.get("stdout_preview", ""),
                    row.get("stderr_preview", ""),
                    row.get("network_grant_id"),
                    row.get("approval_id"),
                    request_json,
                    result_json,
                ),
            )

    def update_execution(self, execution_id: str, updates: dict[str, Any]) -> None:
        allowed = {
            "status",
            "exit_code",
            "reason_code",
            "reason",
            "ended_at",
            "stdout_sha256",
            "stderr_sha256",
            "stdout_preview",
            "stderr_preview",
            "result_json",
        }
        filtered = {key: value for key, value in updates.items() if key in allowed}
        if not filtered:
            return
        assignments = ", ".join(f"{name} = ?" for name in filtered)
        params = list(filtered.values()) + [execution_id]
        with self._tx():
            self.conn.execute(
                f"UPDATE executions SET {assignments} WHERE execution_id = ?", params
            )

    def list_executions(self, task_id: str, *, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM executions WHERE task_id = ? ORDER BY started_at DESC, execution_id LIMIT ?",
                (task_id, int(limit)),
            ).fetchall()
        return [dict(row) for row in rows]

    def record_screenshot(self, record: ScreenshotRecord) -> None:
        with self._tx():
            self.conn.execute(
                "INSERT INTO screenshots(screenshot_id, task_id, worker_id, step_id, session_id,"
                " scope, captured_at, sha256, width, height, status, failure_reason, media_type,"
                " execution_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    record.screenshot_id,
                    record.task_id,
                    record.worker_id,
                    record.step_id,
                    record.session_id,
                    record.scope,
                    record.captured_at,
                    record.sha256,
                    record.width,
                    record.height,
                    record.status.value,
                    record.failure_reason,
                    record.media_type,
                    record.execution_id,
                ),
            )

    def list_screenshots(self, task_id: str) -> list[ScreenshotRecord]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM screenshots WHERE task_id = ? ORDER BY captured_at, screenshot_id",
                (task_id,),
            ).fetchall()
        return [ScreenshotRecord.from_row(row) for row in rows]

    def record_export(self, info: ExportInfo) -> None:
        import uuid

        with self._tx():
            self.conn.execute(
                "INSERT INTO exports(export_id, task_id, kind, path, sha256, created_at)"
                " VALUES(?,?,?,?,?,?)",
                (
                    f"exp-{uuid.uuid4().hex}",
                    getattr(info, "task_id", "") or "",
                    info.kind,
                    info.path,
                    info.sha256,
                    self.clock.now_ms(),
                ),
            )

    def count_queued(self) -> int:
        return len(self.list_tasks(status=TaskStatus.QUEUED.value))

    def workspace_for_worker(self, worker_id: str) -> str | None:
        worker = self.get_worker(worker_id)
        return worker.workspace_path if worker is not None else None


def _approval_from_row(row: Any) -> ApprovalRecord:
    payload: dict[str, Any]
    try:
        payload = json.loads(row["payload_json"] or "{}")
    except (ValueError, TypeError):  # pragma: no cover - corrupted row
        payload = {}
    return ApprovalRecord(
        approval_id=row["approval_id"],
        task_id=row["task_id"],
        action_kind=row["action_kind"],
        action_digest=row["action_digest"],
        status=ApprovalStatus(row["status"]),
        requested_at=int(row["requested_at"]),
        decided_at=row["decided_at"],
        approver=row["approver"],
        note=row["note"] or "",
        payload=payload if isinstance(payload, dict) else {},
        expires_at=row["expires_at"],
        consumed_at=row["consumed_at"],
    )


def _grant_from_row(row: Any) -> GrantRecord:
    return GrantRecord(
        grant_id=row["grant_id"],
        task_id=row["task_id"],
        competition_profile=row["competition_profile"],
        host=row["host"],
        port=int(row["port"]),
        protocol=row["protocol"],
        method=row["method"],
        path_prefix=row["path_prefix"],
        expires_at=int(row["expires_at"]),
        max_calls=int(row["max_calls"]),
        calls_used=int(row["calls_used"]),
        approver=row["approver"],
        created_at=int(row["created_at"]),
        status=GrantStatus(row["status"]),
        grant_digest=row["grant_digest"] or "",
    )


from ..core.types import SLOT_OCCUPYING_TASK_STATUSES as _SLOT_TASK_STATUSES
from ..core.types import SLOT_OCCUPYING_WORKER_STATUSES as _SLOT_WORKER_STATUSES
