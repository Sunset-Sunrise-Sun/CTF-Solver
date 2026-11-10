"""Durable Manager state repository (SQLite), implementing PolicyRepository.

All Task/Worker/approval/grant/execution state lives here. Evidence events are
appended by the evidence store; this repository only owns Manager state tables.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from typing import Any, Iterator, Mapping, Sequence

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
    ImportedInput,
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

    def get_worker_by_session(self, session_id: str) -> WorkerRecord | None:
        """Reverse-map an ACP session id through the Manager's own registry.

        Never relies on the ACP server's ``session/list``; an unknown session is
        simply absent. The mapping is unique in practice; the most recently
        created Worker wins if a session id was ever re-used.
        """

        text = str(session_id or "").strip()
        if not text:
            return None
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM workers WHERE acp_session_id = ?"
                " ORDER BY created_at DESC, worker_id DESC LIMIT 1",
                (text,),
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

    def record_approval_confirmation(
        self,
        approval_id: str,
        *,
        approved: bool,
        confirmation: Any,
        decided_at: int | None = None,
        note: str = "",
    ) -> ApprovalRecord:
        """Atomically record the only valid approval decision: a human confirmation.

        ``confirmation`` is a :class:`ctf_solver.security.confirmation.HumanConfirmation`
        (or a mapping with the same keys). It must carry the local-console
        channel, a non-empty confirmed OS user, a confirmation id, and the full
        action digest that the human was shown. Anything else -- a caller
        supplied approver string, a mismatched digest, a replayed decision, an
        expired approval -- fails closed with :class:`StateError`.
        """

        fields = _confirmation_fields(confirmation)
        channel = fields["channel"]
        os_user = fields["os_user"]
        confirmation_id = fields["confirmation_id"]
        digest = fields["approval_digest"]
        if channel != "local_console":
            raise StateError(
                "an approval decision requires the local console confirmation channel; "
                f"got {channel!r}"
            )
        if not os_user:
            raise StateError("a human confirmation requires a recorded OS user identity")
        if not confirmation_id:
            raise StateError("a human confirmation requires a confirmation id")
        if not isinstance(approved, bool):
            raise StateError("approved must be a boolean")
        with self._tx():
            record = self.get_approval(approval_id)
            if record is None:
                raise NotFoundError(f"unknown approval: {approval_id}")
            now = int(decided_at) if decided_at is not None else self.clock.now_ms()
            if record.status is not ApprovalStatus.PENDING:
                raise StateError(f"approval {approval_id} is already {record.status.value}")
            if digest != str(record.action_digest or "").strip().lower():
                raise StateError(
                    "the human confirmation digest does not match the approval action digest"
                )
            if record.expires_at is not None and int(record.expires_at) <= now:
                self.conn.execute(
                    "UPDATE approvals SET status = ? WHERE approval_id = ? AND status = ?",
                    (ApprovalStatus.EXPIRED.value, approval_id, ApprovalStatus.PENDING.value),
                )
                expired = True
            else:
                expired = False
                status = ApprovalStatus.APPROVED if approved else ApprovalStatus.REJECTED
                decision_note = str(note or fields["note"] or "")
                cursor = self.conn.execute(
                    "UPDATE approvals SET status = ?, decided_at = ?, approver = ?, note = ?,"
                    " confirmation_channel = ?, confirmation_id = ?, confirmation_os_user = ?,"
                    " confirmation_note = ?"
                    " WHERE approval_id = ? AND status = ?",
                    (
                        status.value,
                        now,
                        os_user,
                        decision_note,
                        channel,
                        confirmation_id,
                        os_user,
                        decision_note,
                        approval_id,
                        ApprovalStatus.PENDING.value,
                    ),
                )
                if cursor.rowcount != 1:
                    raise StateError(
                        f"approval {approval_id} could not be decided atomically "
                        "(already decided, expired or replayed)"
                    )
        if expired:
            raise StateError(f"approval {approval_id} has expired")
        return self.get_approval(approval_id)  # type: ignore[return-value]

    def mark_approval_expired(self, approval_id: str) -> bool:
        """Mark a still-pending approval as expired; returns whether it changed."""

        with self._tx():
            cursor = self.conn.execute(
                "UPDATE approvals SET status = ? WHERE approval_id = ? AND status = ?",
                (ApprovalStatus.EXPIRED.value, approval_id, ApprovalStatus.PENDING.value),
            )
            return cursor.rowcount == 1

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
        """Atomically validate and consume a one-shot human-confirmed approval.

        The approval must be APPROVED, unexpired, unused, and must carry the
        recorded local-console human confirmation fields. An approved approval
        without a human confirmation (for example a legacy row) can never be
        consumed, so callers cannot bypass the human decision path.
        """

        with self._tx():
            record = self.get_approval(approval_id)
            if record is None:
                return False
            if record.status is not ApprovalStatus.APPROVED:
                return False
            if record.consumed_at is not None:
                return False
            if not (
                record.confirmation_channel == "local_console"
                and record.confirmation_id
                and record.confirmation_os_user
            ):
                return False
            if record.expires_at is not None and int(record.expires_at) <= int(now_ms):
                return False
            cursor = self.conn.execute(
                "UPDATE approvals SET consumed_at = ?"
                " WHERE approval_id = ? AND status = ? AND consumed_at IS NULL"
                " AND confirmation_channel = 'local_console'"
                " AND confirmation_id IS NOT NULL AND confirmation_id != ''"
                " AND confirmation_os_user IS NOT NULL AND confirmation_os_user != ''",
                (now_ms, approval_id, ApprovalStatus.APPROVED.value),
            )
            return cursor.rowcount == 1

    # ------------------------------------------------------------------
    # Network grants
    # ------------------------------------------------------------------

    def create_grant(self, grant: GrantRecord) -> GrantRecord:
        """Insert a network grant row.

        This is a low-level repository primitive; the public use-case API is
        :meth:`ctf_solver.manager.approval_grant_service.ApprovalGrantService.create_grant_from_approval`,
        which is the only accepted path. It is never exposed through MCP.
        """

        with self._tx():
            self._insert_grant_row(grant)
        return self.get_grant(grant.grant_id)  # type: ignore[return-value]

    def _insert_grant_row(self, grant: GrantRecord) -> None:
        try:
            self.conn.execute(
                "INSERT INTO network_grants(grant_id, task_id, competition_profile, host, port,"
                " protocol, method, path_prefix, expires_at, max_calls, calls_used, approver,"
                " created_at, status, grant_digest, approval_id, confirmation_id,"
                " confirmation_os_user)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
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
                    grant.approval_id,
                    grant.confirmation_id,
                    grant.confirmation_os_user,
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise StorageError(f"could not insert network grant {grant.grant_id!r}") from exc

    def create_grant_from_approval(
        self, approval_id: str, grant: GrantRecord, now_ms: int
    ) -> bool:
        """Atomically consume one human-confirmed approval and insert its grant.

        Returns ``False`` (and changes nothing) when the approval is missing,
        not approved, already consumed, expired, missing human confirmation
        fields, or belongs to a different Task than ``grant.task_id``. Exactly
        one caller can win this compare-and-set, so an approval mints at most
        one grant.
        """

        with self._tx():
            record = self.get_approval(approval_id)
            if record is None:
                return False
            if record.status is not ApprovalStatus.APPROVED:
                return False
            if record.consumed_at is not None:
                return False
            if not (
                record.confirmation_channel == "local_console"
                and record.confirmation_id
                and record.confirmation_os_user
            ):
                return False
            if record.expires_at is not None and int(record.expires_at) <= int(now_ms):
                return False
            if grant.task_id != record.task_id:
                return False
            if grant.approval_id != approval_id:
                return False
            if (
                not grant.confirmation_id
                or grant.confirmation_os_user != record.confirmation_os_user
            ):
                return False
            cursor = self.conn.execute(
                "UPDATE approvals SET consumed_at = ?"
                " WHERE approval_id = ? AND status = ? AND consumed_at IS NULL"
                " AND confirmation_channel = 'local_console'"
                " AND confirmation_id IS NOT NULL AND confirmation_id != ''"
                " AND confirmation_os_user IS NOT NULL AND confirmation_os_user != ''",
                (now_ms, approval_id, ApprovalStatus.APPROVED.value),
            )
            if cursor.rowcount != 1:
                return False
            self._insert_grant_row(grant)
            return True

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
    # Task inputs (Manager-controlled challenge file registry)
    # ------------------------------------------------------------------

    def record_task_inputs(
        self, task_id: str, inputs: Sequence[ImportedInput] | Sequence[Mapping[str, Any]]
    ) -> None:
        """Upsert the Manager-controlled registry of imported challenge files.

        ``rel_path`` is workspace-relative and authoritative; ``source_rel_path``
        is the intake-root-relative provenance only. Re-importing the same
        relative path updates its hash/metadata and never duplicates rows.
        """

        task = self.require_task(task_id)
        now = self.clock.now_ms()
        rows: list[tuple[Any, ...]] = []
        for item in inputs or ():
            fields = _imported_input_fields(item)
            if not fields["rel_path"]:
                raise StorageError("an imported input requires a non-empty rel_path")
            if not fields["sha256"]:
                raise StorageError(
                    f"imported input {fields['rel_path']!r} requires a SHA-256 digest"
                )
            rows.append(
                (
                    task.task_id,
                    fields["rel_path"],
                    fields["sha256"],
                    int(fields["size"]),
                    fields["media_type"] or "application/octet-stream",
                    fields["source_rel_path"],
                    int(fields["imported_at"] or now),
                )
            )
        if not rows:
            return
        with self._tx():
            self.conn.executemany(
                "INSERT INTO task_inputs(task_id, rel_path, sha256, size, media_type,"
                " source_rel_path, imported_at) VALUES(?,?,?,?,?,?,?)"
                " ON CONFLICT(task_id, rel_path) DO UPDATE SET"
                " sha256 = excluded.sha256, size = excluded.size,"
                " media_type = excluded.media_type,"
                " source_rel_path = excluded.source_rel_path,"
                " imported_at = excluded.imported_at",
                rows,
            )

    def list_task_inputs(self, task_id: str) -> list[ImportedInput]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM task_inputs WHERE task_id = ? ORDER BY rel_path",
                (task_id,),
            ).fetchall()
        return [ImportedInput.from_row(row) for row in rows]

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
        confirmation_channel=row["confirmation_channel"],
        confirmation_id=row["confirmation_id"],
        confirmation_os_user=row["confirmation_os_user"],
        confirmation_note=row["confirmation_note"],
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
        approval_id=row["approval_id"],
        confirmation_id=row["confirmation_id"],
        confirmation_os_user=row["confirmation_os_user"],
    )


def _confirmation_fields(confirmation: Any) -> dict[str, str]:
    """Read human-confirmation fields from an object or a mapping (fail closed)."""

    if confirmation is None:
        raise StateError("a human confirmation record is required to decide an approval")

    def _get(name: str) -> Any:
        if isinstance(confirmation, Mapping):
            return confirmation.get(name)
        return getattr(confirmation, name, None)

    def _text(name: str) -> str:
        value = _get(name)
        return "" if value is None else str(value).strip()

    return {
        "channel": _text("channel").lower(),
        "os_user": _text("os_user"),
        "confirmation_id": _text("confirmation_id"),
        "approval_digest": _text("approval_digest").lower(),
        "note": "" if _get("note") is None else str(_get("note")),
    }


def _imported_input_fields(item: Any) -> dict[str, Any]:
    if isinstance(item, ImportedInput):
        return {
            "rel_path": item.rel_path,
            "sha256": item.sha256.lower(),
            "size": item.size,
            "media_type": item.media_type,
            "source_rel_path": item.source_rel_path,
            "imported_at": item.imported_at,
        }
    if isinstance(item, Mapping):
        return {
            "rel_path": str(item.get("rel_path") or ""),
            "sha256": str(item.get("sha256") or "").lower(),
            "size": int(item.get("size", 0) or 0),
            "media_type": str(item.get("media_type") or "application/octet-stream"),
            "source_rel_path": str(item.get("source_rel_path") or ""),
            "imported_at": int(item.get("imported_at", 0) or 0),
        }
    raise StorageError(
        f"imported inputs must be ImportedInput or mapping values, got {type(item).__name__}"
    )


from ..core.types import SLOT_OCCUPYING_TASK_STATUSES as _SLOT_TASK_STATUSES
from ..core.types import SLOT_OCCUPYING_WORKER_STATUSES as _SLOT_WORKER_STATUSES
