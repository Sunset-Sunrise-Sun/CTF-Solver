"""Tests for the Round 1 Lead-session binding, schema 1.2 and Lead log resolution.

Covered here (contract section 6, owner A):

* additive migrations ``1.0 -> 1.2`` and ``1.1 -> 1.2`` on real temp SQLite files;
* the one-time binding store API and its uniqueness conflicts;
* ``completion_note`` persistence in the finalize paths and Task serialisation;
* ``SolverConfig.lead_sessions_root`` priority / no-create rules;
* Lead log resolution from a *separate* live root: happy path with a real
  multi-frame zstd fixture, header id mismatch, header cwd mismatch, missing
  root, missing binding, ambiguous logs, unsafe/tampered binding ids;
* the clarified ``auto`` rule: an explicit Lead binding wins over the shell-only
  Worker, while ``source="worker"`` keeps the pre-existing worker-only path.

Synthetic fixtures only: multi-frame zstd logs are built with
``tests.support.zstd_fixtures`` and session event shapes with
``tests.support.session_events``. No Harness process or model call is used.
"""

from __future__ import annotations

import hashlib
import os
import sqlite3
from pathlib import Path

import pytest

from ctf_solver import SCHEMA_VERSION
from ctf_solver.core.canonical import GENESIS_HASH
from ctf_solver.core.config import SolverConfig
from ctf_solver.core.errors import NotFoundError, StateError, ValidationError
from ctf_solver.core.types import (
    Category,
    TaskRecord,
    TaskStatus,
    WorkerRecord,
    WorkerStatus,
)
from ctf_solver.evidence.zstd_frames import decode_all
from ctf_solver.manager.session_logs import (
    REASON_AMBIGUOUS_SESSION_LOG,
    REASON_HEADER_MISMATCH,
    REASON_LEAD_CWD_MISMATCH,
    REASON_LEAD_ROOT_MISSING,
    REASON_LOG_MISSING,
    REASON_NO_BINDING,
    REASON_NO_WORKER,
    REASON_SYMLINK_REJECTED,
    REASON_UNKNOWN_SESSION,
    SESSION_LOG_FILENAME,
    SessionLogError,
    SessionLogResolver,
)
from ctf_solver.manager.store import ManagerStore, SessionBinding
from ctf_solver.storage.db import (
    get_meta,
    initialize_schema,
    open_database,
    table_names,
)
from tests.support.session_events import session_header, standard_session
from tests.support.zstd_fixtures import write_session_log

LEAD_SESSION = "abcdef00-1111-4222-8333-444444444444"
OTHER_SESSION = "11111111-2222-4333-8444-555555555555"
WORKER_SESSION = "99999999-8888-4777-8666-555555555555"
LEAD_SLUG_A = "D--project-live-a"
LEAD_SLUG_B = "D--project-live-b"
WORKER_SLUG = "D--ctf-solver-tasks-task-a-work"

LINK_SKIP_REASON = (
    "Windows symlink creation unavailable in this environment "
    "(not elevated and/or Developer Mode off); link case not exercised"
)


# ---------------------------------------------------------------------------
# Helpers: registry and fixtures
# ---------------------------------------------------------------------------


def _make_task(
    store: ManagerStore,
    task_id: str,
    *,
    status: TaskStatus = TaskStatus.CREATED,
    notes: str = "",
    acp_session_id: str | None = None,
) -> TaskRecord:
    task = TaskRecord(
        task_id=task_id,
        conversation_id="conv-synthetic",
        title=f"synthetic {task_id}",
        category=Category.MISC,
        workspace_path=str(Path("synthetic") / "tasks" / task_id / "work"),
        status=status,
        acp_session_id=acp_session_id,
        notes=notes,
    )
    return store.create_task(task)


def _register_worker(
    store: ManagerStore,
    task_id: str,
    *,
    worker_id: str = "w-a",
    session_id: str = WORKER_SESSION,
) -> WorkerRecord:
    worker = WorkerRecord(
        worker_id=worker_id,
        task_id=task_id,
        acp_session_id=session_id,
        workspace_path=str(Path("synthetic") / "tasks" / task_id / "work"),
        status=WorkerStatus.RUNNING,
        worker_token=f"token-{worker_id}",
    )
    store.create_worker(worker)
    store.update_task_fields(task_id, worker_id=worker_id, acp_session_id=session_id)
    return worker


def _lead_records(session_id: str, header_cwd: Path | str) -> list[dict]:
    """Standard synthetic session whose header carries the given cwd."""

    records = standard_session(session_id=session_id)
    records[0] = session_header(session_id, cwd=str(header_cwd))
    return records


def _write_lead_log(
    lead_root: Path,
    session_id: str,
    records: list[dict],
    *,
    slug: str = LEAD_SLUG_A,
) -> Path:
    path = lead_root / slug / session_id / SESSION_LOG_FILENAME
    write_session_log(path, records, frames=6)
    return path


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _expect(error_type, reason_code: str):
    """Assert a SessionLogError carrying a stable machine-readable reason code."""

    class _Checker:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            assert exc_type is error_type, f"expected {error_type.__name__}, got {exc_type}"
            assert exc.reason_code == reason_code, (
                f"expected reason_code {reason_code!r}, got {exc.reason_code!r}: {exc}"
            )
            payload = exc.to_dict()
            assert payload["reason_code"] == reason_code
            assert payload["error"] == "SessionLogError"
            return True

    return _Checker()


@pytest.fixture
def store(tmp_path: Path):
    manager = ManagerStore(str(tmp_path / "manager.sqlite"))
    try:
        yield manager
    finally:
        manager.close()


@pytest.fixture
def sandbox(tmp_path: Path):
    manager = ManagerStore(str(tmp_path / "manager.sqlite"))
    workspace = tmp_path / "project"
    workspace.mkdir()
    worker_root = tmp_path / "managed-dsh" / "sessions"
    worker_root.mkdir(parents=True)
    lead_root = tmp_path / "live-dsh" / "sessions"
    lead_root.mkdir(parents=True)
    resolver = SessionLogResolver(
        worker_root,
        manager,
        lead_sessions_root=lead_root,
        workspace_root=workspace,
    )
    try:
        yield {
            "tmp": tmp_path,
            "store": manager,
            "worker_root": worker_root,
            "lead_root": lead_root,
            "workspace": workspace,
            "resolver": resolver,
        }
    finally:
        manager.close()


# ---------------------------------------------------------------------------
# Schema 1.2 migrations (additive, real temp SQLite files)
# ---------------------------------------------------------------------------

_LEGACY_COMMON = """
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE tasks (
    task_id          TEXT PRIMARY KEY,
    conversation_id  TEXT NOT NULL,
    title            TEXT NOT NULL,
    category         TEXT NOT NULL,
    source           TEXT NOT NULL DEFAULT '',
    scope_profile    TEXT NOT NULL DEFAULT '',
    workspace_path   TEXT NOT NULL,
    acp_session_id   TEXT,
    worker_id        TEXT,
    status           TEXT NOT NULL,
    result_state     TEXT NOT NULL DEFAULT 'unknown',
    flag_state       TEXT NOT NULL DEFAULT 'none',
    flag_value       TEXT,
    created_at       INTEGER NOT NULL,
    updated_at       INTEGER NOT NULL,
    started_at       INTEGER,
    ended_at         INTEGER,
    evidence_head    TEXT,
    notes            TEXT NOT NULL DEFAULT ''
);
CREATE TABLE approvals (
    approval_id    TEXT PRIMARY KEY,
    task_id        TEXT NOT NULL REFERENCES tasks(task_id),
    action_kind    TEXT NOT NULL,
    action_digest  TEXT NOT NULL,
    status         TEXT NOT NULL,
    requested_at   INTEGER NOT NULL,
    decided_at     INTEGER,
    approver       TEXT,
    note           TEXT NOT NULL DEFAULT '',
    payload_json   TEXT NOT NULL DEFAULT '{}',
    expires_at     INTEGER,
    consumed_at    INTEGER
);
CREATE TABLE network_grants (
    grant_id            TEXT PRIMARY KEY,
    task_id             TEXT NOT NULL REFERENCES tasks(task_id),
    competition_profile TEXT NOT NULL,
    host                TEXT NOT NULL,
    port                INTEGER NOT NULL,
    protocol            TEXT NOT NULL,
    method              TEXT NOT NULL,
    path_prefix         TEXT NOT NULL DEFAULT '/',
    expires_at          INTEGER NOT NULL,
    max_calls           INTEGER NOT NULL,
    calls_used          INTEGER NOT NULL DEFAULT 0,
    approver            TEXT NOT NULL,
    created_at          INTEGER NOT NULL,
    status              TEXT NOT NULL,
    grant_digest        TEXT NOT NULL DEFAULT ''
);
INSERT INTO tasks(
    task_id, conversation_id, title, category, source, scope_profile,
    workspace_path, status, created_at, updated_at, notes)
VALUES(
    'task-legacy', 'conv-legacy', 'legacy task', 'misc', '', '',
    'D:/legacy/tasks/task-legacy/work', 'queued', 1, 1, 'legacy intake notes');
INSERT INTO approvals(
    approval_id, task_id, action_kind, action_digest, status, requested_at)
VALUES('apr-legacy', 'task-legacy', 'tool_action', 'a', 'pending', 1);
"""

_LEGACY_V11_ADDITIONS = """
ALTER TABLE approvals ADD COLUMN confirmation_channel TEXT;
ALTER TABLE approvals ADD COLUMN confirmation_id TEXT;
ALTER TABLE approvals ADD COLUMN confirmation_os_user TEXT;
ALTER TABLE approvals ADD COLUMN confirmation_note TEXT;
ALTER TABLE network_grants ADD COLUMN approval_id TEXT;
ALTER TABLE network_grants ADD COLUMN confirmation_id TEXT;
ALTER TABLE network_grants ADD COLUMN confirmation_os_user TEXT;
CREATE TABLE task_inputs (
    task_id         TEXT NOT NULL REFERENCES tasks(task_id),
    rel_path        TEXT NOT NULL,
    sha256          TEXT NOT NULL,
    size            INTEGER NOT NULL,
    media_type      TEXT NOT NULL DEFAULT 'application/octet-stream',
    source_rel_path TEXT NOT NULL DEFAULT '',
    imported_at     INTEGER NOT NULL,
    PRIMARY KEY (task_id, rel_path)
);
INSERT INTO task_inputs(
    task_id, rel_path, sha256, size, media_type, source_rel_path, imported_at)
VALUES('task-legacy', 'README.md', 'deadbeef', 10, 'text/plain', '', 2);
"""


def _build_legacy_db(path: Path, version: str) -> None:
    """Create a real legacy-schema database (``"1.0"`` or ``"1.1"``)."""

    assert version in ("1.0", "1.1")
    conn = sqlite3.connect(str(path), isolation_level=None)
    try:
        conn.executescript(_LEGACY_COMMON)
        if version == "1.1":
            conn.executescript(_LEGACY_V11_ADDITIONS)
        conn.execute("INSERT INTO meta(key, value) VALUES('schema_version', ?)", (version,))
    finally:
        conn.close()


def _assert_migrated_1_2(conn: sqlite3.Connection, *, legacy_version: str) -> None:
    assert SCHEMA_VERSION == "1.2"
    assert get_meta(conn, "schema_version") == "1.2"
    task_columns = {row["name"] for row in conn.execute("PRAGMA table_info(tasks)")}
    assert "completion_note" in task_columns
    names = set(table_names(conn))
    assert "session_bindings" in names
    assert "idx_session_bindings_task" in {
        row["name"] for row in conn.execute("PRAGMA index_list(session_bindings)")
    }
    # Existing rows survive; the new column is defaulted and the intake notes
    # are never overwritten.
    task_row = conn.execute("SELECT * FROM tasks WHERE task_id = 'task-legacy'").fetchone()
    assert task_row is not None
    assert task_row["title"] == "legacy task"
    assert task_row["notes"] == "legacy intake notes"
    assert task_row["completion_note"] == ""
    approval_row = conn.execute(
        "SELECT * FROM approvals WHERE approval_id = 'apr-legacy'"
    ).fetchone()
    assert approval_row is not None
    if legacy_version == "1.0":
        approval_columns = {
            row["name"] for row in conn.execute("PRAGMA table_info(approvals)")
        }
        assert {
            "confirmation_channel",
            "confirmation_id",
            "confirmation_os_user",
            "confirmation_note",
        } <= approval_columns
        assert "task_inputs" in names
    else:
        assert conn.execute("SELECT COUNT(*) AS n FROM task_inputs").fetchone()["n"] == 1
    assert get_meta(conn, "events_chain_head") == GENESIS_HASH


def test_migration_1_0_to_1_2(tmp_path: Path) -> None:
    db_path = tmp_path / "legacy-1.0.sqlite"
    _build_legacy_db(db_path, "1.0")
    conn = open_database(db_path)
    try:
        _assert_migrated_1_2(conn, legacy_version="1.0")
        # Re-initialising a migrated database is a no-op.
        initialize_schema(conn)
        _assert_migrated_1_2(conn, legacy_version="1.0")
    finally:
        conn.close()


def test_migration_1_1_to_1_2(tmp_path: Path) -> None:
    db_path = tmp_path / "legacy-1.1.sqlite"
    _build_legacy_db(db_path, "1.1")
    conn = open_database(db_path)
    try:
        _assert_migrated_1_2(conn, legacy_version="1.1")
        initialize_schema(conn)
        _assert_migrated_1_2(conn, legacy_version="1.1")
    finally:
        conn.close()


def test_new_database_is_created_as_1_2(tmp_path: Path) -> None:
    conn = open_database(tmp_path / "fresh.sqlite")
    try:
        assert get_meta(conn, "schema_version") == "1.2"
        names = set(table_names(conn))
        assert {"tasks", "session_bindings", "task_inputs"} <= names
        task_columns = {row["name"] for row in conn.execute("PRAGMA table_info(tasks)")}
        assert "completion_note" in task_columns
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# One-time binding store API
# ---------------------------------------------------------------------------


def test_bind_lead_session_round_trip(store: ManagerStore) -> None:
    _make_task(store, "task-a")

    binding = store.bind_lead_session(
        task_id="task-a", session_id=LEAD_SESSION, log_sha256="a" * 64
    )

    assert isinstance(binding, SessionBinding)
    assert binding.session_id == LEAD_SESSION
    assert binding.task_id == "task-a"
    assert binding.bound_by == "lead"
    assert binding.log_sha256 == "a" * 64
    assert binding.bound_at > 0
    assert store.get_lead_binding("task-a") == binding
    assert store.get_task_for_lead_session(LEAD_SESSION) == "task-a"
    assert binding.to_dict() == {
        "session_id": LEAD_SESSION,
        "task_id": "task-a",
        "bound_at": binding.bound_at,
        "bound_by": "lead",
        "log_sha256": "a" * 64,
    }
    assert store.get_lead_binding("task-missing") is None
    assert store.get_task_for_lead_session("unknown-session") is None
    assert store.get_lead_binding("") is None
    assert store.get_task_for_lead_session("") is None


def test_bind_same_task_twice_rejected(store: ManagerStore) -> None:
    _make_task(store, "task-a")
    store.bind_lead_session(task_id="task-a", session_id=LEAD_SESSION)

    with pytest.raises(StateError):
        store.bind_lead_session(task_id="task-a", session_id=OTHER_SESSION)
    # The original binding is untouched: this is not a silent replace.
    assert store.get_lead_binding("task-a").session_id == LEAD_SESSION
    assert store.get_task_for_lead_session(OTHER_SESSION) is None


def test_bind_same_session_to_two_tasks_rejected(store: ManagerStore) -> None:
    _make_task(store, "task-a")
    _make_task(store, "task-b")
    store.bind_lead_session(task_id="task-a", session_id=LEAD_SESSION)

    with pytest.raises(StateError):
        store.bind_lead_session(task_id="task-b", session_id=LEAD_SESSION)
    assert store.get_lead_binding("task-b") is None
    assert store.get_task_for_lead_session(LEAD_SESSION) == "task-a"


def test_bind_unknown_task_rejected(store: ManagerStore) -> None:
    with pytest.raises(NotFoundError):
        store.bind_lead_session(task_id="task-missing", session_id=LEAD_SESSION)


def test_bind_empty_session_id_rejected(store: ManagerStore) -> None:
    _make_task(store, "task-a")
    with pytest.raises(StateError):
        store.bind_lead_session(task_id="task-a", session_id="   ")
    assert store.get_lead_binding("task-a") is None


# ---------------------------------------------------------------------------
# completion_note persistence
# ---------------------------------------------------------------------------


def _completion_task(store: ManagerStore, *, status: TaskStatus) -> TaskRecord:
    task = _make_task(
        store,
        "task-a",
        status=status,
        notes="intake record",
        acp_session_id=WORKER_SESSION,
    )
    store.create_worker(
        WorkerRecord(
            worker_id="w-a",
            task_id="task-a",
            acp_session_id=WORKER_SESSION,
            workspace_path=task.workspace_path,
            status=WorkerStatus.RUNNING,
            worker_token="token-w-a",
        )
    )
    return task


def test_finalize_completion_writes_completion_note(store: ManagerStore) -> None:
    _completion_task(store, status=TaskStatus.COMPLETION_PENDING)

    finalized = store.finalize_task_completion(
        "task-a",
        worker_id="w-a",
        result_state="solved_flag_candidate",
        ended_at=1234,
        notes="outcome record",
    )

    assert finalized.status is TaskStatus.COMPLETED
    assert finalized.completion_note == "outcome record"
    assert finalized.notes == "intake record"
    assert store.get_worker("w-a").status is WorkerStatus.STOPPED


def test_finalize_interruption_writes_completion_note(store: ManagerStore) -> None:
    _completion_task(store, status=TaskStatus.RUNNING)

    finalized = store.finalize_task_interruption(
        "task-a",
        expected_status=TaskStatus.RUNNING,
        result_state="partial_analysis",
        ended_at=4321,
        notes="interrupted outcome record",
    )

    assert finalized.status is TaskStatus.INTERRUPTED
    assert finalized.completion_note == "interrupted outcome record"
    assert finalized.notes == "intake record"


def test_task_record_completion_note_serialisation() -> None:
    record = TaskRecord(
        task_id="task-a",
        conversation_id="conv",
        title="synthetic",
        category=Category.MISC,
        workspace_path="D:/synthetic/tasks/task-a/work",
        completion_note="outcome",
    )
    payload = record.to_dict()
    assert payload["completion_note"] == "outcome"

    legacy_row = {key: value for key, value in payload.items() if key != "completion_note"}
    restored = TaskRecord.from_row(legacy_row)
    assert restored.completion_note == ""


# ---------------------------------------------------------------------------
# SolverConfig.lead_sessions_root
# ---------------------------------------------------------------------------


def test_lead_sessions_root_priority(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("CTF_SOLVER_LEAD_SESSIONS_ROOT", raising=False)
    config = SolverConfig(root=tmp_path / "project")
    assert config.lead_sessions_root == Path.home() / ".dsh" / "sessions"

    env_root = tmp_path / "env-sessions"
    monkeypatch.setenv("CTF_SOLVER_LEAD_SESSIONS_ROOT", str(env_root))
    assert config.lead_sessions_root == env_root

    extra_root = tmp_path / "extra-sessions"
    configured = SolverConfig(
        root=tmp_path / "project", extra={"lead_sessions_root": str(extra_root)}
    )
    assert configured.lead_sessions_root == extra_root


def test_lead_sessions_root_is_not_derived_from_dsh_home(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("CTF_SOLVER_LEAD_SESSIONS_ROOT", raising=False)
    isolated = SolverConfig(
        root=tmp_path / "project", extra={"dsh_home": str(tmp_path / "isolated-home")}
    )
    assert isolated.dsh_home == tmp_path / "isolated-home"
    assert isolated.lead_sessions_root == Path.home() / ".dsh" / "sessions"


def test_ensure_runtime_dirs_does_not_create_lead_root(tmp_path: Path) -> None:
    lead_root = tmp_path / "live-dsh" / "sessions"
    config = SolverConfig(
        root=tmp_path / "project", extra={"lead_sessions_root": str(lead_root)}
    )

    config.ensure_runtime_dirs()

    assert not lead_root.exists()
    assert config.paths.data_dir.is_dir()
    assert config.dsh_home.is_dir()
    assert config.session_log_root.is_dir()


# ---------------------------------------------------------------------------
# Lead resolution: validation, happy path, content identity
# ---------------------------------------------------------------------------


def test_validate_lead_candidate_returns_path_and_raw_sha(sandbox) -> None:
    _make_task(sandbox["store"], "task-a")
    path = _write_lead_log(
        sandbox["lead_root"],
        LEAD_SESSION,
        _lead_records(LEAD_SESSION, sandbox["workspace"]),
    )

    session_id, resolved_path, raw_sha256 = sandbox["resolver"].validate_lead_candidate(
        LEAD_SESSION
    )

    assert session_id == LEAD_SESSION
    assert resolved_path == path
    assert raw_sha256 == _sha256(path)
    # Validation alone must not create a binding.
    assert sandbox["store"].get_lead_binding("task-a") is None
    assert sandbox["store"].get_task_for_lead_session(LEAD_SESSION) is None


def test_lead_resolution_happy_path_multiframe_log(sandbox) -> None:
    _make_task(sandbox["store"], "task-a")
    path = _write_lead_log(
        sandbox["lead_root"],
        LEAD_SESSION,
        _lead_records(LEAD_SESSION, sandbox["workspace"]),
    )
    assert len(decode_all(path.read_bytes()).frames) > 1
    sandbox["store"].bind_lead_session(
        task_id="task-a", session_id=LEAD_SESSION, log_sha256=_sha256(path)
    )

    resolved = sandbox["resolver"].resolve("task-a", source="lead")

    assert resolved.task_id == "task-a"
    assert resolved.worker_id is None
    assert resolved.session_id == LEAD_SESSION
    assert resolved.path == path
    assert resolved.source == "lead"
    assert resolved.to_dict() == {
        "task_id": "task-a",
        "worker_id": None,
        "session_id": LEAD_SESSION,
        "path": str(path),
        "source": "lead",
    }


def test_lead_header_id_mismatch_rejected(sandbox) -> None:
    _make_task(sandbox["store"], "task-a")
    path = _write_lead_log(
        sandbox["lead_root"],
        LEAD_SESSION,
        _lead_records(OTHER_SESSION, sandbox["workspace"]),
    )
    sandbox["store"].bind_lead_session(
        task_id="task-a", session_id=LEAD_SESSION, log_sha256=_sha256(path)
    )

    with _expect(SessionLogError, REASON_HEADER_MISMATCH):
        sandbox["resolver"].validate_lead_candidate(LEAD_SESSION)
    with pytest.raises(SessionLogError) as info:
        sandbox["resolver"].resolve("task-a", source="lead")
    assert info.value.reason_code == REASON_HEADER_MISMATCH
    assert info.value.details["header_session_id"] == OTHER_SESSION


def test_lead_cwd_mismatch_rejected(sandbox) -> None:
    _make_task(sandbox["store"], "task-a")
    other_workspace = sandbox["tmp"] / "other-workspace"
    other_workspace.mkdir()
    path = _write_lead_log(
        sandbox["lead_root"],
        LEAD_SESSION,
        _lead_records(LEAD_SESSION, other_workspace),
    )
    sandbox["store"].bind_lead_session(
        task_id="task-a", session_id=LEAD_SESSION, log_sha256=_sha256(path)
    )

    with pytest.raises(SessionLogError) as info:
        sandbox["resolver"].validate_lead_candidate(LEAD_SESSION)
    assert info.value.reason_code == REASON_LEAD_CWD_MISMATCH
    with _expect(SessionLogError, REASON_LEAD_CWD_MISMATCH):
        sandbox["resolver"].resolve("task-a", source="lead")


def test_lead_cwd_check_skipped_without_workspace_root(sandbox) -> None:
    """The cwd check is only enforceable when production wiring supplies the root."""

    _make_task(sandbox["store"], "task-a")
    path = _write_lead_log(
        sandbox["lead_root"],
        LEAD_SESSION,
        _lead_records(LEAD_SESSION, sandbox["tmp"] / "unrelated-cwd"),
    )
    sandbox["store"].bind_lead_session(
        task_id="task-a", session_id=LEAD_SESSION, log_sha256=_sha256(path)
    )
    resolver = SessionLogResolver(
        sandbox["worker_root"],
        sandbox["store"],
        lead_sessions_root=sandbox["lead_root"],
    )

    resolved = resolver.resolve("task-a", source="lead")
    assert resolved.source == "lead"
    assert resolved.path == path


def test_missing_lead_root_rejected(sandbox) -> None:
    _make_task(sandbox["store"], "task-a")
    no_root = SessionLogResolver(sandbox["worker_root"], sandbox["store"])
    absent_root = SessionLogResolver(
        sandbox["worker_root"],
        sandbox["store"],
        lead_sessions_root=sandbox["tmp"] / "absent-live-sessions",
    )

    with _expect(SessionLogError, REASON_LEAD_ROOT_MISSING):
        no_root.resolve("task-a", source="lead")
    with _expect(SessionLogError, REASON_LEAD_ROOT_MISSING):
        no_root.validate_lead_candidate(LEAD_SESSION)
    with _expect(SessionLogError, REASON_LEAD_ROOT_MISSING):
        absent_root.validate_lead_candidate(LEAD_SESSION)


def test_no_binding_rejected(sandbox) -> None:
    _make_task(sandbox["store"], "task-a")
    _write_lead_log(
        sandbox["lead_root"],
        LEAD_SESSION,
        _lead_records(LEAD_SESSION, sandbox["workspace"]),
    )

    with _expect(SessionLogError, REASON_NO_BINDING):
        sandbox["resolver"].resolve("task-a", source="lead")


def test_bound_lead_log_missing_rejected(sandbox) -> None:
    _make_task(sandbox["store"], "task-a")
    sandbox["store"].bind_lead_session(task_id="task-a", session_id=LEAD_SESSION)

    with _expect(SessionLogError, REASON_LOG_MISSING):
        sandbox["resolver"].resolve("task-a", source="lead")


def test_ambiguous_lead_logs_rejected(sandbox) -> None:
    records = _lead_records(LEAD_SESSION, sandbox["workspace"])
    _write_lead_log(sandbox["lead_root"], LEAD_SESSION, records, slug=LEAD_SLUG_A)
    _write_lead_log(sandbox["lead_root"], LEAD_SESSION, records, slug=LEAD_SLUG_B)

    with _expect(SessionLogError, REASON_AMBIGUOUS_SESSION_LOG):
        sandbox["resolver"].validate_lead_candidate(LEAD_SESSION)


def test_unsafe_lead_candidate_session_id_rejected(sandbox) -> None:
    for session_id in ("../../outside", "C:\\Windows\\System32", "/etc/passwd", "..", ""):
        with _expect(SessionLogError, REASON_UNKNOWN_SESSION):
            sandbox["resolver"].validate_lead_candidate(session_id)


def test_tampered_binding_with_unsafe_session_id_rejected(sandbox) -> None:
    _make_task(sandbox["store"], "task-a")
    sandbox["store"].conn.execute(
        "INSERT INTO session_bindings(session_id, task_id, bound_at, bound_by, log_sha256)"
        " VALUES(?,?,?,?,?)",
        ("../../outside", "task-a", 1, "lead", None),
    )

    with _expect(SessionLogError, REASON_UNKNOWN_SESSION):
        sandbox["resolver"].resolve("task-a", source="lead")


def test_symlinked_lead_root_rejected(sandbox) -> None:
    real_root = sandbox["tmp"] / "real-live-dsh" / "sessions"
    real_root.mkdir(parents=True)
    link_root = sandbox["tmp"] / "linked-live-dsh"
    try:
        os.symlink(real_root, link_root, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip(LINK_SKIP_REASON)
    _write_lead_log(
        real_root,
        LEAD_SESSION,
        _lead_records(LEAD_SESSION, sandbox["workspace"]),
    )
    resolver = SessionLogResolver(
        sandbox["worker_root"],
        sandbox["store"],
        lead_sessions_root=link_root,
        workspace_root=sandbox["workspace"],
    )

    with _expect(SessionLogError, REASON_SYMLINK_REJECTED):
        resolver.validate_lead_candidate(LEAD_SESSION)


# ---------------------------------------------------------------------------
# source selector: worker unchanged, auto prefers an explicit Lead binding
# ---------------------------------------------------------------------------


def _write_worker_log(sandbox, *, session_id: str = WORKER_SESSION) -> Path:
    path = sandbox["worker_root"] / WORKER_SLUG / session_id / SESSION_LOG_FILENAME
    write_session_log(path, standard_session(session_id=session_id), frames=4)
    return path


def test_source_worker_unchanged_for_worker_only_task(sandbox) -> None:
    _make_task(sandbox["store"], "task-a")
    _register_worker(sandbox["store"], "task-a")
    path = _write_worker_log(sandbox)

    resolved = sandbox["resolver"].resolve("task-a", source="worker")

    assert resolved.source == "worker"
    assert resolved.worker_id == "w-a"
    assert resolved.session_id == WORKER_SESSION
    assert resolved.path == path


def test_source_worker_never_falls_back_to_lead(sandbox) -> None:
    _make_task(sandbox["store"], "task-a")
    _write_lead_log(
        sandbox["lead_root"],
        LEAD_SESSION,
        _lead_records(LEAD_SESSION, sandbox["workspace"]),
    )
    sandbox["store"].bind_lead_session(task_id="task-a", session_id=LEAD_SESSION)

    with _expect(SessionLogError, REASON_NO_WORKER):
        sandbox["resolver"].resolve("task-a", source="worker")


def test_source_lead_never_falls_back_to_worker(sandbox) -> None:
    _make_task(sandbox["store"], "task-a")
    _register_worker(sandbox["store"], "task-a")
    _write_worker_log(sandbox)

    with _expect(SessionLogError, REASON_NO_BINDING):
        sandbox["resolver"].resolve("task-a", source="lead")


def test_auto_uses_worker_when_no_binding(sandbox) -> None:
    _make_task(sandbox["store"], "task-a")
    _register_worker(sandbox["store"], "task-a")
    _write_worker_log(sandbox)

    resolved = sandbox["resolver"].resolve("task-a")

    assert resolved.source == "worker"
    assert resolved.worker_id == "w-a"


def test_auto_prefers_lead_binding_over_shell_worker(sandbox) -> None:
    _make_task(sandbox["store"], "task-a")
    _register_worker(sandbox["store"], "task-a")
    _write_worker_log(sandbox)
    lead_path = _write_lead_log(
        sandbox["lead_root"],
        LEAD_SESSION,
        _lead_records(LEAD_SESSION, sandbox["workspace"]),
    )
    sandbox["store"].bind_lead_session(
        task_id="task-a", session_id=LEAD_SESSION, log_sha256=_sha256(lead_path)
    )

    resolved = sandbox["resolver"].resolve("task-a")

    assert resolved.source == "lead"
    assert resolved.path == lead_path
    assert resolved.worker_id is None


def test_auto_uses_lead_when_binding_without_worker(sandbox) -> None:
    _make_task(sandbox["store"], "task-a")
    path = _write_lead_log(
        sandbox["lead_root"],
        LEAD_SESSION,
        _lead_records(LEAD_SESSION, sandbox["workspace"]),
    )
    sandbox["store"].bind_lead_session(
        task_id="task-a", session_id=LEAD_SESSION, log_sha256=_sha256(path)
    )

    resolved = sandbox["resolver"].resolve("task-a")

    assert resolved.source == "lead"
    assert resolved.path == path


def test_auto_does_not_silently_fall_back_when_bound_lead_log_missing(sandbox) -> None:
    _make_task(sandbox["store"], "task-a")
    _register_worker(sandbox["store"], "task-a")
    _write_worker_log(sandbox)
    sandbox["store"].bind_lead_session(task_id="task-a", session_id=LEAD_SESSION)

    with _expect(SessionLogError, REASON_LOG_MISSING):
        sandbox["resolver"].resolve("task-a")


def test_unknown_source_rejected(sandbox) -> None:
    with pytest.raises(ValidationError):
        sandbox["resolver"].resolve("task-a", source="bogus")


# ---------------------------------------------------------------------------
# Wiring: the live Lead root and Manager root reach the service constructor
# ---------------------------------------------------------------------------


def test_wiring_passes_lead_root_and_workspace_root(tmp_path: Path, monkeypatch) -> None:
    import ctf_solver.wiring as wiring
    from ctf_solver.manager import service as manager_service_module

    captured: dict = {}

    class _CapturingService:
        def __init__(self, **kwargs):
            captured.update(kwargs)

    monkeypatch.setattr(manager_service_module, "ManagerService", _CapturingService)
    config = SolverConfig(root=tmp_path / "project", capture_mode="fake")

    wiring.build_manager_service(config, acp_factory=lambda: None)

    assert captured["lead_sessions_root"] == config.lead_sessions_root
    assert captured["workspace_root"] == config.root
