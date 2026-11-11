"""PHASE 2 independent verification (part 2): adversarial Lead-binding/ingest security
and service-level flow checks.

Read-only with respect to the product; every artifact stays under the verifier dir.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path
from typing import Any

WORKTREE = Path(r"D:\CTF-SOLVER\scratch\lead-round1")
BASE = Path(r"D:\CTF-SOLVER\scratch\lead-round1-plan\base-checkout")
VERIFIER = Path(r"D:\CTF-SOLVER\scratch\lead-round1-plan\verifier")
WORK = VERIFIER / "work"
sys.path.insert(0, str(WORKTREE))

from ctf_solver.core.errors import (  # noqa: E402
    NotFoundError,
    StateError,
    ValidationError,
)
from ctf_solver.core.types import (  # noqa: E402
    Category,
    TaskRecord,
    TaskStatus,
    WorkerRecord,
    WorkerStatus,
)
from ctf_solver.evidence.store import EvidenceStore  # noqa: E402
from ctf_solver.manager.service import ManagerService  # noqa: E402
from ctf_solver.manager.session_logs import (  # noqa: E402
    REASON_AMBIGUOUS_SESSION_LOG,
    REASON_HEADER_MISMATCH,
    REASON_LEAD_CWD_MISMATCH,
    REASON_LEAD_ROOT_MISSING,
    REASON_LOG_MISSING,
    REASON_NO_BINDING,
    REASON_SYMLINK_REJECTED,
    REASON_UNKNOWN_SESSION,
    SESSION_LOG_FILENAME,
    SessionLogError,
    SessionLogResolver,
)
from ctf_solver.core.config import SolverConfig  # noqa: E402
from ctf_solver.manager.store import ManagerStore  # noqa: E402
from tests.support.session_events import (  # noqa: E402
    session_header,
    standard_session,
    tool_call,
)
from tests.support.zstd_fixtures import write_session_log  # noqa: E402

LEAD_ID = "abcdef00-1111-4222-8333-444444444444"
OTHER_ID = "11111111-2222-4333-8444-555555555555"
WORKER_SESSION = "99999999-8888-4777-8666-555555555555"
RESULTS: list[dict[str, str]] = []


def record(name: str, status: str, detail: str = "") -> None:
    RESULTS.append({"check": name, "status": status, "detail": detail})
    print(f"[{status}] {name}" + (f" :: {detail}" if detail else ""))


def check(name: str, fn: Any) -> None:
    try:
        detail = fn()
        record(name, "PASS", detail if isinstance(detail, str) else "")
    except AssertionError as exc:
        record(name, "FAIL", str(exc))
    except Exception as exc:  # noqa: BLE001
        record(name, "FAIL", f"{type(exc).__name__}: {exc}")


def skip(name: str, reason: str) -> None:
    record(name, "SKIP", reason)


class SimpleClock:
    def __init__(self, start: int = 1_700_000_000_000) -> None:
        self._now = start

    def now_ms(self) -> int:
        return self._now

    def advance(self, ms: int) -> None:
        self._now += ms


def fresh_dir(name: str) -> Path:
    path = WORK / name
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True)
    return path


def make_store(root: Path, clock: SimpleClock | None = None) -> ManagerStore:
    paths = SolverConfig(root=root).ensure_layout()
    return ManagerStore(str(paths.db_path), clock or SimpleClock())


def make_task(
    store: ManagerStore,
    task_id: str,
    *,
    status: TaskStatus = TaskStatus.CREATED,
    acp_session_id: str | None = None,
    notes: str = "",
) -> TaskRecord:
    task = TaskRecord(
        task_id=task_id,
        conversation_id="conv-verify",
        title=f"synthetic {task_id}",
        category=Category.MISC,
        workspace_path=str(Path("synthetic") / "tasks" / task_id / "work"),
        status=status,
        acp_session_id=acp_session_id,
        notes=notes,
    )
    return store.create_task(task)


def register_worker(
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


def lead_records(session_id: str, cwd: str, *, header_id: str | None = None) -> list[dict]:
    records = standard_session(session_id=session_id)
    records[0] = session_header(header_id or session_id, cwd=cwd)
    return records


def write_lead_log(
    lead_root: Path,
    session_id: str,
    *,
    cwd: str,
    header_id: str | None = None,
    slug: str = "lead-slug",
    frames: int = 4,
    extra: list[dict] | None = None,
) -> bytes:
    records = lead_records(session_id, cwd, header_id=header_id)
    if extra:
        records.extend(extra)
    return write_session_log(
        lead_root / slug / session_id / SESSION_LOG_FILENAME, records, frames=frames
    )


def expect_error(fn: Any, exc_type: type[BaseException], reason: str | None = None) -> BaseException:
    try:
        fn()
    except exc_type as exc:  # type: ignore[misc]
        if reason is not None:
            got = getattr(exc, "reason_code", None)
            assert got == reason, f"expected reason_code {reason!r}, got {got!r} ({exc})"
        return exc
    except Exception as exc:  # noqa: BLE001
        raise AssertionError(
            f"expected {exc_type.__name__}, got {type(exc).__name__}: {exc}"
        ) from exc
    raise AssertionError(f"expected {exc_type.__name__}; nothing raised")


# ===========================================================================
print("=" * 78)
print("SECTION C — ADVERSARIAL LEAD-BINDING / INGEST SECURITY")
print("=" * 78)

ROOT = fresh_dir("security")
LEAD_ROOT = ROOT / "live-lead-sessions"
LEAD_ROOT.mkdir()
WORKSPACE = ROOT / "manager-root"
WORKSPACE.mkdir()
clock = SimpleClock()
store = make_store(ROOT, clock)
resolver = SessionLogResolver(
    ROOT / ".ctf-solver-data" / "dsh-home" / "sessions",
    store,
    lead_sessions_root=LEAD_ROOT,
    workspace_root=WORKSPACE,
    clock=clock,
)
RAW_VALID = write_lead_log(LEAD_ROOT, LEAD_ID, cwd=str(WORKSPACE))
task_a = make_task(store, "t-a", status=TaskStatus.RUNNING, acp_session_id="sess-worker-a")
task_b = make_task(store, "t-b", status=TaskStatus.RUNNING, acp_session_id="sess-worker-b")
register_worker(store, "t-a", worker_id="w-a", session_id="sess-worker-a")
register_worker(store, "t-b", worker_id="w-b", session_id="sess-worker-b")


def c01() -> str:
    unsafe_ids = [
        "../escape",
        "..\\escape",
        "C:\\Windows\\System32",
        "/etc/passwd",
        "a/b",
        "a\\b",
        "..",
        ".",
        "a:b",
        " padded ",
        "x" * 129,
        "\x00null",
        "line\nbreak",
        "\\\\server\\share",
    ]
    for session_id in unsafe_ids:
        err = expect_error(
            lambda sid=session_id: resolver.validate_lead_candidate(sid),
            SessionLogError,
            REASON_UNKNOWN_SESSION,
        )
        assert "safe path component" in str(err), str(err)
    return f"{len(unsafe_ids)} path/session injection attempts -> reason_code unknown_session"


check("C01 session-id path injection rejected before binding", c01)


def c02() -> str:
    # Valid-but-absent id must be log_missing, never a filesystem fallback.
    expect_error(
        lambda: resolver.validate_lead_candidate("session-absent"),
        SessionLogError,
        REASON_LOG_MISSING,
    )
    # The candidate is never created on disk by validation.
    assert not (LEAD_ROOT / "lead-slug" / "session-absent").exists()
    return "absent id -> log_missing; validation writes nothing"


check("C02 absent id fails closed with log_missing", c02)


def c03() -> str:
    # A valid on-disk log that is NOT bound cannot be ingested via source=lead.
    expect_error(
        lambda: resolver.resolve("t-a", source="lead"),
        SessionLogError,
        REASON_NO_BINDING,
    )
    # Unknown source selector fails closed.
    expect_error(
        lambda: resolver.resolve("t-a", source="bogus"),
        ValidationError,
    )
    return "no binding -> no_binding; unknown source -> ValidationError"


check("C03 unbound task cannot ingest a lead log", c03)


def c04() -> str:
    candidate_id, path, log_sha = resolver.validate_lead_candidate(LEAD_ID)
    assert candidate_id == LEAD_ID
    assert path == LEAD_ROOT / "lead-slug" / LEAD_ID / SESSION_LOG_FILENAME
    expected = hashlib.sha256(RAW_VALID).hexdigest()
    assert log_sha == expected, f"{log_sha} != {expected}"
    binding = store.bind_lead_session(
        task_id="t-a", session_id=LEAD_ID, bound_by="lead", log_sha256=log_sha
    )
    assert binding.session_id == LEAD_ID and binding.log_sha256 == expected
    resolved = resolver.resolve("t-a", source="lead")
    assert resolved.session_id == LEAD_ID and resolved.source == "lead"
    assert resolved.worker_id is None
    assert str(resolved.path) == str(path)
    # Task B cannot use Task A's bound session through any source selector.
    expect_error(
        lambda: resolver.resolve("t-b", source="lead"),
        SessionLogError,
        REASON_NO_BINDING,
    )
    return "validate returns raw-bytes sha256; one-time binding; only its Task can resolve it"


check("C04 valid binding + sha256 of verified raw bytes", c04)


def c05() -> str:
    # Same Task twice: hard error, no silent replacement.
    expect_error(
        lambda: store.bind_lead_session(task_id="t-a", session_id=OTHER_ID),
        StateError,
    )
    # Same session on another Task: hard error.
    expect_error(
        lambda: store.bind_lead_session(task_id="t-b", session_id=LEAD_ID),
        StateError,
    )
    # Unknown Task: registry error before any insert.
    expect_error(
        lambda: store.bind_lead_session(task_id="t-nope", session_id=OTHER_ID),
        NotFoundError,
    )
    # DB-level uniqueness is the durable guard (direct SQL, bypassing the store).
    conn = store.conn
    for sql, params, label in (
        (
            "INSERT INTO session_bindings(session_id, task_id, bound_at, bound_by)"
            " VALUES(?,?,?,?)",
            (LEAD_ID, "t-b", 1, "lead"),
            "duplicate session_id",
        ),
        (
            "INSERT INTO session_bindings(session_id, task_id, bound_at, bound_by)"
            " VALUES(?,?,?,?)",
            (OTHER_ID, "t-a", 1, "lead"),
            "duplicate task_id",
        ),
        (
            "INSERT INTO session_bindings(session_id, task_id, bound_at, bound_by)"
            " VALUES(?,?,?,?)",
            (OTHER_ID, "t-missing", 1, "lead"),
            "unknown task FK",
        ),
    ):
        try:
            conn.execute(sql, params)
            conn.execute("ROLLBACK")
            raise AssertionError(f"{label}: INSERT unexpectedly succeeded")
        except sqlite3.IntegrityError:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.OperationalError:
                pass
    sql = conn.execute(
        "SELECT sql FROM sqlite_master WHERE name='session_bindings'"
    ).fetchone()["sql"]
    assert "UNIQUE" in sql and "PRIMARY KEY" in sql and "REFERENCES" in sql
    rows = conn.execute("SELECT COUNT(*) AS n FROM session_bindings").fetchone()["n"]
    assert rows == 1, rows
    return "both uniqueness directions + FK enforced by SQLite; exactly 1 binding row"


check("C05 duplicate/foreign binding rejected (store + DB level)", c05)


def c06() -> str:
    bad_id = "feedface-0000-4000-8000-000000000001"
    write_lead_log(LEAD_ROOT, bad_id, cwd=str(WORKSPACE), header_id=OTHER_ID, slug="lead-badid")
    err = expect_error(
        lambda: resolver.validate_lead_candidate(bad_id),
        SessionLogError,
        REASON_HEADER_MISMATCH,
    )
    assert "header id does not match" in str(err)
    return "header id != registered id -> header_mismatch"


check("C06 header id mismatch rejected", c06)


def c07() -> str:
    bad_cwd_id = "feedface-0000-4000-8000-000000000002"
    write_lead_log(
        LEAD_ROOT, bad_cwd_id, cwd=str(ROOT / "some-other-project"), slug="lead-badcwd"
    )
    err = expect_error(
        lambda: resolver.validate_lead_candidate(bad_cwd_id),
        SessionLogError,
        REASON_LEAD_CWD_MISMATCH,
    )
    assert "cwd does not match" in str(err)
    # Contract: without a configured workspace_root the cwd check is skipped (tests only).
    loose = SessionLogResolver(
        ROOT / ".ctf-solver-data" / "dsh-home" / "sessions",
        store,
        lead_sessions_root=LEAD_ROOT,
        workspace_root=None,
        clock=clock,
    )
    loose.validate_lead_candidate(bad_cwd_id)
    return "cwd mismatch -> lead_cwd_mismatch; no workspace_root skips check (test-only)"


check("C07 header cwd mismatch rejected", c07)


def c08() -> str:
    none_root = SessionLogResolver(
        ROOT / ".ctf-solver-data" / "dsh-home" / "sessions",
        store,
        lead_sessions_root=None,
        workspace_root=WORKSPACE,
        clock=clock,
    )
    expect_error(
        lambda: none_root.resolve("t-a", source="lead"),
        SessionLogError,
        REASON_LEAD_ROOT_MISSING,
    )
    expect_error(
        lambda: none_root.validate_lead_candidate(LEAD_ID),
        SessionLogError,
        REASON_LEAD_ROOT_MISSING,
    )
    missing_root = SessionLogResolver(
        ROOT / ".ctf-solver-data" / "dsh-home" / "sessions",
        store,
        lead_sessions_root=ROOT / "does-not-exist",
        workspace_root=WORKSPACE,
        clock=clock,
    )
    expect_error(
        lambda: missing_root.resolve("t-a", source="lead"),
        SessionLogError,
        REASON_LEAD_ROOT_MISSING,
    )
    return "None/missing lead root -> lead_sessions_root_missing"


check("C08 missing lead sessions root rejected", c08)


def c09() -> str:
    ambiguous_id = "feedface-0000-4000-8000-000000000003"
    write_lead_log(LEAD_ROOT, ambiguous_id, cwd=str(WORKSPACE), slug="lead-slug-1")
    write_lead_log(LEAD_ROOT, ambiguous_id, cwd=str(WORKSPACE), slug="lead-slug-2")
    expect_error(
        lambda: resolver.validate_lead_candidate(ambiguous_id),
        SessionLogError,
        REASON_AMBIGUOUS_SESSION_LOG,
    )
    expect_error(
        lambda: resolver.validate_lead_candidate("never-written"),
        SessionLogError,
        REASON_LOG_MISSING,
    )
    return "two on-disk logs -> ambiguous_session_log; none -> log_missing"


check("C09 ambiguous / missing log rejected", c09)


def c10() -> str:
    # Registry tampering: a binding row with an unsafe session id is rejected on read.
    tamper_id = "t-tamper"
    make_task(store, tamper_id, status=TaskStatus.RUNNING, acp_session_id="sess-tamper")
    with store._tx():  # verifier simulation of a tampered registry row
        store.conn.execute(
            "INSERT INTO session_bindings(session_id, task_id, bound_at, bound_by)"
            " VALUES(?,?,?,?)",
            ("..\\..\\evil", tamper_id, 1, "lead"),
        )
    expect_error(
        lambda: resolver.resolve(tamper_id, source="lead"),
        SessionLogError,
        REASON_UNKNOWN_SESSION,
    )
    return "tampered binding id -> unknown_session (registry row is not trusted)"


check("C10 tampered registry binding rejected at resolution", c10)


def c11() -> str:
    # Positive control: the real multi-frame fixture resolves for worker source, and
    # auto is unchanged for a task without a binding.
    worker_root = ROOT / ".ctf-solver-data" / "dsh-home" / "sessions"
    for worker_session in ("sess-worker-a", "sess-worker-b"):
        raw = write_session_log(
            worker_root / "worker-slug" / worker_session / SESSION_LOG_FILENAME,
            standard_session(session_id=worker_session),
            frames=5,
        )
        assert raw
    resolved_worker = resolver.resolve("t-b", source="worker")
    assert resolved_worker.source == "worker"
    assert resolved_worker.worker_id == "w-b"
    assert resolved_worker.session_id == "sess-worker-b"
    auto_unbound = resolver.resolve("t-b")
    assert auto_unbound.source == "worker"
    # Task A has a Lead binding: auto must choose the Lead session (clarified rule).
    auto_bound = resolver.resolve("t-a")
    assert auto_bound.source == "lead", auto_bound.source
    # source=worker still selects the registered Worker even when a binding exists.
    worker_for_a = resolver.resolve("t-a", source="worker")
    assert worker_for_a.source == "worker" and worker_for_a.worker_id == "w-a"
    return "worker path unchanged; auto=lead when bound, worker otherwise"


check("C11 worker path unchanged + auto precedence", c11)


def c12() -> str:
    # source="auto" with an explicit worker_id keeps the caller's worker selection
    # (documented in the resolver) — record the exact observed semantics.
    resolved = resolver.resolve("t-a", worker_id="w-a")
    assert resolved.source == "worker"
    return "auto + explicit worker_id -> worker (explicit selection wins)"


check("C12 auto with explicit worker_id semantics recorded", c12)


def c13() -> str:
    # The binding is one-time: after a Task is bound, a second create is rejected by
    # the service before persistence (service-level check D3), and the store refuses.
    expect_error(
        lambda: store.bind_lead_session(task_id="t-a", session_id="session-new"),
        StateError,
    )
    assert store.get_lead_binding("t-a") is not None
    assert store.get_task_for_lead_session(LEAD_ID) == "t-a"
    assert store.get_lead_binding("t-b") is None
    return "one-time binding verified through both reverse-map directions"


check("C13 binding reverse-map + one-time invariant", c13)


def c14() -> str:
    # Symlink/junction components must be rejected when the host can create one.
    target = ROOT / "outside-target"
    target.mkdir()
    outside_log = target / "session.v4.jsonl.zstd"
    outside_log.write_bytes(RAW_VALID)
    link_id = "feedface-0000-4000-8000-000000000004"
    slug_link = LEAD_ROOT / "lead-junction-slug"
    created = None
    try:
        os.symlink(target, slug_link, target_is_directory=True)
        created = "symlink"
    except OSError:
        result = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(slug_link), str(target)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        if result.returncode == 0 and slug_link.exists():
            created = "junction"
    if created is None:
        skip("C14 link/junction escape rejected", "host cannot create symlink or junction")
        return ""
    try:
        (slug_link / link_id).mkdir(exist_ok=False)
        shutil.copy2(outside_log, slug_link / link_id / SESSION_LOG_FILENAME)
        expect_error(
            lambda: resolver.validate_lead_candidate(link_id),
            SessionLogError,
            REASON_SYMLINK_REJECTED,
        )
        return f"{created} component -> symlink_rejected"
    finally:
        try:
            shutil.rmtree(slug_link, ignore_errors=True)
        except OSError:
            pass


check("C14 link/junction escape rejected", c14)

# ===========================================================================
print()
print("=" * 78)
print("SECTION D — SERVICE-LEVEL FLOW (real EvidenceStore, deterministic fakes)")
print("=" * 78)


class MiniAcp:
    def __init__(self) -> None:
        self.alive = False
        self.sessions: list[dict[str, Any]] = []
        self.closed: list[str] = []

    def start(self) -> None:
        self.alive = True

    def stop(self, timeout_s: float = 10.0) -> None:
        self.alive = False

    def is_alive(self) -> bool:
        return self.alive

    def diagnostics(self) -> dict[str, Any]:
        return {"state": "ready", "is_alive": self.alive}

    def new_session(self, cwd: str, mcp_servers: list[dict[str, Any]] | None = None):
        sid = f"session-mini-{len(self.sessions) + 1:03d}"
        self.sessions.append({"cwd": cwd, "session_id": sid})
        return {"sessionId": sid, "configOptions": []}

    def list_sessions(self, cwd: str | None = None):
        return {"sessions": []}

    def resume_session(self, session_id: str, cwd: str):
        return {"configOptions": []}

    def close_session(self, session_id: str) -> None:
        self.closed.append(session_id)

    def cancel_session(self, session_id: str) -> None:
        pass

    def prompt(self, session_id: str, content: list[dict[str, Any]]):
        raise AssertionError("Round 1 must never issue session/prompt")

    def set_session_update_handler(self, handler: Any) -> None:
        pass

    def set_permission_handler(self, handler: Any) -> None:
        pass


class MiniPipeline:
    def execute(self, request: Any, worker_token: str) -> Any:
        raise AssertionError("pipeline not used")


class MiniDeliverables:
    def __init__(self, root: Path) -> None:
        self.root = root

    def build_writeup(self, task: TaskRecord) -> Any:
        raise AssertionError("not used")

    def export_evidence_zip(self, task: TaskRecord) -> Any:
        raise AssertionError("not used")


class MiniCapturer:
    def capture(self, *, scope: str, workdir: str | None = None) -> Any:
        from ctf_solver.core.types import CaptureResult

        return CaptureResult(
            ok=True,
            png_bytes=b"\x89PNG\r\n\x1a\nservice-mini",
            width=80,
            height=60,
            blank=False,
            method="mini",
            captured_at=1,
        )


SERVICE_ROOT = fresh_dir("service")
SERVICE_LEAD_ROOT = SERVICE_ROOT / "live-lead-sessions"
SERVICE_LEAD_ROOT.mkdir()
svc_config = SolverConfig(root=SERVICE_ROOT, capture_mode="fake")
svc_paths = svc_config.ensure_layout()
svc_clock = SimpleClock()
svc_store = ManagerStore(str(svc_paths.db_path), svc_clock)
svc_evidence = EvidenceStore(str(svc_paths.db_path), str(svc_paths.cas_dir), clock=svc_clock)
mini_acp = MiniAcp()
service = ManagerService(
    config=svc_config,
    store=svc_store,
    acp_factory=lambda: mini_acp,
    evidence=svc_evidence,
    pipeline=MiniPipeline(),
    deliverables=MiniDeliverables(SERVICE_ROOT),
    capturer=MiniCapturer(),
    clock=svc_clock,
    lead_sessions_root=SERVICE_LEAD_ROOT,
    workspace_root=SERVICE_ROOT,
)
service.start()
RAW_SERVICE_LEAD = write_lead_log(
    SERVICE_LEAD_ROOT,
    LEAD_ID,
    cwd=str(SERVICE_ROOT),
    extra=[tool_call(900, 1_700_000_900_000, "call-900", "bash", {"command": "id"}, turn=3, step=2)],
)


def svc_events(event_type: str) -> list[dict]:
    return svc_evidence.list_events(task_id="", event_type=event_type) if False else [
        event
        for event in svc_evidence.list_events()
        if event.get("event_type") == event_type
    ]


def d01() -> str:
    task = service.create_task(
        title="Lead-driven synthetic challenge",
        category="web",
        conversation_id="conv-lead",
        notes="handoff: execute the Lead plan",
        lead_session_id=LEAD_ID,
    )
    assert task.status is TaskStatus.RUNNING, task.status
    assert task.worker_id and task.acp_session_id
    binding = svc_store.get_lead_binding(task.task_id)
    assert binding is not None and binding.session_id == LEAD_ID
    assert binding.bound_by == "lead"
    assert binding.log_sha256 == hashlib.sha256(RAW_SERVICE_LEAD).hexdigest()
    created = [
        event
        for event in svc_evidence.list_events()
        if event["event_type"] == "task_created" and event["task_id"] == task.task_id
    ]
    assert len(created) == 1, created
    payload = created[0]["payload"]
    assert payload["lead_session_id"] == LEAD_ID, payload
    assert payload["notes"] == "handoff: execute the Lead plan", payload
    bound = [
        event
        for event in svc_evidence.list_events()
        if event["event_type"] == "lead_session_bound" and event["task_id"] == task.task_id
    ]
    assert len(bound) == 1
    assert bound[0]["payload"]["session_id"] == LEAD_ID
    seq_created = created[0]["seq"]
    seq_bound = bound[0]["seq"]
    assert seq_bound > seq_created, (seq_created, seq_bound)
    D01_STATE["task_id"] = task.task_id
    return "binding + task_created(lead_session_id, notes) + lead_session_bound after it"


D01_STATE: dict[str, str] = {}
check("D01 create_task binds verified Lead session", d01)


def d02() -> str:
    before = len(svc_store.list_tasks())
    for bad in ("", "   "):
        expect_error(
            lambda value=bad: service.create_task(
                title="bad", category="misc", conversation_id="c", lead_session_id=value
            ),
            ValidationError,
        )
    for bad in ("..\\escape", "C:\\Windows", "x" * 129):
        expect_error(
            lambda value=bad: service.create_task(
                title="bad", category="misc", conversation_id="c", lead_session_id=value
            ),
            SessionLogError,
        )
    after = len(svc_store.list_tasks())
    assert after == before, f"{before} -> {after} tasks persisted on failed validation"
    return f"invalid candidates rejected before persistence ({before} tasks unchanged)"


check("D02 invalid lead_session_id fails closed before persistence", d02)


def d03() -> str:
    before = len(svc_store.list_tasks())
    err = expect_error(
        lambda: service.create_task(
            title="duplicate", category="misc", conversation_id="c", lead_session_id=LEAD_ID
        ),
        StateError,
    )
    assert "already bound" in str(err), str(err)
    assert len(svc_store.list_tasks()) == before
    return "duplicate session on a second Task -> StateError, no Task persisted"


check("D03 duplicate Lead session rejected at create", d03)


def d04() -> str:
    bad_cwd_id = "feedface-0000-4000-8000-000000000010"
    write_lead_log(
        SERVICE_LEAD_ROOT, bad_cwd_id, cwd=str(SERVICE_ROOT / "other-project"), slug="cwd-slug"
    )
    before = len(svc_store.list_tasks())
    err = expect_error(
        lambda: service.create_task(
            title="badcwd", category="misc", conversation_id="c", lead_session_id=bad_cwd_id
        ),
        SessionLogError,
    )
    assert getattr(err, "reason_code", None) == REASON_LEAD_CWD_MISMATCH
    assert len(svc_store.list_tasks()) == before
    return "header cwd mismatch -> lead_cwd_mismatch, no Task persisted"


check("D04 create_task rejects cwd mismatch", d04)


def d05() -> str:
    task_id = D01_STATE["task_id"]
    report = service.ingest_session_log(task_id, source="lead")
    assert "path" not in report and "raw_path" not in report, sorted(report)
    ingested = [
        event
        for event in svc_evidence.list_events()
        if event["event_type"] == "evidence_ingested" and event["task_id"] == task_id
    ]
    assert ingested, "no evidence_ingested event"
    payload = ingested[-1]["payload"]
    assert payload["source"] == "lead", payload
    assert payload["session_id"] == LEAD_ID
    D05_STATE["after_first"] = len(svc_evidence.list_events())
    D05_STATE["tool_calls"] = len(
        [e for e in svc_evidence.list_events() if e["event_type"] == "tool_call"]
    )
    return f"source=lead, path redacted, appended={report.get('appended')}"


D05_STATE: dict[str, int] = {}
check("D05 ingest source=lead works and redacts path", d05)


def d06() -> str:
    task_id = D01_STATE["task_id"]
    second = service.ingest_session_log(task_id, source="lead")
    assert int(second.get("appended") or 0) == 0, second
    assert int(second.get("skipped_duplicates") or 0) >= 1, second
    tool_calls_after = len(
        [e for e in svc_evidence.list_events() if e["event_type"] == "tool_call"]
    )
    assert tool_calls_after == D05_STATE["tool_calls"], (
        D05_STATE["tool_calls"],
        tool_calls_after,
    )
    chain = svc_evidence.chain_status()
    assert chain.ok, chain
    return (
        "re-ingest appended=0, skipped_duplicates>0, no duplicated evidence records,"
        " chain ok"
    )


check("D06 ingest idempotency at evidence-chain level", d06)


def d07() -> str:
    working_id = "11111111-2222-4333-8444-000000000020"
    write_lead_log(SERVICE_LEAD_ROOT, working_id, cwd=str(SERVICE_ROOT), slug="auto-slug")
    task = service.create_task(
        title="auto-order", category="misc", conversation_id="c", lead_session_id=working_id
    )
    worker_raw = write_session_log(
        svc_config.session_log_root
        / "worker-slug"
        / str(task.acp_session_id)
        / SESSION_LOG_FILENAME,
        standard_session(session_id=str(task.acp_session_id)),
        frames=3,
    )
    assert worker_raw
    report = service.ingest_session_log(task.task_id)  # auto
    ingested = [
        event
        for event in svc_evidence.list_events()
        if event["event_type"] == "evidence_ingested" and event["task_id"] == task.task_id
    ]
    assert ingested[-1]["payload"]["source"] == "lead", ingested[-1]["payload"]
    report_worker = service.ingest_session_log(task.task_id, source="worker")
    ingested = [
        event
        for event in svc_evidence.list_events()
        if event["event_type"] == "evidence_ingested" and event["task_id"] == task.task_id
    ]
    assert ingested[-1]["payload"]["source"] == "worker", ingested[-1]["payload"]
    expect_error(
        lambda: service.ingest_session_log(task.task_id, source="bogus"),
        ValidationError,
    )
    D07_STATE["worker_task_id"] = task.task_id
    return "auto -> lead when bound; worker -> worker; bogus -> ValidationError"


D07_STATE: dict[str, str] = {}
check("D07 ingest source selection auto/worker/lead", d07)


def free_slots(keep: set[str] | None = None) -> None:
    """Cancel active Tasks so the two-slot contract cannot queue the next one."""
    keep = keep or set()
    for active in svc_store.list_active_tasks():
        if active.task_id in keep:
            continue
        try:
            service.cancel_task(active.task_id, reason="verifier slot cleanup")
        except Exception:  # noqa: BLE001 - best effort cleanup between checks
            pass


def d08() -> str:
    # Keep D07's Task running: the completion checks below still need it.
    free_slots(keep={D07_STATE.get("worker_task_id", "")})
    task = service.create_task(
        title="worker-only", category="misc", conversation_id="c"
    )
    assert svc_store.get_lead_binding(task.task_id) is None
    assert task.status is TaskStatus.RUNNING, task.status
    worker_log = write_session_log(
        svc_config.session_log_root
        / "worker-only-slug"
        / str(task.acp_session_id)
        / SESSION_LOG_FILENAME,
        standard_session(session_id=str(task.acp_session_id)),
        frames=3,
    )
    assert worker_log
    service.ingest_session_log(task.task_id)  # auto, no binding
    ingested = [
        event
        for event in svc_evidence.list_events()
        if event["event_type"] == "evidence_ingested" and event["task_id"] == task.task_id
    ]
    assert ingested[-1]["payload"]["source"] == "worker", ingested[-1]["payload"]
    created = [
        event
        for event in svc_evidence.list_events()
        if event["event_type"] == "task_created" and event["task_id"] == task.task_id
    ]
    assert created[0]["payload"]["lead_session_id"] is None
    return "worker-only Task: no binding, auto resolves worker, task_created lead_session_id=None"


check("D08 worker-only behaviour unchanged", d08)


def d09() -> str:
    task_id = D07_STATE["worker_task_id"]
    # Lead log is already ingested twice for this Task; completion must not double-ingest.
    before = len(
        [e for e in svc_evidence.list_events() if e["event_type"] == "evidence_ingested"]
    )
    result = service.complete_task(task_id, result_state="no_flag", note="completed via Lead evidence")
    assert result["status"] == TaskStatus.COMPLETED.value, result
    after = len(
        [e for e in svc_evidence.list_events() if e["event_type"] == "evidence_ingested"]
    )
    assert after == before, (before, after)
    completed = svc_store.require_task(task_id)
    assert completed.completion_note == "completed via Lead evidence", completed.completion_note
    assert completed.notes == "", "completion note must not overwrite intake notes"
    again = service.complete_task(task_id, result_state="no_flag")
    assert again.get("already_completed") is True
    return "completion persisted completion_note, no double-ingest, idempotent re-complete"


check("D09 completion_note persisted; no double ingest", d09)


def d10() -> str:
    # (a) Completion must not double-ingest a bound Lead log that is already in.
    pre_id = "abcdef00-1111-4222-8333-cccccccccccc"
    write_lead_log(SERVICE_LEAD_ROOT, pre_id, cwd=str(SERVICE_ROOT), slug="pre-ingest-slug")
    task_a = service.create_task(
        title="pre-ingested", category="misc", conversation_id="c", lead_session_id=pre_id
    )
    service.ingest_session_log(task_a.task_id, source="lead")
    before_a = len(
        [
            event
            for event in svc_evidence.list_events()
            if event["event_type"] == "evidence_ingested"
            and event["task_id"] == task_a.task_id
        ]
    )
    assert before_a == 1, before_a
    result_a = service.complete_task(task_a.task_id, result_state="solved_flag_candidate", note="outcome")
    assert result_a["status"] == TaskStatus.COMPLETED.value
    after_a = len(
        [
            event
            for event in svc_evidence.list_events()
            if event["event_type"] == "evidence_ingested"
            and event["task_id"] == task_a.task_id
        ]
    )
    assert after_a == before_a, (before_a, after_a)

    # (b) A bound Lead log never ingested before must be auto-ingested exactly once.
    new_id = "abcdef00-1111-4222-8333-999999999999"
    write_lead_log(SERVICE_LEAD_ROOT, new_id, cwd=str(SERVICE_ROOT), slug="autoingest-slug")
    task_b = service.create_task(
        title="auto-ingest", category="misc", conversation_id="c", lead_session_id=new_id
    )
    before_total = len(
        [event for event in svc_evidence.list_events() if event["event_type"] == "evidence_ingested"]
    )
    result_b = service.complete_task(task_b.task_id, result_state="no_flag")
    assert result_b["status"] == TaskStatus.COMPLETED.value
    ingested_b = [
        event
        for event in svc_evidence.list_events()
        if event["event_type"] == "evidence_ingested" and event["task_id"] == task_b.task_id
    ]
    assert len(ingested_b) == 1, len(ingested_b)
    assert ingested_b[0]["payload"]["source"] == "lead"
    after_total = len(
        [event for event in svc_evidence.list_events() if event["event_type"] == "evidence_ingested"]
    )
    assert after_total == before_total + 1, (before_total, after_total)
    return (
        "no double-ingest when already ingested; exactly one auto-ingest for a"
        " never-ingested bound Lead session"
    )


check("D10 completion auto-ingests bound Lead log exactly once", d10)


def d11() -> str:
    # Screenshot step derivation from the newest ingested tool_call (turn 3, step 2).
    new_id = "abcdef00-1111-4222-8333-aaaaaaaaaaaa"
    write_lead_log(
        SERVICE_LEAD_ROOT,
        new_id,
        cwd=str(SERVICE_ROOT),
        slug="shot-slug",
        extra=[
            tool_call(950, 1_700_000_950_000, "call-950", "bash", {"command": "ls"}, turn=4, step=1),
            tool_call(951, 1_700_000_951_000, "call-951", "bash", {"command": "id"}, turn=5, step=3),
        ],
    )
    task = service.create_task(
        title="screenshots", category="misc", conversation_id="c", lead_session_id=new_id
    )
    service.ingest_session_log(task.task_id, source="lead")
    shot = service.take_screenshot(task.task_id)
    assert shot.step_id == "turn5-step3", shot.step_id
    explicit = service.take_screenshot(task.task_id, step_id="turn9-step9")
    assert explicit.step_id == "turn9-step9"
    expect_error(
        lambda: service.take_screenshot(task.task_id, step_id="bad step!"),
        (ValidationError, ValueError),
    )
    # No tool-call evidence yet -> honestly unbound (None), never invented.
    bare = service.create_task(title="bare", category="misc", conversation_id="c")
    unbound = service.take_screenshot(bare.task_id)
    assert unbound.step_id is None, unbound.step_id
    return "default step_id=turn5-step3 from newest tool_call; explicit kept; bare -> None"


check("D11 screenshot default step_id derivation", d11)


def d12() -> str:
    # Worker-only completion keeps its previous requirement: explicit ingest needed.
    free_slots()
    task = service.create_task(
        title="worker-complete",
        category="misc",
        conversation_id="c",
        notes="worker intake record",
    )
    write_session_log(
        svc_config.session_log_root
        / "wc-slug"
        / str(task.acp_session_id)
        / SESSION_LOG_FILENAME,
        standard_session(session_id=str(task.acp_session_id)),
        frames=2,
    )
    service.ingest_session_log(task.task_id)
    result = service.complete_task(task.task_id, result_state="no_flag", note="worker done")
    assert result["status"] == TaskStatus.COMPLETED.value
    completed = svc_store.require_task(task.task_id)
    assert completed.completion_note == "worker done"
    assert completed.notes == "worker intake record", completed.notes
    return "worker-only completion unchanged; completion_note written, intake notes preserved"


check("D12 worker-only completion path unchanged", d12)


def d13() -> str:
    """Lead-reported live defect class: completion must not clobber intake notes."""
    free_slots()
    intake = "Intake record: preserve exactly this text — 中文 & symbols <>"
    new_id = "abcdef00-1111-4222-8333-bbbbbbbbbbbb"
    write_lead_log(SERVICE_LEAD_ROOT, new_id, cwd=str(SERVICE_ROOT), slug="notes-slug")
    task = service.create_task(
        title="notes-preservation",
        category="misc",
        conversation_id="c",
        notes=intake,
        lead_session_id=new_id,
    )
    assert task.notes == intake
    service.complete_task(task.task_id, result_state="no_flag", note="completion outcome note")
    completed = svc_store.require_task(task.task_id)
    assert completed.notes == intake, (completed.notes, intake)
    assert completed.completion_note == "completion outcome note", completed.completion_note
    raw_row = svc_store.conn.execute(
        "SELECT notes, completion_note FROM tasks WHERE task_id = ?", (task.task_id,)
    ).fetchone()
    assert raw_row["notes"] == intake and raw_row["completion_note"] == "completion outcome note"
    # Direct store check of the COMPLETION_PENDING transition itself.
    bare = service.create_task(
        title="pending-transition", category="misc", conversation_id="c", notes="intake B"
    )
    svc_store.set_task_status(
        bare.task_id,
        TaskStatus.COMPLETION_PENDING,
        result_state="pending_x",
        completion_note="pending lifecycle note",
    )
    after = svc_store.require_task(bare.task_id)
    assert after.notes == "intake B", after.notes
    assert after.completion_note == "pending lifecycle note", after.completion_note
    # Verifier-only cleanup of the deliberately pending Task (raw SQL on the
    # verifier's own copy; the product never does this).
    with svc_store._tx():
        svc_store.conn.execute(
            "UPDATE tasks SET status = ? WHERE task_id = ?",
            (TaskStatus.CANCELLED.value, bare.task_id),
        )
    return (
        "completion keeps tasks.notes byte-identical; completion_note holds the outcome;"
        " COMPLETION_PENDING transition writes completion_note only"
    )


check("D13 intake notes preserved by completion (live defect regression)", d13)


def d14() -> str:
    free_slots()
    intake = "pause/cancel intake record"
    task = service.create_task(
        title="pause-cancel", category="misc", conversation_id="c", notes=intake
    )
    paused = service.pause_task(task.task_id, reason="human asked")
    assert paused["status"] == TaskStatus.PAUSED.value, paused
    paused_task = svc_store.require_task(task.task_id)
    assert paused_task.notes == intake, paused_task.notes
    assert paused_task.completion_note == "pause: human asked", paused_task.completion_note
    cancelled = service.cancel_task(task.task_id, reason="human cancel")
    after = svc_store.require_task(task.task_id)
    assert after.status in {TaskStatus.CANCEL_REQUESTED, TaskStatus.CANCELLED}, after.status
    assert after.notes == intake, after.notes
    assert "cancel" in (after.completion_note or ""), after.completion_note
    return (
        f"pause writes completion_note='pause: human asked'; cancel -> {after.status.value};"
        " intake notes byte-identical"
    )


check("D14 pause/cancel do not mutate intake notes", d14)

# ===========================================================================
print()
print("=" * 78)
print("SECTION E — WORKER RESOLUTION PARITY vs BASE COMMIT 21908de")
print("=" * 78)

RUNNER = VERIFIER / "phase2_worker_scenarios.py"
RUNNER.write_text(
    r'''"""Worker-resolution parity scenarios (run under both trees)."""
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.getcwd())
from ctf_solver.core.types import Category, TaskRecord, TaskStatus, WorkerRecord, WorkerStatus
from ctf_solver.manager.session_logs import SessionLogResolver
from ctf_solver.manager.store import ManagerStore

try:
    import zstandard as _zstd
    def _compress(data):
        return _zstd.ZstdCompressor(level=3).compress(data)
except ImportError:
    from compression import zstd as _stdz
    def _compress(data):
        return (
            _stdz.ZstdCompressor().compress(data)
            if hasattr(_stdz, "ZstdCompressor")
            else _stdz.compress(data)
        )


def log_bytes(records):
    payload = b"".join(
        json.dumps(record, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n"
        for record in records
    )
    return _compress(payload)


def header(session_id, cwd):
    return {"type": "session", "seq": 0, "time": 1, "data": {"id": session_id, "cwd": cwd}}


def main() -> int:
    work = Path(sys.argv[1])
    if work.exists():
        import shutil
        shutil.rmtree(work)
    work.mkdir(parents=True)
    db = work / "db.sqlite"
    store = ManagerStore(str(db))
    tasks = work / "tasks"
    worker_root = work / "worker-sessions"

    def task(task_id, *, with_worker, session_id=None):
        record = TaskRecord(
            task_id=task_id,
            conversation_id="c",
            title="t",
            category=Category.MISC,
            workspace_path=str(tasks / task_id / "work"),
            status=TaskStatus.RUNNING,
            acp_session_id=session_id,
        )
        store.create_task(record)
        if with_worker and session_id:
            store.create_worker(
                WorkerRecord(
                    worker_id="w-" + task_id,
                    task_id=task_id,
                    acp_session_id=session_id,
                    workspace_path=str(tasks / task_id / "work"),
                    status=WorkerStatus.RUNNING,
                    worker_token="tok-" + task_id,
                )
            )

    task("t-noworker", with_worker=False)
    task("t-missing", with_worker=True, session_id="sess-missing")
    task("t-mismatch", with_worker=True, session_id="sess-mismatch")
    task("t-ok", with_worker=True, session_id="sess-ok")

    (worker_root / "slug" / "sess-mismatch").mkdir(parents=True)
    (worker_root / "slug" / "sess-mismatch" / "session.v4.jsonl.zstd").write_bytes(
        log_bytes([header("other-session", str(work))])
    )
    (worker_root / "slug" / "sess-ok").mkdir(parents=True)
    (worker_root / "slug" / "sess-ok" / "session.v4.jsonl.zstd").write_bytes(
        log_bytes([header("sess-ok", str(work))])
    )

    outcomes = {}

    def capture(name, resolver, task_id):
        try:
            resolved = resolver.resolve(task_id)
            outcomes[name] = {
                "ok": True,
                "source": getattr(resolved, "source", None),
                "filename": resolved.path.name,
                "worker_id": resolved.worker_id,
            }
        except Exception as exc:  # noqa: BLE001
            outcomes[name] = {
                "ok": False,
                "reason_code": getattr(exc, "reason_code", type(exc).__name__),
                "message": str(exc),
            }

    good_resolver = SessionLogResolver(worker_root, store)
    capture("unknown_task", good_resolver, "t-unknown")
    capture("no_worker", good_resolver, "t-noworker")
    capture("log_missing", good_resolver, "t-missing")
    capture("header_mismatch", good_resolver, "t-mismatch")
    capture("valid", good_resolver, "t-ok")
    missing_root = SessionLogResolver(work / "no-such-root", store)
    capture("root_missing", missing_root, "t-ok")
    print(json.dumps(outcomes, indent=2, sort_keys=True))
    store.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
''',
    encoding="utf-8",
)


def run_scenarios(tree: Path, work: Path) -> dict:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(tree)
    result = subprocess.run(
        [sys.executable, str(RUNNER), str(work)],
        cwd=str(tree),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


BASE_OUT = run_scenarios(BASE, WORK / "worker-parity-base")
FROZEN_OUT = run_scenarios(WORKTREE, WORK / "worker-parity-frozen")
(WORK / "worker-parity.json").write_text(
    json.dumps({"base": BASE_OUT, "frozen": FROZEN_OUT}, indent=2), encoding="utf-8"
)


def e01() -> str:
    # The frozen interface adds ResolvedSessionLog.source (default "worker"); the
    # base commit has no such attribute. Normalise that single new field when
    # comparing worker-path outcomes.
    def normalise(outcomes: dict) -> dict:
        normalised = {}
        for key, value in outcomes.items():
            item = dict(value)
            if item.get("ok") and item.get("source") is None:
                item["source"] = "worker"
            normalised[key] = item
        return normalised

    base_norm = normalise(BASE_OUT)
    frozen = normalise(FROZEN_OUT)
    base_versions = {row["reason_code"] for row in base_norm.values() if not row["ok"]}
    frozen_versions = {row["reason_code"] for row in frozen.values() if not row["ok"]}
    assert base_versions == frozen_versions, (base_versions, frozen_versions)
    return f"reason codes identical: {sorted(base_versions)}"


check("E01 worker-path reason codes identical to base", e01)


def e02() -> str:
    def normalise(outcomes: dict) -> dict:
        normalised = {}
        for key, value in outcomes.items():
            item = dict(value)
            if item.get("ok") and item.get("source") is None:
                item["source"] = "worker"
            normalised[key] = item
        return normalised

    base_norm = normalise(BASE_OUT)
    frozen = normalise(FROZEN_OUT)
    differences = {
        key: (base_norm.get(key), frozen.get(key))
        for key in base_norm
        if base_norm.get(key) != frozen.get(key)
    }
    assert not differences, f"worker resolution differs from base: {differences}"
    assert frozen["valid"]["ok"] is True
    assert frozen["valid"]["worker_id"] == "w-t-ok"
    return (
        f"{len(base_norm)} scenarios identical (ok + reason_code + message + worker_id);"
        " only the new default source='worker' field differs"
    )

# ===========================================================================
print()
print("=" * 78)
summary = {
    "total": len(RESULTS),
    "pass": sum(1 for item in RESULTS if item["status"] == "PASS"),
    "fail": sum(1 for item in RESULTS if item["status"] == "FAIL"),
    "skip": sum(1 for item in RESULTS if item["status"] == "SKIP"),
    "results": RESULTS,
}
print(json.dumps({k: summary[k] for k in ("total", "pass", "fail", "skip")}))
for item in RESULTS:
    if item["status"] != "PASS":
        print(f"  {item['status']}: {item['check']} :: {item['detail']}")
(VERIFIER / "phase2_security.json").write_text(
    json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8"
)
print(f"results -> {VERIFIER / 'phase2_security.json'}")
try:
    service.shutdown()
finally:
    svc_evidence.close()
    svc_store.close()
sys.exit(1 if summary["fail"] else 0)
