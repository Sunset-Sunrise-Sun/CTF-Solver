"""Tests for :mod:`ctf_solver.manager.session_logs` (Round 2 section 3.1).

The resolver is a security boundary: the Manager must ingest only the log that
its own registry selected, from the audited Harness layout
``<sessions_root>/<cwd-slug>/<sessionId>/session.v4.jsonl.zstd``. The API has no
path parameter at all, so the negative tests below focus on registry tampering,
filesystem ambiguity/link escapes and content-identity forgery.

Synthetic fixtures only: multi-frame zstd logs are built with
``tests.support.zstd_fixtures`` and session event shapes with
``tests.support.session_events``. No Harness process or model call is used.

Windows note: ``os.symlink`` may require Developer Mode/elevation. Link-based
tests first try a real symlink, then an NTFS junction (which is also a reparse
point the resolver must reject), and only then skip with the documented reason.
"""

from __future__ import annotations

import inspect
import os
import subprocess
from pathlib import Path

import pytest

from ctf_solver.core.types import Category, TaskRecord, WorkerRecord, WorkerStatus
from ctf_solver.manager.session_logs import (
    REASON_AMBIGUOUS_SESSION_LOG,
    REASON_HEADER_MISMATCH,
    REASON_LOG_MISSING,
    REASON_NO_WORKER,
    REASON_PATH_ESCAPE,
    REASON_SESSIONS_ROOT_MISSING,
    REASON_SYMLINK_REJECTED,
    REASON_UNKNOWN_SESSION,
    REASON_UNKNOWN_TASK,
    SESSION_LOG_FILENAME,
    ResolvedSessionLog,
    SessionLogError,
    SessionLogResolver,
)
from ctf_solver.manager.store import ManagerStore
from tests.support.session_events import standard_session, turn_start
from tests.support.zstd_fixtures import (
    build_log_from_chunks,
    corrupt_frame,
    jsonl_bytes,
    truncate_last_frame,
    write_session_log,
)

SESSION_A = "11111111-1111-4111-8111-111111111111"
SESSION_B = "22222222-2222-4222-8222-222222222222"
SLUG_A = "D--CTF-SOLVER-tasks-task-a-work"
SLUG_B = "D--CTF-SOLVER-tasks-task-b-work"

LINK_SKIP_REASON = (
    "Windows symlink/junction creation unavailable in this environment "
    "(not elevated and/or Developer Mode off); link-escape case not exercised"
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _create_task(store: ManagerStore, task_id: str, *, session_id: str | None = None) -> TaskRecord:
    task = TaskRecord(
        task_id=task_id,
        conversation_id="conv-synthetic",
        title=f"synthetic {task_id}",
        category=Category.MISC,
        workspace_path=str(Path("synthetic") / "tasks" / task_id / "work"),
        acp_session_id=session_id,
    )
    return store.create_task(task)


def _register_worker(
    store: ManagerStore,
    task_id: str,
    *,
    worker_id: str,
    session_id: str,
    update_task: bool = True,
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
    if update_task:
        store.update_task_fields(
            task_id, worker_id=worker_id, acp_session_id=session_id
        )
    return worker


def _seed(
    store: ManagerStore,
    task_id: str,
    *,
    worker_id: str | None = None,
    session_id: str | None = None,
) -> None:
    _create_task(store, task_id)
    if worker_id is not None:
        _register_worker(
            store,
            task_id,
            worker_id=worker_id,
            session_id=session_id if session_id is not None else "",
        )


def _write_log(
    sessions_root: Path,
    slug: str,
    session_id: str,
    *,
    records: list[dict] | None = None,
    filename: str = SESSION_LOG_FILENAME,
) -> Path:
    path = sessions_root / slug / session_id / filename
    path.parent.mkdir(parents=True, exist_ok=True)
    write_session_log(path, records or standard_session(session_id=session_id), frames=6)
    return path


def _create_link(target: Path, link: Path, *, directory: bool) -> str:
    """Create a symlink (preferred) or Windows junction; return kind or ""."""

    try:
        os.symlink(target, link, target_is_directory=directory)
        return "symlink"
    except (OSError, NotImplementedError):
        pass
    if os.name != "nt" or not directory:
        return ""
    try:
        completed = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(link), str(target)],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError):  # pragma: no cover - defensive
        return ""
    is_junction = getattr(os.path, "isjunction", lambda _p: False)
    if completed.returncode == 0 and link.exists() and is_junction(link):
        return "junction"
    return ""


def _expect(error_type, reason_code: str):
    """Context manager asserting a SessionLogError with a stable reason code."""

    class _Checker:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            assert exc_type is error_type, f"expected {error_type.__name__}, got {exc_type}"
            assert exc.reason_code == reason_code, (
                f"expected reason_code {reason_code!r}, got {exc.reason_code!r}: {exc}"
            )
            # Stable machine-readable shape for MCP/IPC callers.
            payload = exc.to_dict()
            assert payload["reason_code"] == reason_code
            assert payload["error"] == "SessionLogError"
            return True

    return _Checker()


@pytest.fixture
def sandbox(tmp_path: Path):
    store = ManagerStore(str(tmp_path / "manager.sqlite"))
    root = tmp_path / "dsh-home" / "sessions"
    root.mkdir(parents=True, exist_ok=True)
    try:
        yield {
            "tmp": tmp_path,
            "store": store,
            "root": root,
            "resolver": SessionLogResolver(root, store),
        }
    finally:
        store.close()


# ---------------------------------------------------------------------------
# Valid resolution
# ---------------------------------------------------------------------------


def test_valid_resolution_returns_registered_log(sandbox) -> None:
    _seed(sandbox["store"], "task-a", worker_id="w-a", session_id=SESSION_A)
    path = _write_log(sandbox["root"], SLUG_A, SESSION_A)

    resolved = sandbox["resolver"].resolve("task-a")

    assert isinstance(resolved, ResolvedSessionLog)
    assert resolved.task_id == "task-a"
    assert resolved.worker_id == "w-a"
    assert resolved.session_id == SESSION_A
    assert resolved.path == path
    assert resolved.path.is_file()
    assert resolved.to_dict() == {
        "task_id": "task-a",
        "worker_id": "w-a",
        "session_id": SESSION_A,
        "path": str(path),
    }


def test_resolution_with_matching_worker_id(sandbox) -> None:
    _seed(sandbox["store"], "task-a", worker_id="w-a", session_id=SESSION_A)
    _write_log(sandbox["root"], SLUG_A, SESSION_A)

    resolved = sandbox["resolver"].resolve("task-a", worker_id="w-a")
    assert resolved.session_id == SESSION_A


def test_resolver_accepts_injected_clock(sandbox) -> None:
    _seed(sandbox["store"], "task-a", worker_id="w-a", session_id=SESSION_A)
    _write_log(sandbox["root"], SLUG_A, SESSION_A)
    resolver = SessionLogResolver(sandbox["root"], sandbox["store"], clock=sandbox["store"].clock)
    assert resolver.resolve("task-a").session_id == SESSION_A


def test_header_line_split_across_zstd_frames_still_resolves(sandbox) -> None:
    _seed(sandbox["store"], "task-a", worker_id="w-a", session_id=SESSION_A)
    payload = jsonl_bytes(standard_session(session_id=SESSION_A))
    header_end = payload.index(b"\n")
    # Split the very first JSON line (the session header) across three frames.
    split_one = max(1, header_end // 3)
    split_two = max(split_one + 1, (2 * header_end) // 3)
    chunks = [payload[:split_one], payload[split_one:split_two], payload[split_two:]]
    path = sandbox["root"] / SLUG_A / SESSION_A / SESSION_LOG_FILENAME
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(build_log_from_chunks(chunks))

    resolved = sandbox["resolver"].resolve("task-a")
    assert resolved.path == path


def test_extra_files_in_session_dir_are_ignored(sandbox) -> None:
    _seed(sandbox["store"], "task-a", worker_id="w-a", session_id=SESSION_A)
    path = _write_log(sandbox["root"], SLUG_A, SESSION_A)
    (path.parent / "notes.txt").write_text("synthetic unrelated file", encoding="utf-8")

    assert sandbox["resolver"].resolve("task-a").path == path


# ---------------------------------------------------------------------------
# Registry failures (no caller path exists)
# ---------------------------------------------------------------------------


def test_unknown_task(sandbox) -> None:
    with _expect(SessionLogError, REASON_UNKNOWN_TASK):
        sandbox["resolver"].resolve("task-missing")
    with _expect(SessionLogError, REASON_UNKNOWN_TASK):
        sandbox["resolver"].resolve("")


def test_task_without_worker_mapping(sandbox) -> None:
    _create_task(sandbox["store"], "task-a")
    with _expect(SessionLogError, REASON_NO_WORKER):
        sandbox["resolver"].resolve("task-a")


def test_wrong_worker_id_rejected(sandbox) -> None:
    _seed(sandbox["store"], "task-a", worker_id="w-a", session_id=SESSION_A)
    _write_log(sandbox["root"], SLUG_A, SESSION_A)
    with _expect(SessionLogError, REASON_NO_WORKER):
        sandbox["resolver"].resolve("task-a", worker_id="w-other")


def test_another_tasks_worker_cannot_read_this_log(sandbox) -> None:
    _seed(sandbox["store"], "task-a", worker_id="w-a", session_id=SESSION_A)
    _seed(sandbox["store"], "task-b", worker_id="w-b", session_id=SESSION_B)
    _write_log(sandbox["root"], SLUG_A, SESSION_A)
    _write_log(sandbox["root"], SLUG_B, SESSION_B)

    with _expect(SessionLogError, REASON_NO_WORKER):
        sandbox["resolver"].resolve("task-a", worker_id="w-b")
    assert sandbox["resolver"].resolve("task-a").session_id == SESSION_A
    assert sandbox["resolver"].resolve("task-b").session_id == SESSION_B


def test_resolver_api_has_no_path_parameter(sandbox) -> None:
    parameters = inspect.signature(SessionLogResolver.resolve).parameters
    assert "path" not in parameters
    assert list(parameters) == ["self", "task_id", "worker_id"]

    _seed(sandbox["store"], "task-a", worker_id="w-a", session_id=SESSION_A)
    _write_log(sandbox["root"], SLUG_A, SESSION_A)
    with pytest.raises(TypeError):
        sandbox["resolver"].resolve("task-a", path=str(sandbox["root"]))  # type: ignore[call-arg]


def test_worker_without_session_id(sandbox) -> None:
    _seed(sandbox["store"], "task-a", worker_id="w-a", session_id=None)
    with _expect(SessionLogError, REASON_UNKNOWN_SESSION):
        sandbox["resolver"].resolve("task-a")


def test_task_worker_registry_session_disagreement(sandbox) -> None:
    _seed(sandbox["store"], "task-a", worker_id="w-a", session_id=SESSION_A)
    sandbox["store"].update_task_fields("task-a", acp_session_id=SESSION_B)
    with _expect(SessionLogError, REASON_UNKNOWN_SESSION):
        sandbox["resolver"].resolve("task-a")


@pytest.mark.parametrize(
    "session_id",
    [
        "../../outside-session",
        "..\\..\\outside-session",
        "C:\\Windows\\System32\\config",
        "/etc/passwd",
        "slug/session",
        "slug\\session",
        ".",
        "..",
        " ",
        "session\x00id",
        "\x1fcontrol",
    ],
)
def test_unsafe_registered_session_id_cannot_address_system_paths(sandbox, session_id: str) -> None:
    _seed(sandbox["store"], "task-a", worker_id="w-a", session_id=session_id)
    with _expect(SessionLogError, REASON_UNKNOWN_SESSION):
        sandbox["resolver"].resolve("task-a")


# ---------------------------------------------------------------------------
# Filesystem failures
# ---------------------------------------------------------------------------


def test_missing_sessions_root(sandbox) -> None:
    _seed(sandbox["store"], "task-a", worker_id="w-a", session_id=SESSION_A)
    resolver = SessionLogResolver(sandbox["tmp"] / "absent" / "sessions", sandbox["store"])
    with _expect(SessionLogError, REASON_SESSIONS_ROOT_MISSING):
        resolver.resolve("task-a")


def test_sessions_root_is_a_file(sandbox) -> None:
    _seed(sandbox["store"], "task-a", worker_id="w-a", session_id=SESSION_A)
    root_file = sandbox["tmp"] / "sessions-file"
    root_file.write_text("not a directory", encoding="utf-8")
    resolver = SessionLogResolver(root_file, sandbox["store"])
    with _expect(SessionLogError, REASON_SESSIONS_ROOT_MISSING):
        resolver.resolve("task-a")


def test_empty_sessions_root_argument_rejected(sandbox) -> None:
    with pytest.raises(Exception) as info:
        SessionLogResolver("", sandbox["store"])
    assert "sessions_root" in str(info.value)


def test_log_missing_when_root_is_empty(sandbox) -> None:
    _seed(sandbox["store"], "task-a", worker_id="w-a", session_id=SESSION_A)
    with _expect(SessionLogError, REASON_LOG_MISSING):
        sandbox["resolver"].resolve("task-a")


def test_log_missing_with_wrong_filename(sandbox) -> None:
    _seed(sandbox["store"], "task-a", worker_id="w-a", session_id=SESSION_A)
    _write_log(sandbox["root"], SLUG_A, SESSION_A, filename="session.v5.jsonl.zstd")
    with _expect(SessionLogError, REASON_LOG_MISSING):
        sandbox["resolver"].resolve("task-a")


def test_log_missing_when_session_dir_absent(sandbox) -> None:
    _seed(sandbox["store"], "task-a", worker_id="w-a", session_id=SESSION_A)
    (sandbox["root"] / SLUG_A).mkdir(parents=True)
    with _expect(SessionLogError, REASON_LOG_MISSING):
        sandbox["resolver"].resolve("task-a")


def test_ambiguous_duplicate_session_logs(sandbox) -> None:
    _seed(sandbox["store"], "task-a", worker_id="w-a", session_id=SESSION_A)
    first = _write_log(sandbox["root"], SLUG_A, SESSION_A)
    second = _write_log(sandbox["root"], SLUG_B, SESSION_A)

    with _expect(SessionLogError, REASON_AMBIGUOUS_SESSION_LOG):
        sandbox["resolver"].resolve("task-a")
    with pytest.raises(SessionLogError) as info:
        sandbox["resolver"].resolve("task-a")
    assert set(info.value.details["paths"]) == {str(first), str(second)}


# ---------------------------------------------------------------------------
# Content identity (first-frame session header must match)
# ---------------------------------------------------------------------------


def test_header_mismatch_rejected(sandbox) -> None:
    _seed(sandbox["store"], "task-a", worker_id="w-a", session_id=SESSION_A)
    _write_log(
        sandbox["root"],
        SLUG_A,
        SESSION_A,
        records=standard_session(session_id=SESSION_B),
    )
    with pytest.raises(SessionLogError) as info:
        sandbox["resolver"].resolve("task-a")
    assert info.value.reason_code == REASON_HEADER_MISMATCH
    assert info.value.details["registered_session_id"] == SESSION_A
    assert info.value.details["header_session_id"] == SESSION_B


def test_header_without_id_rejected(sandbox) -> None:
    _seed(sandbox["store"], "task-a", worker_id="w-a", session_id=SESSION_A)
    records = [
        {"type": "session", "seq": 0, "time": 1, "data": {"cwd": "synthetic"}},
        turn_start(1, 2),
    ]
    _write_log(sandbox["root"], SLUG_A, SESSION_A, records=records)
    with _expect(SessionLogError, REASON_HEADER_MISMATCH):
        sandbox["resolver"].resolve("task-a")


def test_first_record_not_session_header_rejected(sandbox) -> None:
    _seed(sandbox["store"], "task-a", worker_id="w-a", session_id=SESSION_A)
    records = [
        {"type": "turn/start", "seq": 0, "time": 1, "data": {"id": SESSION_A}},
    ]
    _write_log(sandbox["root"], SLUG_A, SESSION_A, records=records)
    with _expect(SessionLogError, REASON_HEADER_MISMATCH):
        sandbox["resolver"].resolve("task-a")


def test_non_zstd_log_rejected(sandbox) -> None:
    _seed(sandbox["store"], "task-a", worker_id="w-a", session_id=SESSION_A)
    path = sandbox["root"] / SLUG_A / SESSION_A / SESSION_LOG_FILENAME
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"not a session log at all")
    with _expect(SessionLogError, REASON_HEADER_MISMATCH):
        sandbox["resolver"].resolve("task-a")


def test_empty_log_rejected(sandbox) -> None:
    _seed(sandbox["store"], "task-a", worker_id="w-a", session_id=SESSION_A)
    path = sandbox["root"] / SLUG_A / SESSION_A / SESSION_LOG_FILENAME
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"")
    with _expect(SessionLogError, REASON_HEADER_MISMATCH):
        sandbox["resolver"].resolve("task-a")


def test_corrupted_first_frame_rejected(sandbox) -> None:
    _seed(sandbox["store"], "task-a", worker_id="w-a", session_id=SESSION_A)
    path = _write_log(sandbox["root"], SLUG_A, SESSION_A)
    path.write_bytes(corrupt_frame(path.read_bytes(), 0))
    with _expect(SessionLogError, REASON_HEADER_MISMATCH):
        sandbox["resolver"].resolve("task-a")


def test_truncated_tail_after_valid_header_still_resolves(sandbox) -> None:
    """Identity lives in the header; incomplete tails are an *ingestion* gap."""

    _seed(sandbox["store"], "task-a", worker_id="w-a", session_id=SESSION_A)
    path = _write_log(sandbox["root"], SLUG_A, SESSION_A)
    path.write_bytes(truncate_last_frame(path.read_bytes(), drop=10))
    assert sandbox["resolver"].resolve("task-a").path == path


# ---------------------------------------------------------------------------
# Link / containment escapes
# ---------------------------------------------------------------------------


def test_containment_guard_rejects_outside_paths(sandbox) -> None:
    from ctf_solver.manager.session_logs import _contained_within_root

    outside = sandbox["tmp"] / "outside" / "session.v4.jsonl.zstd"
    outside.parent.mkdir(parents=True)
    outside.write_bytes(b"x")
    assert _contained_within_root(sandbox["root"], sandbox["root"] / "slug" / "sid" / "log") is True
    assert _contained_within_root(sandbox["root"], outside) is False


def test_path_escape_reason_code_is_wired(sandbox, monkeypatch) -> None:
    """Defense-in-depth guard (TOCTOU/race): a realpath escape maps to path_escape."""

    from ctf_solver.manager import session_logs

    _seed(sandbox["store"], "task-a", worker_id="w-a", session_id=SESSION_A)
    _write_log(sandbox["root"], SLUG_A, SESSION_A)
    monkeypatch.setattr(session_logs, "_contained_within_root", lambda root, path: False)
    with _expect(SessionLogError, REASON_PATH_ESCAPE):
        sandbox["resolver"].resolve("task-a")


def test_symlinked_sessions_root_rejected(sandbox) -> None:
    _seed(sandbox["store"], "task-a", worker_id="w-a", session_id=SESSION_A)
    real_root = sandbox["tmp"] / "real-sessions"
    _write_log(real_root, SLUG_A, SESSION_A)
    link_root = sandbox["tmp"] / "linked-sessions"
    kind = _create_link(real_root, link_root, directory=True)
    if not kind:
        pytest.skip(LINK_SKIP_REASON)
    resolver = SessionLogResolver(link_root, sandbox["store"])
    with _expect(SessionLogError, REASON_SYMLINK_REJECTED):
        resolver.resolve("task-a")


def test_symlinked_slug_directory_rejected(sandbox) -> None:
    _seed(sandbox["store"], "task-a", worker_id="w-a", session_id=SESSION_A)
    outside = sandbox["tmp"] / "outside-sessions"
    _write_log(outside, SLUG_A, SESSION_A)
    kind = _create_link(outside / SLUG_A, sandbox["root"] / SLUG_A, directory=True)
    if not kind:
        pytest.skip(LINK_SKIP_REASON)
    with _expect(SessionLogError, REASON_SYMLINK_REJECTED):
        sandbox["resolver"].resolve("task-a")


def test_symlinked_session_directory_rejected(sandbox) -> None:
    _seed(sandbox["store"], "task-a", worker_id="w-a", session_id=SESSION_A)
    outside = sandbox["tmp"] / "outside-sessions"
    _write_log(outside, SLUG_A, SESSION_A)
    slug_dir = sandbox["root"] / SLUG_A
    slug_dir.mkdir(parents=True)
    kind = _create_link(outside / SLUG_A / SESSION_A, slug_dir / SESSION_A, directory=True)
    if not kind:
        pytest.skip(LINK_SKIP_REASON)
    with _expect(SessionLogError, REASON_SYMLINK_REJECTED):
        sandbox["resolver"].resolve("task-a")


def test_symlinked_log_file_rejected(sandbox) -> None:
    _seed(sandbox["store"], "task-a", worker_id="w-a", session_id=SESSION_A)
    outside = sandbox["tmp"] / "outside-sessions"
    real_log = _write_log(outside, SLUG_A, SESSION_A)
    target_dir = sandbox["root"] / SLUG_A / SESSION_A
    target_dir.mkdir(parents=True)
    kind = _create_link(real_log, target_dir / SESSION_LOG_FILENAME, directory=False)
    if not kind:
        pytest.skip(LINK_SKIP_REASON)
    with _expect(SessionLogError, REASON_SYMLINK_REJECTED):
        sandbox["resolver"].resolve("task-a")


def test_two_tasks_with_logs_resolve_independently(sandbox) -> None:
    _seed(sandbox["store"], "task-a", worker_id="w-a", session_id=SESSION_A)
    _seed(sandbox["store"], "task-b", worker_id="w-b", session_id=SESSION_B)
    path_a = _write_log(sandbox["root"], SLUG_A, SESSION_A)
    path_b = _write_log(sandbox["root"], SLUG_B, SESSION_B)

    resolved_a = sandbox["resolver"].resolve("task-a")
    resolved_b = sandbox["resolver"].resolve("task-b")
    assert resolved_a.path == path_a
    assert resolved_b.path == path_b
    assert resolved_a.path != resolved_b.path
    # A resolved log never leaks records from the other Task's session.
    text = resolved_a.path.read_bytes()
    assert text != resolved_b.path.read_bytes()
