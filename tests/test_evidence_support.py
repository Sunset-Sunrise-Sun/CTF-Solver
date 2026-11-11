"""Shared deterministic helpers for the evidence test suites.

This module intentionally contains no tests: it is imported by
``tests/test_evidence_*.py`` and ``tests/test_zstd_*.py`` so the fixtures and
tamper helpers stay identical across suites (the evidence write scope only
covers ``tests/test_evidence_*`` / ``tests/test_zstd_*``).
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any, Iterable

from ctf_solver.core.canonical import canonical_json, file_sha256
from ctf_solver.core.types import CaptureStatus, ScreenshotRecord
from ctf_solver.evidence.cas import Cas
from ctf_solver.evidence.ingest import IngestReport, Ingestor
from ctf_solver.evidence.store import EvidenceStore
from tests.support.session_events import standard_session
from tests.support.zstd_fixtures import build_log_from_chunks, build_session_log, jsonl_bytes

BASE_MS = 1_700_000_000_000
DEFAULT_TASK_ID = "task-1"
DEFAULT_WORKER_ID = "worker-1"
DEFAULT_SESSION_ID = "session-1"
DEFAULT_SOURCE_ID = "session-log-1"

_EVENTS_TRIGGERS = (
    "CREATE TRIGGER IF NOT EXISTS events_no_update BEFORE UPDATE ON events "
    "BEGIN SELECT RAISE(ABORT, 'events table is append-only'); END",
    "CREATE TRIGGER IF NOT EXISTS events_no_delete BEFORE DELETE ON events "
    "BEGIN SELECT RAISE(ABORT, 'events table is append-only'); END",
)


class FakeClock:
    """Deterministic ``Clock`` implementation for evidence tests."""

    def __init__(self, now_ms: int = BASE_MS) -> None:
        self._now = int(now_ms)

    def now_ms(self) -> int:
        return self._now

    def advance(self, delta_ms: int) -> int:
        self._now += int(delta_ms)
        return self._now


def make_store(tmp_path: Path, *, clock: Any | None = None) -> EvidenceStore:
    """Create an :class:`EvidenceStore` rooted under ``tmp_path``."""

    return EvidenceStore.from_root(Path(tmp_path) / "project", clock=clock or FakeClock())


def make_cas(tmp_path: Path) -> Cas:
    return Cas(Path(tmp_path) / "cas")


def make_screenshot(
    task_id: str = DEFAULT_TASK_ID,
    *,
    screenshot_id: str = "shot-1",
    status: CaptureStatus = CaptureStatus.OK,
    sha256: str | None = "ab" * 32,
    width: int = 1280,
    height: int = 720,
    step_id: str = "step-1",
    worker_id: str = DEFAULT_WORKER_ID,
    session_id: str = DEFAULT_SESSION_ID,
    scope: str = "desktop",
    captured_at: int = BASE_MS,
    failure_reason: str = "",
    execution_id: str | None = "exec-1",
) -> ScreenshotRecord:
    return ScreenshotRecord(
        screenshot_id=screenshot_id,
        task_id=task_id,
        scope=scope,
        captured_at=captured_at,
        status=status,
        worker_id=worker_id,
        step_id=step_id,
        session_id=session_id,
        sha256=sha256,
        width=width,
        height=height,
        media_type="image/png",
        failure_reason=failure_reason,
        execution_id=execution_id,
    )


def insert_task_row(
    store: EvidenceStore,
    task_id: str = DEFAULT_TASK_ID,
    *,
    status: str = "running",
    category: str = "misc",
) -> None:
    """Insert a minimal ``tasks`` row so FK-backed tables accept evidence rows."""

    store.connection.execute(
        "INSERT OR IGNORE INTO tasks("
        "task_id, conversation_id, title, category, source, scope_profile, "
        "workspace_path, status, created_at, updated_at) "
        "VALUES(?,?,?,?,?,?,?,?,?,?)",
        (
            task_id,
            "conversation-1",
            "Synthetic challenge",
            category,
            "unit-test",
            "",
            f"D:/synthetic/tasks/{task_id}/work",
            status,
            BASE_MS,
            BASE_MS,
        ),
    )


# ---------------------------------------------------------------------------
# Session-log fixtures
# ---------------------------------------------------------------------------


def sample_records(**kwargs: Any) -> list[dict[str, Any]]:
    return standard_session(**kwargs)


def session_log_bytes(records: Iterable[dict[str, Any]], *, frames: int = 4) -> bytes:
    return build_session_log(records, frames=frames)


def json_lines(*records: dict[str, Any]) -> bytes:
    return jsonl_bytes(records)


def chunked_log(*chunks: bytes) -> bytes:
    return build_log_from_chunks(list(chunks))


def ingest_bytes(
    store: EvidenceStore,
    data: bytes,
    *,
    task_id: str = DEFAULT_TASK_ID,
    worker_id: str = DEFAULT_WORKER_ID,
    session_id: str = DEFAULT_SESSION_ID,
    source_id: str = DEFAULT_SOURCE_ID,
    path: str | None = None,
) -> IngestReport:
    return Ingestor(store, store.cas).ingest_session_log_bytes(
        task_id=task_id,
        worker_id=worker_id,
        session_id=session_id,
        data=data,
        source_id=source_id,
        path=path,
    )


def ingest_records(
    store: EvidenceStore,
    records: Iterable[dict[str, Any]],
    *,
    frames: int = 4,
    **kwargs: Any,
) -> tuple[bytes, IngestReport]:
    data = session_log_bytes(records, frames=frames)
    return data, ingest_bytes(store, data, **kwargs)


# ---------------------------------------------------------------------------
# Raw (attacker-like) database access used by tamper tests
# ---------------------------------------------------------------------------


def raw_connect(db_path: str | Path) -> sqlite3.Connection:
    connection = sqlite3.connect(str(db_path), isolation_level=None)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA busy_timeout=10000")
    connection.execute("PRAGMA foreign_keys=ON")
    return connection


def drop_events_triggers(connection: sqlite3.Connection) -> None:
    connection.execute("DROP TRIGGER IF EXISTS events_no_update")
    connection.execute("DROP TRIGGER IF EXISTS events_no_delete")


def restore_events_triggers(connection: sqlite3.Connection) -> None:
    for statement in _EVENTS_TRIGGERS:
        connection.execute(statement)


def tamper_events(db_path: str | Path, sql: str, params: Iterable[Any] = ()) -> None:
    """Simulate an attacker with raw DB access mutating the append-only table.

    The update/delete triggers are dropped first (an attacker with file access
    can do that), the mutation is committed, and the triggers are restored so
    the database keeps its declared append-only guard for anything that runs
    afterwards. Detection must come from ``chain_status`` regardless.
    """

    connection = raw_connect(db_path)
    try:
        drop_events_triggers(connection)
        connection.execute(sql, tuple(params))
        restore_events_triggers(connection)
    finally:
        connection.close()


def raw_execute(db_path: str | Path, sql: str, params: Iterable[Any] = ()) -> list[sqlite3.Row]:
    connection = raw_connect(db_path)
    try:
        cursor = connection.execute(sql, tuple(params))
        return cursor.fetchall()
    finally:
        connection.close()


def raw_scalar(db_path: str | Path, sql: str, params: Iterable[Any] = ()) -> Any:
    rows = raw_execute(db_path, sql, params)
    if not rows:
        return None
    return rows[0][0]


def events_snapshot(store: EvidenceStore) -> dict[str, Any]:
    """Logical snapshot of evidence state used to prove "no SQLite writes"."""

    rows = [canonical_json(event) for event in store.list_events()]
    return {
        "head": store.chain_head(),
        "count": store.count_events(),
        "events": rows,
        "exports": store.list_exports(),
        "artifacts": store.list_artifacts(),
    }


def file_sha(path: str | Path) -> str:
    return file_sha256(Path(path))
