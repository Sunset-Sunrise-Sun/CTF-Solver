"""SQLite schema and connection helpers (single authoritative store).

The schema is shared by the Manager state repository, the evidence chain and
the delivery pipeline. ``events`` is append-only: UPDATE/DELETE triggers make
accidental (and casual) tampering fail loudly, and verification recomputes the
hash chain against the protected chain head in ``meta``.

Security note: this is a tamper-evident bookkeeping chain, not a digital
signature.
"""

from __future__ import annotations

import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from .. import SCHEMA_VERSION
from ..core.canonical import GENESIS_HASH
from ..core.errors import StorageError

META_SCHEMA_VERSION = "schema_version"
META_CHAIN_HEAD = "events_chain_head"
META_CHAIN_HEAD_SEQ = "events_chain_head_seq"
META_CREATED_AT = "store_created_at"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tasks (
    task_id          TEXT PRIMARY KEY,
    conversation_id  TEXT NOT NULL,
    title            TEXT NOT NULL,
    category         TEXT NOT NULL CHECK (category IN ('web','misc','crypto','reverse','pwn')),
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
CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status);
CREATE INDEX IF NOT EXISTS idx_tasks_created ON tasks(created_at, task_id);
CREATE INDEX IF NOT EXISTS idx_tasks_conversation ON tasks(conversation_id);

CREATE TABLE IF NOT EXISTS workers (
    worker_id       TEXT PRIMARY KEY,
    task_id         TEXT NOT NULL UNIQUE REFERENCES tasks(task_id),
    acp_session_id  TEXT NOT NULL,
    workspace_path  TEXT NOT NULL,
    status          TEXT NOT NULL,
    worker_token    TEXT NOT NULL UNIQUE,
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_workers_status ON workers(status);

CREATE TABLE IF NOT EXISTS approvals (
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
CREATE INDEX IF NOT EXISTS idx_approvals_task ON approvals(task_id, status);

CREATE TABLE IF NOT EXISTS network_grants (
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
CREATE INDEX IF NOT EXISTS idx_grants_task ON network_grants(task_id, status);

CREATE TABLE IF NOT EXISTS executions (
    execution_id    TEXT PRIMARY KEY,
    task_id         TEXT NOT NULL REFERENCES tasks(task_id),
    worker_id       TEXT NOT NULL,
    step_id         TEXT NOT NULL,
    tool_name       TEXT NOT NULL,
    tool_version    TEXT,
    argv_json       TEXT NOT NULL,
    cwd             TEXT NOT NULL,
    tier            INTEGER NOT NULL,
    status          TEXT NOT NULL,
    exit_code       INTEGER,
    reason_code     TEXT,
    reason          TEXT NOT NULL DEFAULT '',
    started_at      INTEGER NOT NULL,
    ended_at        INTEGER,
    stdout_sha256   TEXT,
    stderr_sha256   TEXT,
    stdout_preview  TEXT NOT NULL DEFAULT '',
    stderr_preview  TEXT NOT NULL DEFAULT '',
    network_grant_id TEXT,
    approval_id     TEXT,
    request_json    TEXT NOT NULL,
    result_json     TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_exec_task ON executions(task_id, started_at);
CREATE INDEX IF NOT EXISTS idx_exec_worker ON executions(worker_id, started_at);

CREATE TABLE IF NOT EXISTS events (
    seq          INTEGER PRIMARY KEY AUTOINCREMENT,
    record_id    TEXT NOT NULL UNIQUE,
    task_id      TEXT NOT NULL,
    worker_id    TEXT,
    session_id   TEXT,
    source       TEXT NOT NULL,
    source_id    TEXT NOT NULL,
    source_seq   INTEGER,
    event_type   TEXT NOT NULL,
    timestamp    INTEGER NOT NULL,
    payload_json TEXT NOT NULL,
    prev_hash    TEXT NOT NULL,
    record_hash  TEXT NOT NULL,
    ingested_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_task_seq ON events(task_id, seq);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
CREATE UNIQUE INDEX IF NOT EXISTS idx_events_source_seq
    ON events(source_id, source_seq) WHERE source_seq IS NOT NULL;

CREATE TRIGGER IF NOT EXISTS events_no_update
BEFORE UPDATE ON events
BEGIN
    SELECT RAISE(ABORT, 'events table is append-only');
END;

CREATE TRIGGER IF NOT EXISTS events_no_delete
BEFORE DELETE ON events
BEGIN
    SELECT RAISE(ABORT, 'events table is append-only');
END;

CREATE TABLE IF NOT EXISTS artifacts (
    sha256      TEXT PRIMARY KEY,
    size        INTEGER NOT NULL,
    media_type  TEXT NOT NULL,
    source      TEXT NOT NULL DEFAULT '',
    created_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS screenshots (
    screenshot_id  TEXT PRIMARY KEY,
    task_id        TEXT NOT NULL REFERENCES tasks(task_id),
    worker_id      TEXT,
    step_id        TEXT,
    session_id     TEXT,
    scope          TEXT NOT NULL,
    captured_at    INTEGER NOT NULL,
    sha256         TEXT,
    width          INTEGER,
    height         INTEGER,
    status         TEXT NOT NULL,
    failure_reason TEXT NOT NULL DEFAULT '',
    media_type     TEXT NOT NULL DEFAULT 'image/png',
    execution_id   TEXT
);
CREATE INDEX IF NOT EXISTS idx_shots_task ON screenshots(task_id, captured_at);

CREATE TABLE IF NOT EXISTS ingestion_sources (
    source_id    TEXT PRIMARY KEY,
    task_id      TEXT NOT NULL,
    session_id   TEXT,
    last_seq     INTEGER NOT NULL DEFAULT -1,
    sha256       TEXT NOT NULL DEFAULT '',
    raw_sha256   TEXT,
    frames       INTEGER NOT NULL DEFAULT 0,
    records      INTEGER NOT NULL DEFAULT 0,
    gaps         INTEGER NOT NULL DEFAULT 0,
    updated_at   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS exports (
    export_id   TEXT PRIMARY KEY,
    task_id     TEXT NOT NULL,
    kind        TEXT NOT NULL,
    path        TEXT NOT NULL,
    sha256      TEXT NOT NULL,
    created_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_exports_task ON exports(task_id, kind, created_at);
"""


def default_db_path(root: str | os.PathLike[str]) -> Path:
    return Path(os.path.abspath(os.fspath(root))) / ".ctf-solver-data" / "manager.sqlite"


def open_database(path: str | os.PathLike[str], *, initialize: bool = True) -> sqlite3.Connection:
    db_path = Path(path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=10000")
    conn.execute("PRAGMA synchronous=NORMAL")
    if initialize:
        initialize_schema(conn)
    return conn


def initialize_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(_SCHEMA)
    with transaction(conn):
        row = conn.execute(
            "SELECT value FROM meta WHERE key = ?", (META_SCHEMA_VERSION,)
        ).fetchone()
        if row is None:
            conn.execute(
                "INSERT INTO meta(key, value) VALUES(?, ?)", (META_SCHEMA_VERSION, SCHEMA_VERSION)
            )
            conn.execute(
                "INSERT OR IGNORE INTO meta(key, value) VALUES(?, ?)",
                (META_CHAIN_HEAD, GENESIS_HASH),
            )
            conn.execute(
                "INSERT OR IGNORE INTO meta(key, value) VALUES(?, '0')", (META_CHAIN_HEAD_SEQ,)
            )
            conn.execute(
                "INSERT OR IGNORE INTO meta(key, value) VALUES(?, CAST(strftime('%s','now') AS TEXT))",
                (META_CREATED_AT,),
            )
        elif row["value"] != SCHEMA_VERSION:
            raise StorageError(
                f"unsupported database schema version {row['value']!r}; expected {SCHEMA_VERSION!r}"
            )
    # Ensure the chain head exists even for databases created by older runs.
    conn.execute(
        "INSERT OR IGNORE INTO meta(key, value) VALUES(?, ?)", (META_CHAIN_HEAD, GENESIS_HASH)
    )
    conn.execute("INSERT OR IGNORE INTO meta(key, value) VALUES(?, '0')", (META_CHAIN_HEAD_SEQ,))


@contextmanager
def transaction(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    """Explicit ``BEGIN IMMEDIATE`` transaction helper.

    Nested calls reuse the outer transaction so helpers can compose.
    """

    if conn.in_transaction:
        yield conn
        return
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    else:
        conn.execute("COMMIT")


def get_meta(conn: sqlite3.Connection, key: str, default: str | None = None) -> str | None:
    row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
    return row["value"] if row is not None else default


def set_meta(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute(
        "INSERT INTO meta(key, value) VALUES(?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, value),
    )


def table_names(conn: sqlite3.Connection) -> list[str]:
    rows = conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
    ).fetchall()
    return [row["name"] for row in rows]
