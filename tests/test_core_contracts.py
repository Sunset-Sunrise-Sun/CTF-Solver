"""Contract tests for shared core types, storage schema and safety helpers."""

from __future__ import annotations

import json
import sqlite3

import pytest

from ctf_solver.core import canonical
from ctf_solver.core.config import SolverConfig, SolverPaths
from ctf_solver.core.errors import ConfigError, ValidationError
from ctf_solver.core.ids import is_valid_id, is_valid_step_id, new_id, new_worker_token
from ctf_solver.core.paths import ensure_relative_safe, is_within, relative_inside
from ctf_solver.core.types import (
    Category,
    ExecRequest,
    ExecutionTier,
    TaskRecord,
    TaskStatus,
    can_transition,
)
from ctf_solver.storage.db import (
    get_meta,
    initialize_schema,
    open_database,
    set_meta,
    table_names,
    transaction,
)


def test_canonical_json_is_stable_and_utf8() -> None:
    first = canonical.canonical_json({"b": 1, "a": "中文", "c": [1, 2]})
    second = canonical.canonical_json({"c": [1, 2], "a": "中文", "b": 1})
    assert first == second
    assert "中文" in first
    assert canonical.canonical_bytes({"a": 1}) == b'{"a":1}'


def test_chain_hash_depends_on_previous_hash() -> None:
    record = {"event_type": "tool_call", "seq": 1}
    assert canonical.chain_hash(canonical.GENESIS_HASH, record) != canonical.chain_hash("f" * 64, record)
    assert len(canonical.chain_hash(canonical.GENESIS_HASH, record)) == 64


def test_schema_has_required_tables_and_meta(tmp_path) -> None:
    conn = open_database(tmp_path / "m.sqlite")
    try:
        names = set(table_names(conn))
        assert {
            "meta",
            "tasks",
            "workers",
            "approvals",
            "network_grants",
            "executions",
            "events",
            "artifacts",
            "screenshots",
            "ingestion_sources",
            "exports",
        } <= names
        assert get_meta(conn, "schema_version") == "1.0"
        assert get_meta(conn, "events_chain_head") == canonical.GENESIS_HASH
        assert get_meta(conn, "events_chain_head_seq") == "0"
        # Idempotent initialization.
        initialize_schema(conn)
    finally:
        conn.close()


def test_events_are_append_only(tmp_path) -> None:
    conn = open_database(tmp_path / "m.sqlite")
    try:
        with transaction(conn):
            conn.execute(
                "INSERT INTO events(record_id, task_id, source, source_id, source_seq, event_type,"
                " timestamp, payload_json, prev_hash, record_hash, ingested_at)"
                " VALUES('ev-1','t-1','runtime','runtime:x',1,'execution_started',1,'{}',?,?,1)",
                (canonical.GENESIS_HASH, "a" * 64),
            )
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("UPDATE events SET event_type='tampered' WHERE record_id='ev-1'")
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("DELETE FROM events WHERE record_id='ev-1'")
        assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 1
    finally:
        conn.close()


def test_meta_round_trip(tmp_path) -> None:
    conn = open_database(tmp_path / "m.sqlite")
    try:
        with transaction(conn):
            set_meta(conn, "events_chain_head", "b" * 64)
        assert get_meta(conn, "events_chain_head") == "b" * 64
    finally:
        conn.close()


def test_task_transition_rules() -> None:
    assert can_transition(TaskStatus.CREATED, TaskStatus.QUEUED)
    assert can_transition(TaskStatus.QUEUED, TaskStatus.STARTING)
    assert can_transition(TaskStatus.RUNNING, TaskStatus.CANCEL_REQUESTED)
    assert can_transition(TaskStatus.CANCEL_REQUESTED, TaskStatus.CANCELLED)
    assert not can_transition(TaskStatus.CANCELLED, TaskStatus.RUNNING)
    assert not can_transition(TaskStatus.COMPLETED, TaskStatus.RUNNING)
    # Queued Tasks skip starting only via the documented transitions.
    assert not can_transition(TaskStatus.QUEUED, TaskStatus.RUNNING)


def test_task_record_round_trip() -> None:
    record = TaskRecord(
        task_id="t-abc",
        conversation_id="conv",
        title="Title",
        category=Category.WEB,
        workspace_path="D:/x/work",
        status=TaskStatus.QUEUED,
        created_at=5,
        updated_at=6,
    )
    row = {
        **record.to_dict(),
        "category": record.category.value,
        "status": record.status.value,
    }
    restored = TaskRecord.from_row(row)
    assert restored.to_dict() == record.to_dict()


def test_exec_request_parsing() -> None:
    base = {
        "task_id": "t-1",
        "worker_id": "w-1",
        "step_id": "step-1",
        "tool_name": "internal.file_hash",
        "argv": ["file.txt"],
        "cwd": "D:/x/work",
    }
    request = ExecRequest.from_mapping(base)
    assert request.tier is ExecutionTier.TIER1_TRUSTED
    assert request.timeout_s == 30.0
    with pytest.raises(ValidationError):
        ExecRequest.from_mapping({**base, "argv": "file.txt"})
    with pytest.raises(ValidationError):
        ExecRequest.from_mapping({**base, "timeout_s": 10_000})
    with pytest.raises(ValidationError):
        ExecRequest.from_mapping({k: v for k, v in base.items() if k != "cwd"})


def test_category_parsing() -> None:
    assert Category.parse("WEB") is Category.WEB
    assert Category.parse("misc") is Category.MISC
    with pytest.raises(ValueError):
        Category.parse("web3")


def test_ids() -> None:
    task_id = new_id("t")
    assert task_id.startswith("t-") and is_valid_id(task_id)
    assert is_valid_step_id("step-1")
    assert not is_valid_step_id("bad step")
    assert not is_valid_id("")
    assert len(new_worker_token()) >= 32


def test_path_containment(tmp_path) -> None:
    root = tmp_path / "root"
    inside = root / "a" / "b.txt"
    inside.parent.mkdir(parents=True)
    inside.write_text("x", encoding="utf-8")
    assert is_within(inside, root) is True
    assert is_within(root, root) is True
    assert is_within(tmp_path / "elsewhere", root) is False
    assert relative_inside(inside, root) == "a/b.txt"
    with pytest.raises(ValueError):
        relative_inside(tmp_path / "elsewhere", root)


def test_relative_path_safety() -> None:
    assert ensure_relative_safe("a/b.txt") == "a/b.txt"
    assert ensure_relative_safe("a\\b.txt") == "a/b.txt"
    for bad in ("/abs/path", "C:/abs", "../escape", "a/../../b", "", "a/./../b"):
        with pytest.raises(ValueError):
            ensure_relative_safe(bad)


def test_solver_paths_layout(tmp_path) -> None:
    paths = SolverPaths.for_root(tmp_path)
    assert paths.db_path == tmp_path / ".ctf-solver-data" / "manager.sqlite"
    assert paths.task_workspace("t-1") == tmp_path / "tasks" / "t-1" / "work"
    paths.ensure()
    assert paths.data_dir.is_dir()
    assert paths.cas_dir.is_dir()


def test_solver_config_contract_boundaries(tmp_path) -> None:
    config = SolverConfig(root=tmp_path)
    assert config.max_active_workers == 2
    with pytest.raises(ConfigError):
        SolverConfig(root=tmp_path, max_active_workers=3)
    with pytest.raises(ConfigError):
        SolverConfig(root=tmp_path, allow_model_calls=True)


def test_json_serialisability_of_export_types(tmp_path) -> None:
    from ctf_solver.core.types import ArtifactRef, BrokerDecision, ExportInfo

    payload = {
        "artifact": ArtifactRef(sha256="a" * 64, size=1).to_dict(),
        "decision": BrokerDecision.deny("denied", "nope").to_dict(),
        "export": ExportInfo(kind="x", path="p", sha256="b" * 64, size=2).to_dict(),
    }
    json.dumps(payload)
