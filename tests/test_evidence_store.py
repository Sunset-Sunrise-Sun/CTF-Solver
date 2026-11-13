"""Deterministic tests for the append-only hash-chained evidence store."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

import pytest

from ctf_solver.core.canonical import GENESIS_HASH, canonical_json, chain_hash
from ctf_solver.core.errors import NotFoundError, StorageError, ValidationError
from ctf_solver.core.types import CaptureStatus
from ctf_solver.evidence.store import EvidenceStore
from tests.test_evidence_support import (
    DEFAULT_SOURCE_ID,
    DEFAULT_TASK_ID,
    FakeClock,
    events_snapshot,
    insert_task_row,
    make_screenshot,
    make_store,
    raw_connect,
    raw_execute,
    raw_scalar,
    tamper_events,
)


def _chain_payload(row: dict) -> dict:
    """Independent reconstruction of the hashed record payload."""

    return {
        "seq": row["seq"],
        "record_id": row["record_id"],
        "task_id": row["task_id"],
        "worker_id": row["worker_id"],
        "session_id": row["session_id"],
        "source": row["source"],
        "source_id": row["source_id"],
        "source_seq": row["source_seq"],
        "event_type": row["event_type"],
        "timestamp": row["timestamp"],
        "payload": row["payload"],
        "ingested_at": row["ingested_at"],
    }


def _append_three(store: EvidenceStore) -> list[str]:
    return [
        store.append_event(
            task_id=DEFAULT_TASK_ID,
            source="runtime",
            source_id="execution:exec-1",
            source_seq=1,
            event_type="execution_started",
            payload={"execution_id": "exec-1", "tool_name": "internal.file_hash"},
            timestamp=1000,
        ),
        store.append_event(
            task_id=DEFAULT_TASK_ID,
            source="runtime",
            source_id="execution:exec-1",
            source_seq=2,
            event_type="execution_completed",
            payload={"execution_id": "exec-1", "status": "completed", "exit_code": 0},
            timestamp=1100,
        ),
        store.append_event(
            task_id=DEFAULT_TASK_ID,
            source="manager",
            event_type="task_created",
            payload={"title": "synthetic", "category": "misc"},
            timestamp=900,
        ),
    ]


# ---------------------------------------------------------------------------
# Append + chain
# ---------------------------------------------------------------------------


def test_append_event_returns_id_and_advances_chain(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    record_ids = _append_three(store)
    assert len(set(record_ids)) == 3
    assert store.count_events(DEFAULT_TASK_ID) == 3

    status = store.chain_status()
    assert status.ok is True
    assert status.records == 3
    assert status.error == ""
    assert status.broken_at_seq is None
    assert store.chain_head() == (3, status.head_hash)

    events = store.list_events()
    assert [event["seq"] for event in events] == [1, 2, 3]
    assert events[0]["prev_hash"] == GENESIS_HASH
    for index, event in enumerate(events):
        payload = _chain_payload(event)
        assert event["record_hash"] == chain_hash(event["prev_hash"], payload)
        if index:
            assert event["prev_hash"] == events[index - 1]["record_hash"]


def test_empty_store_chain_status_is_clean(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    status = store.chain_status()
    assert status.ok is True
    assert status.records == 0
    assert status.head_hash == GENESIS_HASH
    assert store.chain_head() == (0, GENESIS_HASH)
    assert store.count_events() == 0
    assert store.list_events() == []


def test_store_satisfies_evidence_sink_protocol(tmp_path: Path) -> None:
    """The Manager/Runtime integration depends on the frozen protocol surface."""

    from ctf_solver.core.protocols import EvidenceSink

    store = make_store(tmp_path)
    assert isinstance(store, EvidenceSink)
    record_id = store.append_event(
        task_id=DEFAULT_TASK_ID,
        worker_id="worker-1",
        session_id="session-1",
        source="runtime",
        source_id="execution:exec-9",
        source_seq=1,
        event_type="execution_started",
        payload={"execution_id": "exec-9", "tool_name": "internal.file_hash"},
    )
    ref = store.store_artifact(b"stdout bytes", media_type="text/plain", source="runtime")
    assert isinstance(record_id, str) and record_id
    assert ref.sha256
    assert store.cas.get_bytes(ref.sha256) == b"stdout bytes"


def test_read_artifact_and_ingestion_sources_for_delivery(tmp_path: Path) -> None:
    """Delivery's bundle builder reads CAS bytes and raw-source watermarks."""

    store = make_store(tmp_path)
    ref = store.store_artifact(b"writeup stdout bytes", media_type="text/plain")
    assert store.read_artifact(ref.sha256) == b"writeup stdout bytes"
    with pytest.raises(NotFoundError):
        store.read_artifact("c" * 64)

    assert store.ingestion_sources(DEFAULT_TASK_ID) == []
    store.record_ingestion(
        DEFAULT_SOURCE_ID,
        task_id=DEFAULT_TASK_ID,
        session_id="session-1",
        last_seq=7,
        sha256="aa" * 32,
        raw_sha256=ref.sha256,
        frames=2,
        records=8,
        gaps=0,
    )
    store.record_ingestion(
        "session-log-2",
        task_id=DEFAULT_TASK_ID,
        session_id="session-2",
        last_seq=3,
        sha256="bb" * 32,
        raw_sha256=ref.sha256,
        frames=1,
        records=4,
        gaps=1,
    )
    sources = store.ingestion_sources(DEFAULT_TASK_ID)
    assert len(sources) == 2
    assert {row["source_id"] for row in sources} == {DEFAULT_SOURCE_ID, "session-log-2"}
    assert all(row["task_id"] == DEFAULT_TASK_ID for row in sources)
    assert sources[0]["raw_sha256"] == ref.sha256


def test_store_integration_method_surface(tmp_path: Path) -> None:
    """Exact method names the Manager/Delivery integration calls (INTERFACES §4.4)."""

    store = make_store(tmp_path)
    method_names = (
        "append_event",
        "append_events",
        "store_artifact",
        "store_artifact_file",
        "record_artifact",
        "read_artifact",
        "ingestion_sources",
        "list_events",
        "get_event",
        "count_events",
        "chain_status",
        "chain_head",
        "export_events_jsonl",
        "record_screenshot",
        "list_screenshots",
        "get_task_events_for_writeup",
        "ingest_state",
        "record_export",
        "record_ingestion",
        "ingest_session_log_bytes",
        "ingest_session_log_file",
    )
    for name in method_names:
        assert callable(getattr(store, name)), name
    assert EvidenceStore.from_root(tmp_path / "other-root") is not None
    # Convenience writeup query is ordered by seq.
    _append_three(store)
    writeup_events = store.get_task_events_for_writeup(DEFAULT_TASK_ID)
    assert [event["seq"] for event in writeup_events] == [1, 2, 3]


def test_append_event_is_idempotent_for_identical_content(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    kwargs = {
        "task_id": DEFAULT_TASK_ID,
        "source": "manager",
        "source_id": "task:task-1",
        "source_seq": 1,
        "event_type": "task_created",
        "payload": {"title": "same"},
        "timestamp": 1000,
    }
    first = store.append_event(**kwargs)
    second = store.append_event(**kwargs)
    assert first == second
    assert store.count_events() == 1


def test_append_event_rejects_conflicting_record_id(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    store.append_event(
        task_id=DEFAULT_TASK_ID,
        source="runtime",
        source_id="execution:e1",
        event_type="execution_started",
        payload={"v": 1},
        record_id="ev-fixed-record",
        timestamp=1000,
    )
    with pytest.raises(StorageError):
        store.append_event(
            task_id=DEFAULT_TASK_ID,
            source="runtime",
            source_id="execution:e1",
            event_type="execution_started",
            payload={"v": 2},
            record_id="ev-fixed-record",
            timestamp=1000,
        )


def test_append_event_rejects_conflicting_source_sequence(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    store.append_event(
        task_id=DEFAULT_TASK_ID,
        source="runtime",
        source_id="execution:e1",
        source_seq=1,
        event_type="execution_started",
        payload={},
        timestamp=1000,
    )
    with pytest.raises(StorageError):
        store.append_event(
            task_id=DEFAULT_TASK_ID,
            source="runtime",
            source_id="execution:e1",
            source_seq=1,
            event_type="execution_completed",
            payload={},
            timestamp=1000,
        )


def test_append_events_batch_and_skip_duplicates(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    events = [
        {
            "task_id": DEFAULT_TASK_ID,
            "source": "manager",
            "source_id": "task:task-1",
            "source_seq": 1,
            "event_type": "task_created",
            "payload": {"title": "synthetic"},
            "timestamp": 1000,
        },
        {
            "task_id": DEFAULT_TASK_ID,
            "source": "manager",
            "source_id": "task:task-1",
            "source_seq": 2,
            "event_type": "task_started",
            "payload": {"worker_id": "worker-1"},
            "timestamp": 1100,
        },
    ]
    appended = store.append_events(events)
    assert len(appended) == 2
    assert store.count_events() == 2
    again = store.append_events(events, skip_duplicates=True)
    assert again == []
    assert store.count_events() == 2
    # Identical re-append is idempotent even without ``skip_duplicates``.
    assert store.append_events(events) == []
    # A *different* record for the same (source_id, source_seq) fails closed.
    conflicting = dict(events[1])
    conflicting["event_type"] = "task_paused"
    with pytest.raises(StorageError):
        store.append_events([conflicting])
    assert store.count_events() == 2
    # Batch append keeps the chain contiguous and clean.
    assert store.chain_status().ok is True


def test_append_event_validation_errors(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    with pytest.raises(ValidationError):
        store.append_event(task_id="", source="runtime", event_type="x", payload={})
    with pytest.raises(ValidationError):
        store.append_event(task_id="t", source="", event_type="x", payload={})
    with pytest.raises(ValidationError):
        store.append_event(task_id="t", source="runtime", event_type="", payload={})
    with pytest.raises(ValidationError):
        store.append_event(
            task_id="t", source="runtime", event_type="x", payload={"bad": object()}
        )
    with pytest.raises(ValidationError):
        store.append_event(
            task_id="t", source="runtime", event_type="x", payload={}, source_seq="1"
        )
    assert store.count_events() == 0


def test_default_source_id_and_clock_timestamp(tmp_path: Path) -> None:
    clock = FakeClock(12345)
    store = make_store(tmp_path, clock=clock)
    record_id = store.append_event(
        task_id=DEFAULT_TASK_ID, source="runtime", event_type="execution_started", payload={}
    )
    event = store.get_event(record_id)
    assert event is not None
    assert event["source_id"] == f"runtime:{DEFAULT_TASK_ID}"
    assert event["timestamp"] == 12345
    # Deterministic identity: appending the same defaulted event is idempotent.
    assert (
        store.append_event(
            task_id=DEFAULT_TASK_ID, source="runtime", event_type="execution_started", payload={}
        )
        == record_id
    )


# ---------------------------------------------------------------------------
# Queries
# ---------------------------------------------------------------------------


def test_list_events_filters_and_ordering(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    _append_three(store)
    store.append_event(
        task_id="task-2",
        source="manager",
        event_type="task_created",
        payload={"title": "other"},
        timestamp=1200,
    )
    assert store.count_events() == 4
    assert store.count_events(DEFAULT_TASK_ID) == 3
    assert store.count_events("task-2") == 1
    started = store.list_events(event_type="execution_started")
    assert [event["event_type"] for event in started] == ["execution_started"]
    after = store.list_events(after_seq=2)
    assert [event["seq"] for event in after] == [3, 4]
    limited = store.list_events(limit=2)
    assert [event["seq"] for event in limited] == [1, 2]
    assert store.list_events("task-2")[0]["task_id"] == "task-2"
    with pytest.raises(ValidationError):
        store.list_events(limit=-1)


def test_get_event_roundtrip(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    record_id = _append_three(store)[0]
    event = store.get_event(record_id)
    assert event is not None
    assert event["record_id"] == record_id
    assert event["payload"] == {"execution_id": "exec-1", "tool_name": "internal.file_hash"}
    assert isinstance(event["payload"], dict)
    assert store.get_event("ev-does-not-exist") is None


# ---------------------------------------------------------------------------
# Tamper / truncation detection
# ---------------------------------------------------------------------------


def test_chain_status_detects_tampered_payload(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    _append_three(store)
    assert store.chain_status().ok is True
    tamper_events(
        store.db_path,
        "UPDATE events SET payload_json = ? WHERE seq = 2",
        (canonical_json({"execution_id": "exec-1", "status": "COMPLETED", "exit_code": 0}),),
    )
    status = store.chain_status()
    assert status.ok is False
    assert status.broken_at_seq == 2
    assert "record_hash mismatch" in status.error


def test_chain_status_detects_truncated_events(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    _append_three(store)
    tamper_events(store.db_path, "DELETE FROM events WHERE seq = 3")
    status = store.chain_status()
    assert status.ok is False
    assert status.records == 2
    assert "truncated" in status.error.lower() or "head mismatch" in status.error.lower()


def test_chain_status_detects_deleted_middle_row(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    _append_three(store)
    tamper_events(store.db_path, "DELETE FROM events WHERE seq = 2")
    status = store.chain_status()
    assert status.ok is False
    assert status.broken_at_seq == 3  # first sequence discontinuity
    assert "sequence discontinuity" in status.error


def test_chain_status_detects_meta_head_mismatch(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    _append_three(store)
    tamper_events(
        store.db_path,
        "UPDATE meta SET value = ? WHERE key = 'events_chain_head'",
        (GENESIS_HASH,),
    )
    status = store.chain_status()
    assert status.ok is False
    assert "head mismatch" in status.error.lower()
    assert status.head_hash != store.chain_head()[1]


def test_events_table_rejects_casual_update_and_delete(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    _append_three(store)
    connection = raw_connect(store.db_path)
    try:
        with pytest.raises(sqlite3.DatabaseError):
            connection.execute("UPDATE events SET event_type = 'x' WHERE seq = 1")
        with pytest.raises(sqlite3.DatabaseError):
            connection.execute("DELETE FROM events WHERE seq = 1")
    finally:
        connection.close()
    assert store.count_events() == 3
    assert store.chain_status().ok is True


# ---------------------------------------------------------------------------
# Deterministic export
# ---------------------------------------------------------------------------


def test_export_events_jsonl_is_deterministic(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    _append_three(store)
    out_one = tmp_path / "exports" / "events-a.jsonl"
    out_two = tmp_path / "exports" / "events-b.jsonl"
    first = store.export_events_jsonl(task_id=DEFAULT_TASK_ID, out_path=out_one)
    second = store.export_events_jsonl(task_id=DEFAULT_TASK_ID, out_path=out_two)
    bytes_one = out_one.read_bytes()
    bytes_two = out_two.read_bytes()
    assert bytes_one == bytes_two
    assert first.sha256 == second.sha256 == hashlib.sha256(bytes_one).hexdigest()
    assert first.size == len(bytes_one)
    assert first.entries == 3
    assert first.kind == "events_jsonl"
    lines = bytes_one.decode("utf-8").splitlines()
    assert len(lines) == 3
    # The default export is the delivery privacy projection: identity keys plus
    # payload only, never hash-chain internals.
    identity_keys = {
        "seq",
        "record_id",
        "task_id",
        "worker_id",
        "session_id",
        "source",
        "source_id",
        "source_seq",
        "event_type",
        "timestamp",
        "payload",
    }
    for line in lines:
        parsed = json.loads(line)
        assert canonical_json(parsed) == line
        assert isinstance(parsed["payload"], dict)
        assert set(parsed) == identity_keys
    assert [json.loads(line)["seq"] for line in lines] == [1, 2, 3]
    # The raw committed view (internal/test use only) keeps the hash-chain fields.
    raw_out = tmp_path / "exports" / "events-raw.jsonl"
    raw_info = store.export_events_jsonl(
        task_id=DEFAULT_TASK_ID, out_path=raw_out, privacy_filtered=False
    )
    raw_lines = raw_out.read_text(encoding="utf-8").splitlines()
    assert raw_info.entries == 3
    assert [json.loads(line)["seq"] for line in raw_lines] == [1, 2, 3]
    assert all(json.loads(line)["record_hash"] for line in raw_lines)
    assert all(json.loads(line)["prev_hash"] for line in raw_lines)
    # Re-exporting after no change stays byte-identical.
    third = store.export_events_jsonl(task_id=DEFAULT_TASK_ID, out_path=out_one)
    assert third.sha256 == first.sha256
    assert out_one.read_bytes() == bytes_one


def test_export_has_no_sqlite_side_effects(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    _append_three(store)
    before = events_snapshot(store)
    ingestion_before = raw_scalar(store.db_path, "SELECT COUNT(*) FROM ingestion_sources")
    export_rows_before = raw_scalar(store.db_path, "SELECT COUNT(*) FROM exports")
    store.export_events_jsonl(task_id=DEFAULT_TASK_ID, out_path=tmp_path / "events.jsonl")
    after = events_snapshot(store)
    assert after == before
    assert raw_scalar(store.db_path, "SELECT COUNT(*) FROM ingestion_sources") == ingestion_before
    assert raw_scalar(store.db_path, "SELECT COUNT(*) FROM exports") == export_rows_before


def test_export_empty_task_produces_empty_file(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    out = tmp_path / "empty.jsonl"
    info = store.export_events_jsonl(task_id="task-unknown", out_path=out)
    assert out.read_bytes() == b""
    assert info.entries == 0
    assert info.sha256 == hashlib.sha256(b"").hexdigest()
    assert info.size == 0


# ---------------------------------------------------------------------------
# Artifacts, screenshots, exports, ingestion watermarks
# ---------------------------------------------------------------------------


def test_store_artifact_records_metadata_and_dedups(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    data = b"tool stdout bytes"
    ref = store.store_artifact(data, media_type="text/plain", source="runtime")
    assert store.cas.get_bytes(ref.sha256) == data
    row = store.get_artifact(ref.sha256)
    assert row is not None
    assert row["size"] == len(data)
    assert row["media_type"] == "text/plain"
    assert row["source"] == "runtime"
    again = store.store_artifact(data, media_type="text/plain", source="runtime")
    assert again.sha256 == ref.sha256
    assert len(store.list_artifacts()) == 1

    source_file = tmp_path / "artifact.bin"
    source_file.write_bytes(b"file artifact")
    file_ref = store.store_artifact_file(source_file, media_type="application/octet-stream")
    assert file_ref.sha256 == hashlib.sha256(b"file artifact").hexdigest()
    assert len(store.list_artifacts()) == 2
    with pytest.raises(NotFoundError):
        store.store_artifact_file(tmp_path / "missing.bin")
    with pytest.raises(ValidationError):
        store.store_artifact(1234)  # type: ignore[arg-type]


def test_record_screenshot_and_list(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    insert_task_row(store, DEFAULT_TASK_ID)
    ok_shot = make_screenshot(captured_at=1000)
    blank_shot = make_screenshot(
        screenshot_id="shot-blank",
        status=CaptureStatus.BLANK,
        sha256="cd" * 32,
        captured_at=2000,
    )
    failed_shot = make_screenshot(
        screenshot_id="shot-failed",
        status=CaptureStatus.FAILED,
        sha256=None,
        failure_reason="capture device unavailable",
        captured_at=3000,
    )
    for shot in (ok_shot, blank_shot, failed_shot):
        store.record_screenshot(shot)
    stored = store.list_screenshots(DEFAULT_TASK_ID)
    assert [shot.screenshot_id for shot in stored] == ["shot-1", "shot-blank", "shot-failed"]
    assert stored[0].status is CaptureStatus.OK
    assert stored[0].sha256 == "ab" * 32
    assert stored[1].status is CaptureStatus.BLANK
    assert stored[2].status is CaptureStatus.FAILED
    assert stored[2].failure_reason == "capture device unavailable"
    assert store.get_screenshot("shot-blank") is not None
    assert store.get_screenshot("nope") is None
    # Re-recording is idempotent (no duplicate rows).
    store.record_screenshot(ok_shot)
    assert len(store.list_screenshots(DEFAULT_TASK_ID)) == 3
    # FK: unknown task is reported as a storage error, not a silent success.
    with pytest.raises(StorageError):
        store.record_screenshot(make_screenshot(task_id="task-missing"))


def test_record_export_ledger(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    insert_task_row(store, DEFAULT_TASK_ID)
    out = tmp_path / "project" / "tasks" / DEFAULT_TASK_ID / "evidence" / "events.jsonl"
    store.append_event(
        task_id=DEFAULT_TASK_ID, source="manager", event_type="task_created", payload={}, timestamp=1
    )
    info = store.export_events_jsonl(task_id=DEFAULT_TASK_ID, out_path=out)
    store.record_export(info)
    exports = store.list_exports(DEFAULT_TASK_ID)
    assert len(exports) == 1
    assert exports[0]["kind"] == "events_jsonl"
    assert exports[0]["sha256"] == info.sha256
    assert exports[0]["path"] == str(out)
    store.record_export(info)  # upsert, not a duplicate
    assert len(store.list_exports(DEFAULT_TASK_ID)) == 1


def test_ingest_state_roundtrip(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    assert store.ingest_state("session-log-1") is None
    store.record_ingestion(
        DEFAULT_SOURCE_ID,
        task_id=DEFAULT_TASK_ID,
        session_id="session-1",
        last_seq=9,
        sha256="aa" * 32,
        raw_sha256="bb" * 32,
        frames=3,
        records=10,
        gaps=1,
    )
    state = store.ingest_state(DEFAULT_SOURCE_ID)
    assert state is not None
    assert state["last_seq"] == 9
    assert state["frames"] == 3
    assert state["records"] == 10
    assert state["gaps"] == 1
    assert state["raw_sha256"] == "bb" * 32
    # The watermark never moves backwards.
    store.record_ingestion(
        DEFAULT_SOURCE_ID, task_id=DEFAULT_TASK_ID, last_seq=4, sha256="cc" * 32
    )
    state = store.ingest_state(DEFAULT_SOURCE_ID)
    assert state is not None and state["last_seq"] == 9


# ---------------------------------------------------------------------------
# Reopen / crash recovery
# ---------------------------------------------------------------------------


def test_failed_batch_rolls_back_atomically(tmp_path: Path) -> None:
    """A failed append must not leave a half-written chain or a wrong head."""

    store = make_store(tmp_path)
    store.append_event(
        task_id=DEFAULT_TASK_ID,
        source="runtime",
        source_id="execution:e1",
        source_seq=1,
        event_type="execution_started",
        payload={"execution_id": "e1"},
        timestamp=1000,
    )
    head_before = store.chain_head()
    good = {
        "task_id": DEFAULT_TASK_ID,
        "source": "runtime",
        "source_id": "execution:e2",
        "source_seq": 1,
        "event_type": "execution_started",
        "payload": {"execution_id": "e2"},
        "timestamp": 1100,
    }
    conflicting = {
        "task_id": DEFAULT_TASK_ID,
        "source": "runtime",
        "source_id": "execution:e1",  # already ingested with a different record
        "source_seq": 1,
        "event_type": "execution_completed",
        "payload": {"execution_id": "e1"},
        "timestamp": 1200,
    }
    with pytest.raises(StorageError):
        store.append_events([good, conflicting])
    # The whole batch rolled back: no partial row, protected head unchanged.
    assert store.count_events() == 1
    assert store.chain_head() == head_before
    assert store.chain_status().ok is True
    assert store.list_events(event_type="execution_started")[0]["payload"]["execution_id"] == "e1"


def test_reopen_preserves_chain_and_head(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    _append_three(store)
    head_before = store.chain_head()
    count_before = store.count_events()
    store.connection.close()  # simulate an abrupt process end without store.close()

    reopened = EvidenceStore(store.db_path, store.cas.root)
    try:
        assert reopened.chain_head() == head_before
        assert reopened.count_events() == count_before
        status = reopened.chain_status()
        assert status.ok is True
        assert status.records == count_before
        reopened.append_event(
            task_id=DEFAULT_TASK_ID,
            source="manager",
            event_type="task_paused",
            payload={"reason": "synthetic"},
            timestamp=2000,
        )
        assert reopened.count_events() == count_before + 1
        assert reopened.chain_status().ok is True
    finally:
        reopened.close()


def test_store_context_manager_closes_connection(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    with store as active:
        active.append_event(
            task_id=DEFAULT_TASK_ID, source="manager", event_type="x", payload={}
        )
    assert store.connection is None
    with pytest.raises(AttributeError):
        store.connection.execute("SELECT 1")  # type: ignore[union-attr]
