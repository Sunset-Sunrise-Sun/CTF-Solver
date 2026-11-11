"""Deterministic tests for idempotent session-log ingestion (INTERFACES 搂4.5)."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from ctf_solver.core.errors import NotFoundError, ValidationError
from ctf_solver.evidence.ingest import Ingestor
from ctf_solver.evidence.store import EvidenceStore
from ctf_solver.evidence.zstd_frames import scan_frames
from tests.support.zstd_fixtures import (
    build_log_from_chunks,
    build_session_log,
    corrupt_frame,
    jsonl_bytes,
    truncate_last_frame,
)
from tests.test_evidence_support import (
    DEFAULT_SESSION_ID,
    DEFAULT_SOURCE_ID,
    DEFAULT_TASK_ID,
    DEFAULT_WORKER_ID,
    ingest_bytes,
    make_store,
)

FROZEN_SESSION_LOG_TYPES = {
    "tool_call",
    "tool_result",
    "job_registered",
    "job_settled",
    "harness_approval_asked",
    "harness_approval_decided",
    "command_run",
    "command_done",
    "turn_start",
    "turn_end",
    "step_start",
    "step_end",
    "assistant_message",
    "passthrough",
    "evidence_gap",
}


def _standard_records(**kwargs):
    from tests.support.session_events import standard_session

    return standard_session(**kwargs)


def _gap_events(store: EvidenceStore, task_id: str = DEFAULT_TASK_ID) -> list[dict]:
    return store.list_events(task_id=task_id, event_type="evidence_gap")


def _event_rows(store: EvidenceStore, task_id: str = DEFAULT_TASK_ID) -> list[dict]:
    return store.list_events(task_id=task_id)


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_ingest_standard_log_reports_and_retains_raw(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    records = _standard_records(include_approval=True)
    data = build_session_log(records, frames=4)
    report = ingest_bytes(store, data)

    assert report.frames == 4
    assert report.decoded_records == len(records)
    assert report.events_total == report.appended + report.skipped_duplicates
    assert report.skipped_duplicates == 0
    assert report.gaps == []
    assert report.gap_count == 0
    assert report.complete is True
    assert report.raw_sha256 == hashlib.sha256(data).hexdigest()
    assert report.task_id == DEFAULT_TASK_ID
    assert report.source_id == DEFAULT_SOURCE_ID
    assert report.last_seq == max(record["seq"] for record in records)
    assert report.backend in ("zstandard", "stdlib")

    # Raw log bytes are retained in CAS, even though the log decodes cleanly.
    assert store.cas.get_bytes(report.raw_sha256) == data
    raw_artifact = store.get_artifact(report.raw_sha256)
    assert raw_artifact is not None
    assert raw_artifact["media_type"] == "application/zstd"
    assert raw_artifact["size"] == len(data)

    # Every stored event is one of the frozen canonical types.
    stored = _event_rows(store)
    assert len(stored) == report.appended
    assert {event["event_type"] for event in stored} <= FROZEN_SESSION_LOG_TYPES
    assert {event["source"] for event in stored} == {"session_log"}
    assert all(event["source_id"] == DEFAULT_SOURCE_ID for event in stored)

    # The hash chain is clean after ingestion.
    status = store.chain_status()
    assert status.ok is True
    assert status.records == report.appended

    # The ingestion watermark is truthful.
    state = store.ingest_state(DEFAULT_SOURCE_ID)
    assert state is not None
    assert state["task_id"] == DEFAULT_TASK_ID
    assert state["last_seq"] == report.last_seq
    assert state["frames"] == report.frames
    assert state["records"] == report.decoded_records
    assert state["gaps"] == report.gap_count
    assert state["raw_sha256"] == report.raw_sha256

    # Tool-result content bytes are in CAS and referenced by the event.
    results = [event for event in stored if event["event_type"] == "tool_result"]
    assert len(results) == 1
    payload = results[0]["payload"]
    assert store.cas.get_bytes(payload["content_sha256"]) == b"sha256=deadbeef size=12\n"
    assert payload["call_matched"] is True


def test_double_ingestion_is_idempotent(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    records = _standard_records(include_approval=True)
    data = build_session_log(records, frames=4)
    first = ingest_bytes(store, data)
    head_after_first = store.chain_head()
    count_after_first = store.count_events()

    second = ingest_bytes(store, data)
    assert second.appended == 0
    assert second.skipped_duplicates == first.events_total
    assert second.gap_count == first.gap_count
    assert second.raw_sha256 == first.raw_sha256
    assert store.count_events() == count_after_first
    assert store.chain_head() == head_after_first
    assert store.chain_status().ok is True
    # The watermark is not reset or re-estimated.
    assert store.ingest_state(DEFAULT_SOURCE_ID)["last_seq"] == first.last_seq


def test_longer_log_incremental_ingestion_appends_only_new_records(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    records = _standard_records()
    tool_result_index = next(
        index for index, record in enumerate(records) if record["type"] == "tool/result"
    )
    prefix = records[: tool_result_index + 1]
    prefix_data = build_session_log(prefix, frames=3)
    full_data = build_session_log(records, frames=5)

    first = ingest_bytes(store, prefix_data, source_id="session-log-inc")
    assert first.appended == first.events_total == len(prefix)
    count_after_first = store.count_events()

    second = ingest_bytes(store, full_data, source_id="session-log-inc")
    assert second.events_total == len(records)
    assert second.skipped_duplicates == len(prefix)  # exactly the already-known records
    assert second.appended == len(records) - len(prefix)
    assert store.count_events() == count_after_first + second.appended
    assert store.count_events() == len(records)

    # No source sequence number was stored twice.
    duplicates = store.connection.execute(
        "SELECT source_id, source_seq, COUNT(*) AS c FROM events "
        "WHERE source_seq IS NOT NULL GROUP BY source_id, source_seq HAVING c > 1"
    ).fetchall()
    assert duplicates == []
    assert store.chain_status().ok is True

    state = store.ingest_state("session-log-inc")
    assert state is not None
    assert state["last_seq"] == max(record["seq"] for record in records)
    assert state["records"] == len(records)
    assert state["frames"] == second.frames


# ---------------------------------------------------------------------------
# Damaged logs
# ---------------------------------------------------------------------------


def test_truncated_last_frame_records_explicit_gap(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    records = _standard_records()
    data = truncate_last_frame(build_session_log(records, frames=4), drop=8)
    report = ingest_bytes(store, data)
    assert report.complete is False
    assert report.gap_count >= 1
    assert report.gap_reasons.get("truncated_frame") == 1
    assert store.cas.get_bytes(report.raw_sha256) == data  # damaged raw log kept too
    gap_events = _gap_events(store)
    truncated = next(
        event for event in gap_events if event["payload"]["reason"] == "truncated_frame"
    )
    assert "detail" in truncated["payload"]
    assert truncated["source_seq"] is None
    assert all(event["source_seq"] is None for event in gap_events)
    # The lost tail is never invented.
    assert report.decoded_records <= len(records)
    assert store.chain_status().ok is True


def test_corrupt_frame_records_explicit_gap(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    records = _standard_records()
    data = build_session_log(records, frames=4)
    spans = scan_frames(data)
    corrupted = corrupt_frame(data, spans[1].offset)
    report = ingest_bytes(store, corrupted)
    assert report.complete is False
    assert report.gap_count >= 1
    assert report.gap_reasons.get("frame_decode_error") == 1
    gap_payload = _gap_events(store)[0]["payload"]
    assert gap_payload["reason"] == "frame_decode_error"
    assert gap_payload["decode_reason"] == "unscanned_bytes"
    assert 0 < report.decoded_records < len(records)
    assert store.chain_status().ok is True


def test_torn_json_line_records_explicit_gap(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    line_one = b'{"type":"turn/start","seq":1,"time":1000,"data":{"turn":1}}\n'
    torn_line = b'{"type":"turn/en\n'
    line_two = b'{"type":"turn/end","seq":2,"time":1001,"data":{"turn":1}}\n'
    raw = line_one + torn_line + line_two
    data = build_log_from_chunks([raw[:30], raw[30:70], raw[70:]])
    report = ingest_bytes(store, data)
    assert report.complete is False
    assert report.gap_count == 1
    assert report.decoded_records == 2
    gap_payload = _gap_events(store)[0]["payload"]
    assert gap_payload["reason"] == "torn_line"
    assert gap_payload["line_reason"] == "torn_line"
    assert gap_payload["preview"].startswith('{"type":"turn/en')
    events = _event_rows(store)
    assert [event["event_type"] for event in events] == [
        "evidence_gap",
        "turn_start",
        "turn_end",
    ]
    assert store.chain_status().ok is True


# ---------------------------------------------------------------------------
# Semantic gaps
# ---------------------------------------------------------------------------


def test_unmatched_pairs_and_sequence_gap_become_gap_events(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    records = _standard_records(
        include_unmatched_call=True, include_unmatched_result=True, include_gap=True
    )
    data = build_session_log(records, frames=4)
    report = ingest_bytes(store, data)
    # Structurally complete: every frame and line decoded.
    assert report.complete is True
    assert report.gap_count == 3
    assert set(report.gap_reasons) == {"unmatched_call", "unmatched_result", "sequence_gap"}

    gap_events = _gap_events(store)
    assert len(gap_events) == 3
    reasons = {event["payload"]["reason"] for event in gap_events}
    assert reasons == {"unmatched_call", "unmatched_result", "sequence_gap"}
    sequence_gap = next(
        event for event in gap_events if event["payload"]["reason"] == "sequence_gap"
    )
    assert sequence_gap["payload"]["missing_from"] == 12
    assert sequence_gap["payload"]["missing_to"] == 13
    unmatched_result = next(
        event for event in gap_events if event["payload"]["reason"] == "unmatched_result"
    )
    assert unmatched_result["payload"]["call_id"] == "call-missing"
    unmatched_call = next(
        event for event in gap_events if event["payload"]["reason"] == "unmatched_call"
    )
    assert unmatched_call["payload"]["call_id"] == "call-orphan"
    # The raw records around the gaps are still preserved.
    assert report.decoded_records == len(records)
    assert store.chain_status().ok is True


# ---------------------------------------------------------------------------
# File + store delegates
# ---------------------------------------------------------------------------


def test_ingest_file_variant_and_store_delegate(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    records = _standard_records()
    data = build_session_log(records, frames=3)
    log_path = tmp_path / "session.v4.jsonl.zstd"
    log_path.write_bytes(data)

    report_dict = store.ingest_session_log_file(
        task_id=DEFAULT_TASK_ID,
        worker_id=DEFAULT_WORKER_ID,
        session_id=DEFAULT_SESSION_ID,
        path=log_path,
    )
    assert isinstance(report_dict, dict)
    for key in (
        "frames",
        "decoded_records",
        "appended",
        "skipped_duplicates",
        "gaps",
        "raw_sha256",
        "complete",
        "source_id",
        "last_seq",
    ):
        assert key in report_dict
    assert report_dict["source_id"] == f"session:{DEFAULT_SESSION_ID}"
    assert report_dict["complete"] is True
    assert report_dict["raw_path"] == str(log_path)
    state = store.ingest_state(f"session:{DEFAULT_SESSION_ID}")
    assert state is not None and state["raw_sha256"] == report_dict["raw_sha256"]

    # Explicit source_id through the Ingestor file variant.
    ingestor = Ingestor(store, store.cas)
    second = ingestor.ingest_session_log_file(
        task_id="task-2",
        worker_id="worker-2",
        session_id="session-2",
        path=log_path,
        source_id="session-log-explicit",
    )
    assert second.source_id == "session-log-explicit"
    assert second.appended == second.events_total

    # Byte variant delegate returns a serializable report too.
    third = store.ingest_session_log_bytes(
        task_id="task-3",
        worker_id="worker-3",
        session_id="session-3",
        data=data,
        source_id="session-log-bytes",
    )
    assert isinstance(third, dict)
    assert third["appended"] == third["events_total"]


def test_ingest_missing_file_raises_not_found(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    ingestor = Ingestor(store, store.cas)
    with pytest.raises(NotFoundError):
        ingestor.ingest_session_log_file(
            task_id=DEFAULT_TASK_ID,
            worker_id=DEFAULT_WORKER_ID,
            session_id=DEFAULT_SESSION_ID,
            path=tmp_path / "missing.v4.jsonl.zstd",
        )


def test_ingest_invalid_arguments_rejected(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    ingestor = Ingestor(store, store.cas)
    with pytest.raises(ValidationError):
        ingestor.ingest_session_log_bytes(
            task_id="",
            worker_id=None,
            session_id=None,
            data=b"",
            source_id="s",
        )
    with pytest.raises(ValidationError):
        ingestor.ingest_session_log_bytes(
            task_id=DEFAULT_TASK_ID,
            worker_id=None,
            session_id=None,
            data="not-bytes",  # type: ignore[arg-type]
            source_id="s",
        )
    with pytest.raises(ValidationError):
        ingestor.ingest_session_log_bytes(
            task_id=DEFAULT_TASK_ID,
            worker_id=None,
            session_id=None,
            data=b"",
            source_id="",
        )
