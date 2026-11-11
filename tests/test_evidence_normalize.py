"""Deterministic tests for session-record normalization (INTERFACES §4.3/§4.6)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ctf_solver.core.canonical import canonical_bytes, canonical_json
from ctf_solver.evidence.normalize import (
    CONTENT_PREVIEW_CHARS,
    DATA_INLINE_CHARS,
    NormalizedBatch,
    normalize_session_records,
    parse_exit_code,
)
from tests.support.session_events import (
    assistant_message,
    command_done,
    command_run,
    job_registered,
    job_settled,
    records_without,
    session_header,
    tool_call,
    tool_result,
    turn_end,
    turn_start,
)
from tests.test_evidence_support import BASE_MS, make_cas

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


def _normalize(records, cas=None, tmp_path=None, **overrides):
    if cas is None:
        cas = make_cas(tmp_path)
    kwargs = {
        "task_id": "task-1",
        "worker_id": "worker-1",
        "session_id": "session-1",
        "raw_records": records,
        "cas": cas,
        "source_id": "session-log-1",
    }
    kwargs.update(overrides)
    return normalize_session_records(**kwargs)


def _records_by_type(events, event_type: str) -> list[dict]:
    return [event for event in events if event["event_type"] == event_type]


def _standard_records():
    from tests.support.session_events import standard_session

    return standard_session()


def test_event_contract_fields_and_frozen_type_names(tmp_path: Path) -> None:
    batch = _normalize(_standard_records(), tmp_path=tmp_path)
    assert isinstance(batch, NormalizedBatch)
    assert batch.events
    seen_ids: set[str] = set()
    for event in batch.events:
        assert set(event) == {
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
        assert event["source"] == "session_log"
        assert event["task_id"] == "task-1"
        assert event["worker_id"] == "worker-1"
        assert event["session_id"] == "session-1"
        assert event["source_id"] == "session-log-1"
        assert event["record_id"].startswith("ev-")
        assert len(event["record_id"]) == len("ev-") + 24
        assert event["event_type"] in FROZEN_SESSION_LOG_TYPES
        assert isinstance(event["payload"], dict)
        assert event["record_id"] not in seen_ids
        seen_ids.add(event["record_id"])
    stats = batch.stats
    assert stats["records"] == len(_standard_records())
    assert stats["events"] == len(batch.events)
    assert stats["gap_events"] == 0
    assert stats["correlated_pairs"] >= 1


def test_tool_call_result_correlation_and_cas_content(tmp_path: Path) -> None:
    cas = make_cas(tmp_path)
    batch = _normalize(_standard_records(), cas=cas)
    calls = _records_by_type(batch.events, "tool_call")
    results = _records_by_type(batch.events, "tool_result")
    assert len(calls) == 1 and len(results) == 1
    call, result = calls[0], results[0]
    assert call["payload"]["call_id"] == "call-0001"
    assert call["payload"]["tool_name"] == "mcp__ctf-exec__ctf_exec"
    assert json.loads(call["payload"]["arguments"])["tool_name"] == "internal.file_hash"
    assert call["payload"]["turn"] == 1
    assert call["payload"]["step"] == 1
    payload = result["payload"]
    assert payload["call_id"] == "call-0001"
    assert payload["call_matched"] is True
    assert payload["tool_name"] == "mcp__ctf-exec__ctf_exec"
    assert payload["is_error"] is False
    assert payload["cwd"] == "D:/synthetic/tasks/t-demo/work"
    assert payload["turn"] == 1 and payload["step"] == 1
    assert payload["exit_code"] is None
    content = b"sha256=deadbeef size=12\n"
    assert payload["content_size"] == len(content)
    assert payload["content_sha256"] == __import__("hashlib").sha256(content).hexdigest()
    assert cas.get_bytes(payload["content_sha256"]) == content
    assert payload["content_preview"] == content.decode("utf-8")[:CONTENT_PREVIEW_CHARS]
    assert batch.stats["correlated_pairs"] == 1


def test_exit_code_parsed_from_tool_result_and_job_detail(tmp_path: Path) -> None:
    records = [
        session_header("session-x", created_at=BASE_MS),
        tool_call(1, BASE_MS + 1, "call-9", "ctf_exec", {"tool_name": "internal.text_search"}),
        tool_result(2, BASE_MS + 2, "call-9", "boom\nexit code: 7\n", is_error=True),
        job_settled(3, BASE_MS + 3, "job-9", "call-9", detail="killed\nexit code: 2"),
    ]
    batch = _normalize(records, tmp_path=tmp_path)
    result = _records_by_type(batch.events, "tool_result")[0]
    assert result["payload"]["exit_code"] == 7
    assert result["payload"]["is_error"] is True
    settled = _records_by_type(batch.events, "job_settled")[0]
    assert settled["payload"]["exit_code"] == 2
    assert parse_exit_code("no code here") is None
    assert parse_exit_code("EXIT CODE: 3") == 3


def test_content_preview_is_bounded_and_full_bytes_in_cas(tmp_path: Path) -> None:
    cas = make_cas(tmp_path)
    long_text = "A" * 10_000
    records = [
        session_header("session-x", created_at=BASE_MS),
        tool_call(1, BASE_MS + 1, "call-long", "ctf_exec", {}),
        tool_result(2, BASE_MS + 2, "call-long", long_text),
    ]
    batch = _normalize(records, cas=cas)
    payload = _records_by_type(batch.events, "tool_result")[0]["payload"]
    assert len(payload["content_preview"]) == CONTENT_PREVIEW_CHARS
    assert payload["content_preview_truncated"] is True
    assert payload["content_size"] == 10_000
    assert cas.get_bytes(payload["content_sha256"]) == long_text.encode("utf-8")


def test_unmatched_result_becomes_evidence_gap(tmp_path: Path) -> None:
    records = records_without(_standard_records(), "tool/call")
    batch = _normalize(records, tmp_path=tmp_path)
    reasons = [gap["reason"] for gap in batch.gaps]
    assert "unmatched_result" in reasons
    gap = next(gap for gap in batch.gaps if gap["reason"] == "unmatched_result")
    assert gap["call_id"] == "call-0001"
    gap_events = _records_by_type(batch.events, "evidence_gap")
    unmatched_events = [
        event for event in gap_events if event["payload"]["reason"] == "unmatched_result"
    ]
    assert len(unmatched_events) == 1
    assert unmatched_events[0]["source_seq"] is None
    # Removing the call record also leaves a sequence hole: reported explicitly.
    assert any(event["payload"]["reason"] == "sequence_gap" for event in gap_events)
    # The result record itself is preserved even when its call is missing.
    assert len(_records_by_type(batch.events, "tool_result")) == 1
    assert _records_by_type(batch.events, "tool_result")[0]["payload"]["call_matched"] is False


def test_unmatched_call_becomes_evidence_gap(tmp_path: Path) -> None:
    from tests.support.session_events import standard_session

    records = standard_session(include_unmatched_call=True)
    batch = _normalize(records, tmp_path=tmp_path)
    gap = next(gap for gap in batch.gaps if gap["reason"] == "unmatched_call")
    assert gap["call_id"] == "call-orphan"
    assert gap["tool_name"] == "write_file"
    gap_event = _records_by_type(batch.events, "evidence_gap")[0]
    assert gap_event["payload"]["reason"] == "unmatched_call"


def test_sequence_gap_reports_missing_range(tmp_path: Path) -> None:
    from tests.support.session_events import standard_session

    records = standard_session(include_gap=True)
    batch = _normalize(records, tmp_path=tmp_path)
    gap = next(gap for gap in batch.gaps if gap["reason"] == "sequence_gap")
    assert gap["missing_from"] == 10
    assert gap["missing_to"] == 11
    assert "10..11" in gap["detail"]
    gap_event = next(
        event
        for event in batch.events
        if event["event_type"] == "evidence_gap"
        and event["payload"]["reason"] == "sequence_gap"
    )
    assert gap_event["source_seq"] is None


def test_duplicate_sequence_is_reported_and_record_preserved(tmp_path: Path) -> None:
    records = [
        session_header("session-x", created_at=BASE_MS),
        turn_start(1, BASE_MS + 1),
        turn_start(1, BASE_MS + 2),
    ]
    batch = _normalize(records, tmp_path=tmp_path)
    gap = next(gap for gap in batch.gaps if gap["reason"] == "sequence_gap")
    assert gap["duplicate_seq"] == 1
    turn_events = _records_by_type(batch.events, "turn_start")
    assert len(turn_events) == 2
    assert turn_events[0]["source_seq"] == 1
    assert turn_events[1]["source_seq"] is None  # cannot reuse the unique seq slot
    assert turn_events[0]["record_id"] != turn_events[1]["record_id"]


def test_job_and_harness_approval_state_preserved(tmp_path: Path) -> None:
    from tests.support.session_events import standard_session

    records = standard_session(include_approval=True)
    batch = _normalize(records, tmp_path=tmp_path)
    asked = _records_by_type(batch.events, "harness_approval_asked")[0]["payload"]
    assert asked["approval_id"] == "apr-1"
    assert asked["call_id"] == "call-0001"
    assert asked["tool_name"] == "mcp__ctf-exec__ctf_exec"
    assert asked["reason"] == "synthetic approval"
    decided = _records_by_type(batch.events, "harness_approval_decided")[0]["payload"]
    assert decided["approval_id"] == "apr-1"
    assert decided["outcome"] == "approved"
    registered = _records_by_type(batch.events, "job_registered")[0]["payload"]
    assert registered["job_id"] == "job-1"
    assert registered["tool_call_id"] == "call-0001"
    assert registered["kind"] == "shell"
    assert registered["label"] == "synthetic-job"
    settled = _records_by_type(batch.events, "job_settled")[0]["payload"]
    assert settled["job_id"] == "job-1"
    assert settled["tool_call_id"] == "call-0001"
    assert settled["status"] == "completed"
    assert settled["cause"] == "exit"
    assert settled["detail"] == "exit code: 0"


def test_turn_step_and_command_events_preserved(tmp_path: Path) -> None:
    records = [
        session_header("session-x", created_at=BASE_MS),
        turn_start(1, BASE_MS + 1, turn=1),
        command_run(2, BASE_MS + 2, "synthetic-command"),
        command_done(3, BASE_MS + 3, "synthetic-command", 4),
        turn_end(4, BASE_MS + 4, turn=1),
    ]
    batch = _normalize(records, tmp_path=tmp_path)
    turn_start_event = _records_by_type(batch.events, "turn_start")[0]["payload"]
    assert turn_start_event["data"] == {"turn": 1}
    assert turn_start_event["turn"] == 1
    assert _records_by_type(batch.events, "turn_end")[0]["payload"]["data"] == {"turn": 1}
    run_payload = _records_by_type(batch.events, "command_run")[0]["payload"]
    assert run_payload["command"] == "synthetic-command"
    done_payload = _records_by_type(batch.events, "command_done")[0]["payload"]
    assert done_payload["command"] == "synthetic-command"
    assert done_payload["exit_code"] == 4


def test_unknown_event_type_is_passthrough_with_full_data(tmp_path: Path) -> None:
    records = [
        session_header("session-x", created_at=BASE_MS),
        {
            "type": "harness/weird",
            "seq": 1,
            "time": BASE_MS + 1,
            "data": {"x": 1, "nested": {"y": [1, 2, 3]}},
        },
    ]
    batch = _normalize(records, tmp_path=tmp_path)
    passthrough = [
        event
        for event in _records_by_type(batch.events, "passthrough")
        if event["payload"].get("source_type") == "harness/weird"
    ]
    assert len(passthrough) == 1
    assert passthrough[0]["payload"]["data"] == {"x": 1, "nested": {"y": [1, 2, 3]}}


def test_session_header_and_delivery_event_passthrough(tmp_path: Path) -> None:
    from tests.support.session_events import delivery_accepted

    records = [session_header("session-x", created_at=BASE_MS), delivery_accepted(1, BASE_MS + 1)]
    batch = _normalize(records, tmp_path=tmp_path)
    passthroughs = _records_by_type(batch.events, "passthrough")
    assert passthroughs[0]["payload"]["source_type"] == "session"
    assert passthroughs[0]["payload"]["data"]["id"] == "session-x"
    delivery = [
        event for event in passthroughs if event["payload"]["source_type"].startswith("session-log")
    ]
    assert delivery[0]["payload"]["data"]["watermark"] == 0


def test_large_passthrough_data_bounded_and_preserved_in_cas(tmp_path: Path) -> None:
    cas = make_cas(tmp_path)
    big_text = "B" * 50_000
    records = [session_header("session-x", created_at=BASE_MS), assistant_message(1, BASE_MS + 1, big_text)]
    batch = _normalize(records, cas=cas)
    event = _records_by_type(batch.events, "assistant_message")[0]
    payload = event["payload"]
    assert len(canonical_bytes(payload["data"])) <= DATA_INLINE_CHARS + 4_096
    assert payload["data_bounded"] is True
    assert len(payload["data"]["content"][0]["text"]) == 4_096
    full_data = records[1]["data"]
    assert payload["data_size"] == len(canonical_bytes(full_data))
    assert payload["data_sha256"] == __import__("hashlib").sha256(canonical_bytes(full_data)).hexdigest()
    assert cas.get_bytes(payload["data_sha256"]) == canonical_bytes(full_data)
    assert len(event["payload"]["text_preview"]) == CONTENT_PREVIEW_CHARS


def test_deterministic_record_ids_and_timestamps(tmp_path: Path) -> None:
    records = _standard_records()
    first = _normalize(records, tmp_path=tmp_path / "a")
    second = _normalize(records, tmp_path=tmp_path / "b")
    assert [event["record_id"] for event in first.events] == [
        event["record_id"] for event in second.events
    ]
    assert canonical_json(first.events) == canonical_json(second.events)
    raw_times = [record["time"] for record in records]
    record_events = [event for event in first.events if event["event_type"] != "evidence_gap"]
    assert [event["timestamp"] for event in record_events] == raw_times
    assert [event["source_seq"] for event in record_events] == [
        record["seq"] for record in records
    ]


def test_invalid_raw_record_is_preserved_not_dropped(tmp_path: Path) -> None:
    batch = _normalize([session_header("session-x", created_at=BASE_MS), "not-a-record"], tmp_path=tmp_path)
    passthrough = [
        event
        for event in _records_by_type(batch.events, "passthrough")
        if event["payload"].get("source_type") == "invalid_record"
    ]
    assert len(passthrough) == 1
    assert passthrough[0]["payload"]["data"] == "not-a-record"


def test_requires_task_id_and_cas(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        normalize_session_records(
            task_id="",
            worker_id=None,
            session_id=None,
            raw_records=[],
            cas=make_cas(tmp_path),
        )
    with pytest.raises(ValueError):
        normalize_session_records(
            task_id="task-1",
            worker_id=None,
            session_id=None,
            raw_records=[],
            cas=None,
        )
