"""Delivery privacy projection tests (Round 2 contract section B / P0-4).

The delivery view must never carry model reasoning, raw passthrough payloads or
Skill bodies. These tests exercise the single projection shared by the Writeup,
the ``events.jsonl`` export and the evidence ZIP, using a synthetic Harness
session log with unique canary strings in every confidential location.

They also prove the raw session log is still preserved in the local CAS (outside
the delivered ZIP) and that the hash chain still verifies, plus the byte-level
determinism of two ZIP rebuilds.
"""

from __future__ import annotations

import json
import zipfile
from pathlib import Path
from typing import Any, Mapping

from ctf_solver.core.config import SolverPaths
from ctf_solver.core.types import Category, TaskRecord, TaskStatus
from ctf_solver.delivery.bundle import EvidenceBundleBuilder
from ctf_solver.delivery.privacy import (
    DELIVERY_EVENT_TYPES,
    UNMATCHED_RESULT_POLICY_TEMPLATE,
    filter_events,
    project_event,
    sanitize_tool_result,
)
from ctf_solver.delivery.writeup import WriteupBuilder
from ctf_solver.evidence.store import EvidenceStore
from tests.support.png import gradient_png
from tests.support.session_events import (
    assistant_message,
    session_header,
    step_start,
    tool_call,
    tool_result,
    turn_end,
    turn_start,
    user_message,
)
from tests.support.zstd_fixtures import build_session_log, frame_bytes
from tests.test_evidence_support import FakeClock, insert_task_row, make_screenshot

TASK_ID = "task-privacy-0001"
WORKER_ID = "worker-privacy-1"
SESSION_ID = "session-privacy-0001"
SOURCE_ID = "session:privacy"
BASE_TIME = 1_700_000_000_000

REASONING_CANARY = "CANARY-REASONING-7f3a9c"
PASSTHROUGH_CANARY = "CANARY-PASSTHROUGH-1b2c3d"
SKILL_BODY_CANARY = "CANARY-SKILL-BODY-4d5e6f"
TURN_RAW_CANARY = "CANARY-TURN-RAW-9a8b7c"
TOOL_EVIDENCE_TEXT = "sha256=deadbeef size=12 retained tool output"

ALL_CANARIES = (
    REASONING_CANARY,
    PASSTHROUGH_CANARY,
    SKILL_BODY_CANARY,
    TURN_RAW_CANARY,
)

#: Types the contract says must be dropped entirely from the delivery view.
DENIED_EVENT_TYPES = (
    "assistant_message",
    "passthrough",
    "job_registered",
    "job_settled",
    "command_run",
    "command_done",
    "session/title",
    "session/title_changed",
    "unknown_delivery_type",
)

IDENTITY_KEYS = {
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


# ---------------------------------------------------------------------------
# Synthetic evidence
# ---------------------------------------------------------------------------


def _event(event_type: str, payload: Mapping[str, Any], seq: int = 1) -> dict[str, Any]:
    return {
        "seq": seq,
        "record_id": f"ev-{event_type.replace('/', '-')}-{seq}",
        "task_id": TASK_ID,
        "worker_id": WORKER_ID,
        "session_id": SESSION_ID,
        "source": "session_log",
        "source_id": SOURCE_ID,
        "source_seq": seq,
        "event_type": event_type,
        "timestamp": BASE_TIME + seq,
        "payload": dict(payload),
    }


def _session_records() -> list[dict[str, Any]]:
    records = [
        session_header(SESSION_ID, created_at=BASE_TIME),
        turn_start(1, BASE_TIME + 10),
        step_start(2, BASE_TIME + 20),
        assistant_message(3, BASE_TIME + 30, text=f"private plan {REASONING_CANARY}"),
        user_message(4, BASE_TIME + 40, text=f"system prompt {PASSTHROUGH_CANARY}"),
        tool_call(5, BASE_TIME + 50, "call-skill", "skill", {"name": "ctf-misc"}),
        tool_result(
            6,
            BASE_TIME + 60,
            "call-skill",
            f"# Category Skill body\n{SKILL_BODY_CANARY}\n",
        ),
        tool_call(
            7,
            BASE_TIME + 70,
            "call-tool",
            "mcp__ctf-exec__ctf_exec",
            {"tool_name": "internal.file_hash", "argv": ["README.md"]},
        ),
        tool_result(8, BASE_TIME + 80, "call-tool", f"{TOOL_EVIDENCE_TEXT}\n"),
        turn_end(9, BASE_TIME + 90),
    ]
    # Extra raw fields in a turn lifecycle record must not survive projection.
    records[1]["data"]["raw_turn_context"] = TURN_RAW_CANARY
    return records


def _make_store(tmp_path: Path) -> tuple[EvidenceStore, SolverPaths, bytes, dict[str, Any]]:
    root = tmp_path / "project"
    paths = SolverPaths.for_root(root)
    paths.ensure()
    store = EvidenceStore.from_root(root, clock=FakeClock())
    insert_task_row(store, TASK_ID)
    data = build_session_log(_session_records(), frames=3)
    report = store.ingest_session_log_bytes(
        task_id=TASK_ID,
        worker_id=WORKER_ID,
        session_id=SESSION_ID,
        data=data,
        source_id=SOURCE_ID,
    )
    png = gradient_png(64, 48)
    ref = store.store_artifact(png, media_type="image/png", source="synthetic")
    store.record_screenshot(
        make_screenshot(
            TASK_ID,
            screenshot_id="shot-privacy",
            sha256=ref.sha256,
            width=64,
            height=48,
            step_id="turn1-step1",
            worker_id=WORKER_ID,
            session_id=SESSION_ID,
            captured_at=BASE_TIME + 100,
        )
    )
    return store, paths, data, report


def _make_task(tmp_path: Path) -> TaskRecord:
    return TaskRecord(
        task_id=TASK_ID,
        conversation_id="conv-privacy",
        title="Synthetic privacy challenge",
        category=Category.MISC,
        workspace_path=str(tmp_path / "project" / "work"),
        source="synthetic-local",
        scope_profile="synthetic-local",
        status=TaskStatus.RUNNING,
        created_at=BASE_TIME,
        updated_at=BASE_TIME + 500,
        started_at=BASE_TIME + 5,
        evidence_head="d" * 64,
        notes="Synthetic challenge description without any canary string.",
    )


def _export_lines(path: Path) -> list[dict[str, Any]]:
    text = path.read_text(encoding="utf-8")
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def _assert_canaries_absent(data: bytes, where: str) -> None:
    for canary in ALL_CANARIES:
        assert canary.encode("utf-8") not in data, f"canary leaked into {where}: {canary}"


# ---------------------------------------------------------------------------
# Unit matrix items 11-14: projection rules
# ---------------------------------------------------------------------------


def test_projection_drops_confidential_types_by_default() -> None:
    for event_type in DENIED_EVENT_TYPES:
        assert event_type not in DELIVERY_EVENT_TYPES
        event = _event(event_type, {"secret": REASONING_CANARY, "data": {"text": REASONING_CANARY}})
        assert project_event(event) is None, event_type
        assert filter_events([event]) == [], event_type


def test_projection_keeps_evidence_types_and_identity_shape() -> None:
    allowed = (
        "tool_call",
        "tool_result",
        "evidence_gap",
        "evidence_ingested",
        "execution_started",
        "execution_completed",
        "execution_failed",
        "execution_denied",
        "task_created",
        "task_started",
        "task_completed",
        "task_failed",
        "task_paused",
        "task_cancelled",
        "task_interrupted",
        "flag_candidate",
        "screenshot_captured",
        "screenshot_failed",
        "lead_session_bound",
        "harness_approval_asked",
        "harness_approval_decided",
        "turn_start",
        "turn_end",
        "step_start",
        "step_end",
    )
    for event_type in allowed:
        assert event_type in DELIVERY_EVENT_TYPES, event_type
        event = _event(event_type, {"tool_name": "internal.file_hash"})
        projected = project_event(event)
        assert projected is not None, event_type
        assert set(projected) == IDENTITY_KEYS
        assert projected["event_type"] == event_type
        assert projected["record_id"] == event["record_id"]
        assert projected["source"] == "session_log"
        # Hash-chain internals never travel with the delivery view.
        assert "record_hash" not in projected
        assert "prev_hash" not in projected
        assert "ingested_at" not in projected


def test_filter_events_preserves_order_and_is_deterministic() -> None:
    events = [
        _event("tool_call", {"call_id": "c1", "tool_name": "pwsh", "arguments": "{}"}, seq=1),
        _event("assistant_message", {"text_preview": REASONING_CANARY}, seq=2),
        _event("turn_start", {"turn": 1, "step": 1, "raw": TURN_RAW_CANARY}, seq=3),
        _event("tool_result", {"call_id": "c1", "content_preview": TOOL_EVIDENCE_TEXT}, seq=4),
    ]
    first = filter_events(events)
    second = filter_events(events)
    assert [item["event_type"] for item in first] == ["tool_call", "turn_start", "tool_result"]
    assert [item["seq"] for item in first] == [1, 3, 4]
    assert first == second
    # The projection returns fresh objects; callers cannot mutate the input.
    first[0]["payload"]["tool_name"] = "mutated"
    assert events[0]["payload"]["tool_name"] == "pwsh"


def test_turn_and_step_payloads_keep_only_numeric_metadata() -> None:
    for event_type in ("turn_start", "turn_end", "step_start", "step_end"):
        projected = project_event(
            _event(
                event_type,
                {"turn": 2, "step": 3, "data": {"reasoning": TURN_RAW_CANARY}, "cwd": "D:/x"},
            )
        )
        assert projected is not None
        assert projected["payload"] == {"turn": 2, "step": 3}
    # Booleans and non-integers are not trusted as numeric metadata.
    for raw_turn, raw_step, expected_turn, expected_step in (
        (True, 2, None, 2),
        ("1", None, None, None),
        (1.5, 4, None, 4),
        (None, None, None, None),
    ):
        projected = project_event(_event("step_start", {"turn": raw_turn, "step": raw_step}))
        assert projected is not None
        assert projected["payload"] == {"turn": expected_turn, "step": expected_step}


def test_skill_result_body_is_replaced_by_policy_notice() -> None:
    call = _event(
        "tool_call",
        {"call_id": "call-skill", "tool_name": "skill", "arguments": json.dumps({"name": "ctf-misc"})},
        seq=1,
    )
    result = _event(
        "tool_result",
        {
            "call_id": "call-skill",
            "tool_name": "skill",
            "content_preview": f"# body\n{SKILL_BODY_CANARY}\n",
            "content_item_types": ["text"],
            "content_sha256": "a" * 64,
            "content_size": 42,
            "is_error": False,
            "exit_code": None,
        },
        seq=2,
    )
    projected = filter_events([call, result])
    assert len(projected) == 2
    payload = projected[1]["payload"]
    assert payload["content_preview"] == (
        "Skill loaded: ctf-misc (content omitted by delivery privacy policy)"
    )
    assert "content_item_types" not in payload
    assert payload["content_sha256"] == "a" * 64
    assert payload["content_size"] == 42
    assert payload["is_error"] is False
    assert "exit_code" in payload
    # Direct sanitizer call without matching context falls back explicitly.
    isolated = sanitize_tool_result(result["payload"], {})
    assert isolated["content_preview"] == (
        "Skill loaded: unknown (content omitted by delivery privacy policy)"
    )
    # A result correlated to a known Skill call is guarded even when its payload
    # lacks the ``tool_name`` field.
    orphan = dict(result["payload"])
    orphan.pop("tool_name")
    guarded = sanitize_tool_result(orphan, {"call-skill": "ctf-misc"})
    assert guarded["content_preview"] == (
        "Skill loaded: ctf-misc (content omitted by delivery privacy policy)"
    )
    assert SKILL_BODY_CANARY not in json.dumps(guarded)
    # Non-Skill tool output is genuine evidence and keeps its real preview.
    other = _event(
        "tool_result",
        {"call_id": "call-tool", "tool_name": "mcp__ctf-exec__ctf_exec", "content_preview": TOOL_EVIDENCE_TEXT},
    )
    assert sanitize_tool_result(other["payload"], {})["content_preview"] == TOOL_EVIDENCE_TEXT


# ---------------------------------------------------------------------------
# Delivery surfaces: export, Writeup, ZIP
# ---------------------------------------------------------------------------


def test_events_export_is_privacy_filtered_by_default(tmp_path: Path) -> None:
    store, _paths, _data, _report = _make_store(tmp_path)
    try:
        out = tmp_path / "exports" / "events.jsonl"
        info = store.export_events_jsonl(task_id=TASK_ID, out_path=out)
        rows = _export_lines(out)
        assert info.entries == len(rows) > 0
        types = [row["event_type"] for row in rows]
        assert "assistant_message" not in types
        assert "passthrough" not in types
        assert "job_registered" not in types
        assert "job_settled" not in types
        assert "command_run" not in types
        assert "command_done" not in types
        assert "tool_call" in types and "tool_result" in types
        assert "turn_start" in types and "step_start" in types
        for row in rows:
            assert set(row) == IDENTITY_KEYS
            if row["event_type"] in {"turn_start", "turn_end", "step_start", "step_end"}:
                assert set(row["payload"]) == {"turn", "step"}
        text = out.read_text(encoding="utf-8")
        for canary in ALL_CANARIES:
            assert canary not in text, canary
        # Skill body is replaced, tool evidence survives.
        skill_results = [
            row
            for row in rows
            if row["event_type"] == "tool_result"
            and row["payload"].get("tool_name") == "skill"
        ]
        assert len(skill_results) == 1
        assert "content omitted by delivery privacy policy" in (
            skill_results[0]["payload"]["content_preview"]
        )
        tool_results = [
            row
            for row in rows
            if row["event_type"] == "tool_result"
            and row["payload"].get("tool_name") != "skill"
        ]
        assert TOOL_EVIDENCE_TEXT in tool_results[0]["payload"]["content_preview"]
        # Two filtered exports of unchanged state are byte-identical.
        again = store.export_events_jsonl(task_id=TASK_ID, out_path=tmp_path / "exports" / "again.jsonl")
        assert again.sha256 == info.sha256
    finally:
        store.close()


def test_raw_export_path_retains_committed_rows_for_internal_use(tmp_path: Path) -> None:
    store, _paths, _data, _report = _make_store(tmp_path)
    try:
        out = tmp_path / "exports" / "events-raw.jsonl"
        info = store.export_events_jsonl(task_id=TASK_ID, out_path=out, privacy_filtered=False)
        text = out.read_text(encoding="utf-8")
        rows = _export_lines(out)
        assert info.entries == len(rows) > 0
        assert "assistant_message" in {row["event_type"] for row in rows}
        assert "passthrough" in {row["event_type"] for row in rows}
        assert all(row["record_hash"] for row in rows)
        for canary in ALL_CANARIES:
            assert canary in text, canary
    finally:
        store.close()


def test_writeup_does_not_render_confidential_canaries(tmp_path: Path) -> None:
    store, _paths, _data, _report = _make_store(tmp_path)
    try:
        task = _make_task(tmp_path)
        out = tmp_path / "writeup.md"
        info = WriteupBuilder(store).build(task, out)
        text = out.read_text(encoding="utf-8")
        assert info["sha256"]
        for canary in ALL_CANARIES:
            assert canary not in text, canary
        # Evidence and the Skill policy notice are rendered instead.
        assert TOOL_EVIDENCE_TEXT in text
        assert "Skill loaded: ctf-misc (content omitted by delivery privacy policy)" in text
        assert "## 4. Chronological steps" in text
    finally:
        store.close()


def test_evidence_zip_excludes_raw_logs_and_confidential_canaries(tmp_path: Path) -> None:
    store, paths, raw_data, report = _make_store(tmp_path)
    try:
        task = _make_task(tmp_path)
        info = EvidenceBundleBuilder(store, paths).build(task)
        zip_path = Path(info.path)
        with zipfile.ZipFile(zip_path) as archive:
            names = sorted(archive.namelist())
            members = {name: archive.read(name) for name in names}
        assert "writeup.md" in names
        assert "events.jsonl" in names
        assert "manifest.sha256" in names
        assert any(name.startswith("screenshots/") for name in names)
        assert not any(name.startswith("raw/") for name in names)
        assert all("jsonl.zstd" not in name for name in names)
        # Every member (text or binary) is free of every canary.
        for name, data in members.items():
            _assert_canaries_absent(data, f"ZIP member {name}")
        # The raw session log itself is not shipped.
        assert raw_data not in members.values()
        # events.jsonl is the filtered export.
        events_text = members["events.jsonl"].decode("utf-8")
        events = [json.loads(line) for line in events_text.splitlines() if line.strip()]
        event_types = {row["event_type"] for row in events}
        assert "assistant_message" not in event_types
        assert "passthrough" not in event_types
        assert "tool_call" in event_types
        # Manifest covers exactly the other members and verifies independently.
        manifest_lines = [
            line.split("  ", 1)[1]
            for line in members["manifest.sha256"].decode("utf-8").splitlines()
            if line.strip()
        ]
        assert sorted(manifest_lines) == sorted(name for name in names if name != "manifest.sha256")
        report_verify = EvidenceBundleBuilder.verify_zip(zip_path, tmp_path / "extract")
        assert report_verify["ok"] is True, report_verify["problems"]
        # The raw log is still preserved in the local CAS, untouched.
        raw_sha = report["raw_sha256"]
        assert store.cas.get_bytes(raw_sha) == raw_data
        artifact = store.get_artifact(raw_sha)
        assert artifact is not None and artifact["size"] == len(raw_data)
        # The ingestion/chain integrity still verifies after building the ZIP.
        assert store.chain_status().ok is True
    finally:
        store.close()


def test_zip_rebuild_is_byte_identical_and_canary_scan_repeats(tmp_path: Path) -> None:
    store, paths, _data, _report = _make_store(tmp_path)
    try:
        task = _make_task(tmp_path)
        builder = EvidenceBundleBuilder(store, paths)
        first = builder.build(task)
        second = builder.build(task)
        assert first.sha256 == second.sha256
        assert Path(first.path).read_bytes() == Path(second.path).read_bytes()
        for build in (first, second):
            with zipfile.ZipFile(build.path) as archive:
                for name in archive.namelist():
                    _assert_canaries_absent(archive.read(name), f"rebuild member {name}")
            verify = EvidenceBundleBuilder.verify_zip(build.path, tmp_path / "verify-rebuild")
            assert verify["ok"] is True, verify["problems"]
        # Standalone Writeup rebuild is deterministic too.
        task_obj = _make_task(tmp_path)
        one = WriteupBuilder(store).render(task_obj)
        two = WriteupBuilder(store).render(task_obj)
        assert one == two
    finally:
        store.close()


# ---------------------------------------------------------------------------
# Final-audit regressions: raw log fragments and unclassifiable tool output
# ---------------------------------------------------------------------------


def test_torn_line_raw_preview_is_not_delivered(tmp_path: Path) -> None:
    """A torn/unparsable line's raw preview must not reach the delivery view.

    The preview can contain assistant reasoning or passthrough text; the raw
    append-only event keeps it locally, but ``filter_events`` / the default
    ``events.jsonl`` export must not ship it.
    """

    canary = "CANARY-TORN-PREVIEW-2f7d1e"
    valid = {
        "type": "turn/start",
        "seq": 1,
        "time": BASE_TIME,
        "data": {"turn": 1, "step": 1},
    }
    torn = (
        '{"type":"assistant/message","seq":2,"time":'
        + str(BASE_TIME + 1)
        + ',"data":{"content":[{"type":"text","text":"'
        + canary
        + " my private reasoning"
    )
    payload = json.dumps(valid, separators=(",", ":")).encode("utf-8") + b"\n" + torn.encode("utf-8")
    data = frame_bytes([payload])
    root = tmp_path / "project"
    paths = SolverPaths.for_root(root)
    paths.ensure()
    store = EvidenceStore.from_root(root, clock=FakeClock())
    try:
        insert_task_row(store, TASK_ID)
        report = store.ingest_session_log_bytes(
            task_id=TASK_ID,
            worker_id=WORKER_ID,
            session_id=SESSION_ID,
            data=data,
            source_id=SOURCE_ID,
        )
        assert report["gap_reasons"].get("torn_line") == 1
        raw_events = store.list_events(task_id=TASK_ID)
        # The append-only evidence DB still stores the raw fragment for audit.
        assert canary in json.dumps(raw_events, ensure_ascii=False)
        projected = filter_events(raw_events)
        gaps = [event for event in projected if event["event_type"] == "evidence_gap"]
        assert gaps
        assert "preview" not in gaps[0]["payload"]
        assert "preview" in gaps[0]["payload"]["omitted_fields"]
        assert canary not in json.dumps(projected, ensure_ascii=False)
        delivered = tmp_path / "delivered-events.jsonl"
        store.export_events_jsonl(task_id=TASK_ID, out_path=delivered)
        assert canary not in delivered.read_text(encoding="utf-8")
        raw_out = tmp_path / "events-raw.jsonl"
        store.export_events_jsonl(task_id=TASK_ID, out_path=raw_out, privacy_filtered=False)
        assert canary in raw_out.read_text(encoding="utf-8")
        assert store.chain_status().ok is True
    finally:
        store.close()


def test_unmatched_tool_result_preview_is_withheld(tmp_path: Path) -> None:
    """An orphaned result cannot be classified, so its preview is withheld.

    A ``tool/result`` without a correlated ``tool/call`` may be a Skill body; the
    delivery view replaces its preview with the unmatched-result policy notice
    while keeping hashes/sizes and the raw CAS/event data local.
    """

    canary = "CANARY-ORPHAN-SKILL-4d5e6f"
    skill_body = "# ctf-solver Skill body\n" + canary + "\n" + ("policy text " * 40)
    records = [
        session_header(SESSION_ID, created_at=BASE_TIME),
        tool_result(2, BASE_TIME + 10, "call-orphan", skill_body),
    ]
    payload = (
        b"\n".join(
            json.dumps(record, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            for record in records
        )
        + b"\n"
    )
    data = frame_bytes([payload])
    root = tmp_path / "project"
    paths = SolverPaths.for_root(root)
    paths.ensure()
    store = EvidenceStore.from_root(root, clock=FakeClock())
    try:
        insert_task_row(store, TASK_ID)
        store.ingest_session_log_bytes(
            task_id=TASK_ID,
            worker_id=WORKER_ID,
            session_id=SESSION_ID,
            data=data,
            source_id=SOURCE_ID,
        )
        raw_events = store.list_events(task_id=TASK_ID)
        assert canary in json.dumps(raw_events, ensure_ascii=False)
        projected = filter_events(raw_events)
        results = [event for event in projected if event["event_type"] == "tool_result"]
        assert results
        result_payload = results[0]["payload"]
        assert result_payload["content_preview"] == UNMATCHED_RESULT_POLICY_TEMPLATE
        assert result_payload.get("content_sha256")
        assert canary not in json.dumps(projected, ensure_ascii=False)
        delivered = tmp_path / "delivered-events.jsonl"
        store.export_events_jsonl(task_id=TASK_ID, out_path=delivered)
        assert canary not in delivered.read_text(encoding="utf-8")
        raw_out = tmp_path / "events-raw.jsonl"
        store.export_events_jsonl(task_id=TASK_ID, out_path=raw_out, privacy_filtered=False)
        assert canary in raw_out.read_text(encoding="utf-8")
        assert store.chain_status().ok is True
    finally:
        store.close()
