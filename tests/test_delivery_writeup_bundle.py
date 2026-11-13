"""Tests for deterministic Markdown Writeup and evidence ZIP generation."""

from __future__ import annotations

import dataclasses
import json
import tempfile
import zipfile
from pathlib import Path

import pytest

from ctf_solver.core.canonical import file_sha256, sha256_hex
from ctf_solver.core.config import SolverPaths
from ctf_solver.core.errors import DeliveryError
from ctf_solver.core.types import (
    CaptureStatus,
    Category,
    ExportInfo,
    FlagState,
    ScreenshotRecord,
    TaskRecord,
    TaskStatus,
)
from ctf_solver.delivery import bundle as bundle_module
from ctf_solver.delivery.bundle import EvidenceBundleBuilder, verify_manifest
from ctf_solver.delivery.privacy import filter_events
from ctf_solver.delivery.writeup import WriteupBuilder
from tests.support.png import gradient_png


class FakeEvidence:
    def __init__(self) -> None:
        self.events: list[dict] = []
        self.screenshots: list[ScreenshotRecord] = []
        self.artifacts: dict[str, bytes] = {}
        self.exports: list[ExportInfo] = []
        self.sources: list[dict] = []

    def list_events(self, *, task_id=None, after_seq=None, limit=None, event_type=None):
        items = self.events
        if task_id is not None:
            items = [event for event in items if event.get("task_id") == task_id]
        if after_seq is not None:
            items = [event for event in items if int(event.get("seq", 0)) > after_seq]
        if event_type is not None:
            items = [event for event in items if event.get("event_type") == event_type]
        if limit is not None:
            items = items[:limit]
        return [dict(item) for item in items]

    def list_screenshots(self, task_id: str):
        return [shot for shot in self.screenshots if shot.task_id == task_id]

    def read_artifact(self, sha256: str) -> bytes:
        return self.artifacts[sha256]

    def export_events_jsonl(self, *, task_id: str, out_path):
        # Mirror the real store default: the delivered export is the shared
        # privacy-projected view, never the raw event rows.
        events = filter_events(
            [dict(event) for event in self.events if event.get("task_id") == task_id]
        )
        lines = [
            json.dumps(event, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            for event in sorted(events, key=lambda item: item.get("seq") or 0)
        ]
        text = "\n".join(lines) + "\n"
        Path(out_path).parent.mkdir(parents=True, exist_ok=True)
        Path(out_path).write_text(text, encoding="utf-8", newline="\n")
        payload = text.encode("utf-8")
        return ExportInfo(
            kind="events_jsonl",
            path=str(out_path),
            sha256=sha256_hex(payload),
            size=len(payload),
            entries=len(lines),
        )

    def record_export(self, info: ExportInfo) -> None:
        self.exports.append(info)

    def ingestion_sources(self, task_id: str):
        return list(self.sources)


def _event(
    seq: int, event_type: str, payload: dict, timestamp: int | None = None, *, source_seq: int = 1
) -> dict:
    return {
        "seq": seq,
        "record_id": f"ev-{seq:04d}",
        "task_id": "t-writeup0001",
        "worker_id": "w-1",
        "session_id": "session-1",
        "source": "runtime",
        "source_id": f"execution:exec-{seq}",
        "source_seq": source_seq,
        "event_type": event_type,
        "timestamp": 1_700_000_000_000 + seq,
        "payload": payload,
    }


def _task(tmp_path: Path, *, completion_note: str = "") -> TaskRecord:
    fields = {
        "task_id": "t-writeup0001",
        "conversation_id": "conv-1",
        "title": "Synthetic Misc Challenge",
        "category": Category.MISC,
        "workspace_path": str(tmp_path / "tasks" / "t-writeup0001" / "work"),
        "source": "synthetic-local",
        "scope_profile": "synthetic-local",
        "status": TaskStatus.RUNNING,
        "created_at": 1_700_000_000_000,
        "updated_at": 1_700_000_000_500,
        "started_at": 1_700_000_000_100,
        "evidence_head": "b" * 64,
        "flag_state": FlagState.CANDIDATE,
        "notes": "Synthetic challenge description for the Writeup test.",
    }
    has_field = "completion_note" in {field.name for field in dataclasses.fields(TaskRecord)}
    if has_field:
        fields["completion_note"] = completion_note
    task = TaskRecord(**fields)
    if completion_note and not has_field:
        # TaskRecord.completion_note lands with the core-binding change; the
        # Writeup reads it through getattr, so tests can exercise both states.
        task.completion_note = completion_note  # type: ignore[attr-defined]
    return task


def _evidence(tmp_path: Path) -> FakeEvidence:
    evidence = FakeEvidence()
    stdout = b"sha256=deadbeef size=12\n"
    stderr = b""
    shot_png = gradient_png()
    evidence.artifacts[sha256_hex(stdout)] = stdout
    evidence.artifacts[sha256_hex(shot_png)] = shot_png
    t = 1_700_000_000_000
    evidence.events = [
        _event(1, "task_created", {"title": "Synthetic Misc Challenge", "category": "misc", "conversation_id": "conv-1"}, t),
        _event(
            2,
            "execution_started",
            {
                "execution_id": "exec-1",
                "step_id": "step-1",
                "tool_name": "internal.file_hash",
                "tool_version": "1.0",
                "argv": ["challenge.txt"],
                "cwd": str(tmp_path / "tasks" / "t-writeup0001" / "work"),
                "tier": 0,
            },
            t + 10,
        ),
        _event(
            3,
            "execution_completed",
            {
                "execution_id": "exec-1",
                "status": "completed",
                "exit_code": 0,
                "stdout_sha256": sha256_hex(stdout),
                "stderr_sha256": sha256_hex(stderr),
                "stdout_preview": stdout.decode(),
                "stderr_preview": "",
            },
            t + 20,
        ),
        _event(
            4,
            "execution_started",
            {
                "execution_id": "exec-2",
                "step_id": "step-2",
                "tool_name": "tool.python_version",
                "tool_version": "Python 3.14.7",
                "argv": ["--version"],
                "cwd": str(tmp_path / "tasks" / "t-writeup0001" / "work"),
                "tier": 1,
            },
            t + 30,
        ),
        _event(
            5,
            "execution_failed",
            {
                "execution_id": "exec-2",
                "status": "failed",
                "exit_code": 2,
                "reason_code": "process_exit",
                "stdout_preview": "",
                "stderr_preview": "synthetic failure",
            },
            t + 40,
        ),
        _event(
            6,
            "execution_denied",
            {
                "execution_id": "exec-3",
                "tool_name": "tool.remote_probe",
                "status": "denied",
                "reason_code": "grant_missing",
            },
            t + 50,
        ),
        _event(
            7,
            "tool_call",
            {
                "call_id": "call-1",
                "tool_name": "mcp__ctf-exec__ctf_exec",
                "arguments": {"tool_name": "internal.file_hash"},
                "turn": 2,
                "step": 5,
            },
            t + 60,
        ),
        _event(
            8,
            "tool_result",
            {
                "call_id": "call-1",
                "is_error": False,
                "content_preview": "sha256=deadbeef",
                "content_sha256": sha256_hex(stdout),
                "content_size": len(stdout),
                "exit_code": 0,
            },
            t + 70,
        ),
        _event(
            9,
            "evidence_gap",
            {"reason": "unmatched_result", "detail": "result for call-missing"},
            t + 80,
        ),
    ]
    evidence.screenshots = [
        ScreenshotRecord(
            screenshot_id="shot-ok",
            task_id="t-writeup0001",
            worker_id="w-1",
            step_id="step-2",
            session_id="session-1",
            scope="desktop",
            captured_at=t + 45,
            status=CaptureStatus.OK,
            sha256=sha256_hex(shot_png),
            width=64,
            height=48,
        ),
        ScreenshotRecord(
            screenshot_id="shot-blank",
            task_id="t-writeup0001",
            worker_id="w-1",
            step_id="step-1",
            session_id="session-1",
            scope="desktop",
            captured_at=t + 25,
            status=CaptureStatus.BLANK,
            failure_reason="blank capture (stddev below threshold)",
        ),
        ScreenshotRecord(
            screenshot_id="shot-derived",
            task_id="t-writeup0001",
            worker_id=None,
            step_id="turn2-step5",
            session_id="session-1",
            scope="desktop",
            captured_at=t + 65,
            status=CaptureStatus.OK,
            sha256=sha256_hex(shot_png),
            width=64,
            height=48,
        ),
    ]
    return evidence


def test_writeup_contains_required_sections_and_real_data(tmp_path: Path) -> None:
    task = _task(tmp_path)
    text = WriteupBuilder(_evidence(tmp_path)).render(task)
    for heading in (
        "## 1. Challenge metadata and supplied materials",
        "## 2. Challenge description and scope",
        "## 3. Tool and environment versions actually observed",
        "## 4. Chronological steps",
        "## 5. Failed attempts and meaningful negative results",
        "## 6. Candidate Flag and exact verification status",
        "## 7. Unresolved or blocked steps",
        "## 8. Evidence index and hashes",
    ):
        assert heading in text, heading
    assert "internal.file_hash" in text
    assert "sha256=deadbeef size=12" in text
    assert "challenge.txt" in text
    assert "tool.python_version" in text
    assert "synthetic failure" in text
    assert "grant_missing" in text
    assert "unmatched_result" in text
    assert "candidate" in text
    assert "does not submit Flags automatically" in text
    assert "screenshot unavailable: capture status `blank`" in text
    assert "![Screenshot shot-ok](screenshots/shot-ok.png)" in text
    assert "shot-blank" in text
    # Fabrication guards: no invented "verified" claim.
    assert "platform_verified" in text
    assert "No tool output" in text


def test_writeup_is_deterministic(tmp_path: Path) -> None:
    task = _task(tmp_path)
    first = WriteupBuilder(_evidence(tmp_path)).render(task)
    second = WriteupBuilder(_evidence(tmp_path)).render(task)
    assert first == second
    assert first.endswith("\n")


def test_bundle_build_and_manifest_verification(tmp_path: Path) -> None:
    paths = SolverPaths.for_root(tmp_path)
    paths.ensure()
    task = _task(tmp_path)
    evidence = _evidence(tmp_path)
    (paths.task_workspace(task.task_id)).mkdir(parents=True, exist_ok=True)
    builder = EvidenceBundleBuilder(evidence, paths)
    first = builder.build(task)
    assert first.kind == "evidence_zip"
    assert Path(first.path).is_file()
    with zipfile.ZipFile(first.path) as archive:
        names = sorted(archive.namelist())
    assert "writeup.md" in names
    assert "events.jsonl" in names
    assert "manifest.sha256" in names
    assert "screenshots/shot-ok.png" in names
    assert "screenshots/shot-blank.png" not in names
    assert "outputs/exec-1-stdout.txt" in names
    extracted = tmp_path / "verify"
    report = builder.verify_zip(first.path, extracted)
    assert report["ok"] is True, report["problems"]
    assert report["zip_sha256"] == first.sha256
    # Export records are written back to the evidence store.
    kinds = {info.kind for info in evidence.exports}
    assert {"evidence_zip", "writeup", "events_jsonl"} <= kinds


def test_bundle_is_reproducible(tmp_path: Path) -> None:
    paths = SolverPaths.for_root(tmp_path)
    paths.ensure()
    task = _task(tmp_path)
    evidence = _evidence(tmp_path)
    (paths.task_workspace(task.task_id)).mkdir(parents=True, exist_ok=True)
    builder = EvidenceBundleBuilder(evidence, paths)
    first = builder.build(task)
    second = builder.build(task)
    assert first.sha256 == second.sha256
    assert file_sha256(first.path) == first.sha256


def test_manifest_verification_detects_tampering(tmp_path: Path) -> None:
    paths = SolverPaths.for_root(tmp_path)
    paths.ensure()
    task = _task(tmp_path)
    evidence = _evidence(tmp_path)
    (paths.task_workspace(task.task_id)).mkdir(parents=True, exist_ok=True)
    info = EvidenceBundleBuilder(evidence, paths).build(task)
    extracted = tmp_path / "tampered"
    EvidenceBundleBuilder.verify_zip(info.path, extracted)
    target = extracted / "writeup.md"
    target.write_text(target.read_text(encoding="utf-8") + "\nTAMPERED\n", encoding="utf-8")
    report = verify_manifest(extracted / "manifest.sha256", extracted)
    assert report["ok"] is False
    assert any("hash mismatch" in problem for problem in report["problems"])


# ---------------------------------------------------------------------------
# Round 1 delivery additions: intake notes, completion note, step binding,
# raw Lead log inclusion and internal ZIP verification.
# ---------------------------------------------------------------------------


def _section(text: str, heading: str) -> str:
    start = text.index(heading)
    end = text.find("\n## ", start + len(heading))
    return text[start:] if end == -1 else text[start:end]


def test_intake_notes_rendered_exactly_once_in_section_1(tmp_path: Path) -> None:
    task = _task(tmp_path)
    text = WriteupBuilder(_evidence(tmp_path)).render(task)
    notes = task.notes
    assert text.count(notes) == 1
    section_1 = _section(text, "## 1. Challenge metadata and supplied materials")
    assert notes in section_1
    section_2 = _section(text, "## 2. Challenge description and scope")
    assert notes not in section_2
    assert "reproduced in section 1 and not duplicated here" in section_2


def test_completion_note_rendered_as_subsection_after_description(tmp_path: Path) -> None:
    completion_note = "Outcome: candidate flag recorded; no platform verification claimed."
    task = _task(tmp_path, completion_note=completion_note)
    text = WriteupBuilder(_evidence(tmp_path)).render(task)
    assert "### 2.1 Completion note (outcome record)" in text
    assert text.count(completion_note) == 1
    section_2 = _section(text, "## 2. Challenge description and scope")
    assert completion_note in section_2
    assert task.notes not in section_2
    section_1 = _section(text, "## 1. Challenge metadata and supplied materials")
    assert completion_note not in section_1
    # The subsection comes after the description reference and the scope line.
    assert text.index("reproduced in section 1") < text.index("### 2.1 Completion note")


def test_empty_completion_note_renders_no_subsection(tmp_path: Path) -> None:
    task = _task(tmp_path)
    text = WriteupBuilder(_evidence(tmp_path)).render(task)
    assert "### 2.1 Completion note" not in text
    assert getattr(task, "completion_note", "") == ""


def test_tool_call_heading_includes_recorded_turn_and_step(tmp_path: Path) -> None:
    task = _task(tmp_path)
    text = WriteupBuilder(_evidence(tmp_path)).render(task)
    step_heading = "### Step 3 — Worker initiated `mcp__ctf-exec__ctf_exec` (turn 2, step 5) at "
    assert step_heading in text


def test_tool_call_heading_marks_lead_origin_when_worker_id_is_null(tmp_path: Path) -> None:
    evidence = _evidence(tmp_path)
    lead_event = _event(
        90,
        "tool_call",
        {
            "call_id": "call-lead-1",
            "tool_name": "pwsh",
            "arguments": json.dumps({"command": "Get-ChildItem"}),
            "turn": 1,
            "step": 7,
        },
    )
    lead_event["worker_id"] = None
    evidence.events.append(lead_event)
    text = WriteupBuilder(evidence).render(_task(tmp_path))
    assert "Lead initiated `pwsh` (turn 1, step 7)" in text
    assert "the Lead requested this tool call" in text
    # Worker-sourced evidence keeps the historical wording unchanged.
    assert "Worker initiated `mcp__ctf-exec__ctf_exec`" in text


def test_screenshot_bound_by_derived_turn_step_id_appears_under_its_step(tmp_path: Path) -> None:
    task = _task(tmp_path)
    text = WriteupBuilder(_evidence(tmp_path)).render(task)
    heading = "### Step 3 — Worker initiated `mcp__ctf-exec__ctf_exec` (turn 2, step 5) at "
    screenshot_line = "![Screenshot shot-derived](screenshots/shot-derived.png)"
    assert screenshot_line in text
    assert text.index(heading) < text.index(screenshot_line)
    # The derived screenshot must not leak into another section (e.g. failures).
    step_block = text[text.index(heading) :]
    assert screenshot_line in step_block
    assert step_block.index(screenshot_line) < step_block.index("\n## 5. ")


def test_bundle_excludes_raw_session_log_and_delivers_the_privacy_view(tmp_path: Path) -> None:
    paths = SolverPaths.for_root(tmp_path)
    paths.ensure()
    task = _task(tmp_path)
    evidence = _evidence(tmp_path)
    raw_log = b"raw-lead-session-log-bytes"
    raw_sha = sha256_hex(raw_log)
    evidence.artifacts[raw_sha] = raw_log
    evidence.sources = [
        {"source_id": "lead", "task_id": task.task_id, "raw_sha256": raw_sha}
    ]
    reasoning_canary = "REASONING-CANARY-NEVER-DELIVERED"
    evidence.events.append(
        _event(
            90,
            "assistant_message",
            {"text": reasoning_canary, "reasoning": reasoning_canary},
            1_700_000_000_000 + 90,
        )
    )
    (paths.task_workspace(task.task_id)).mkdir(parents=True, exist_ok=True)
    info = EvidenceBundleBuilder(evidence, paths).build(task)
    with zipfile.ZipFile(info.path) as archive:
        names = sorted(archive.namelist())
        assert not any(name.startswith("raw/") for name in names)
        assert "raw/session-" not in " ".join(names)
        events_text = archive.read("events.jsonl").decode("utf-8")
        writeup_text = archive.read("writeup.md").decode("utf-8")
    # The delivered view is the shared privacy projection: model reasoning never ships.
    assert reasoning_canary not in events_text
    assert reasoning_canary not in writeup_text
    assert '"assistant_message"' not in events_text
    # The raw ingested log object itself stays in the local CAS, untouched.
    assert evidence.artifacts[raw_sha] == raw_log
    report = EvidenceBundleBuilder.verify_zip(info.path, tmp_path / "verify-no-raw")
    assert report["ok"] is True, report["problems"]
    assert not any(name.startswith("raw/") for name in report["members"])


def test_bundle_internal_verification_failure_raises_delivery_error(tmp_path: Path, monkeypatch) -> None:
    paths = SolverPaths.for_root(tmp_path)
    paths.ensure()
    task = _task(tmp_path)
    evidence = _evidence(tmp_path)
    (paths.task_workspace(task.task_id)).mkdir(parents=True, exist_ok=True)

    def failing_verify(zip_path, extract_to):
        return {"ok": False, "checked": 0, "problems": ["synthetic manifest mismatch"]}

    monkeypatch.setattr(EvidenceBundleBuilder, "verify_zip", staticmethod(failing_verify))
    with pytest.raises(DeliveryError) as excinfo:
        EvidenceBundleBuilder(evidence, paths).build(task)
    assert "internal verification" in str(excinfo.value)
    assert "synthetic manifest mismatch" in str(excinfo.value)


def test_bundle_internal_verification_cleans_up_temp_dir(tmp_path: Path, monkeypatch) -> None:
    paths = SolverPaths.for_root(tmp_path)
    paths.ensure()
    task = _task(tmp_path)
    evidence = _evidence(tmp_path)
    (paths.task_workspace(task.task_id)).mkdir(parents=True, exist_ok=True)
    created: list[str] = []
    real_mkdtemp = tempfile.mkdtemp

    def recording_mkdtemp(*args, **kwargs):
        path = real_mkdtemp(*args, **kwargs)
        created.append(path)
        return path

    monkeypatch.setattr(bundle_module.tempfile, "mkdtemp", recording_mkdtemp)
    info = EvidenceBundleBuilder(evidence, paths).build(task)
    assert Path(info.path).is_file()
    assert created, "internal verification temp dir was never created"
    assert all(not Path(path).exists() for path in created)


# ---------------------------------------------------------------------------
# Round 2 delivery additions: Lead native calls vs Worker execution versions,
# Markdown screenshot embedding materialised beside the standalone Writeup (and
# inside the ZIP), honest unavailable captures, and the append-only gap tri-state.
# ---------------------------------------------------------------------------


def _writeup_screenshot(
    screenshot_id: str,
    *,
    step_id: str | None = "step-1",
    status: CaptureStatus = CaptureStatus.OK,
    sha256: str | None = None,
    failure_reason: str = "",
    width: int | None = 64,
    height: int | None = 48,
) -> ScreenshotRecord:
    return ScreenshotRecord(
        screenshot_id=screenshot_id,
        task_id="t-writeup0001",
        worker_id="w-1",
        step_id=step_id,
        session_id="session-1",
        scope="desktop",
        captured_at=1_700_000_000_000,
        status=status,
        sha256=sha256,
        width=width,
        height=height,
        failure_reason=failure_reason,
    )


def _screenshot_step_events(png_sha: str, t: int = 1_700_000_000_000) -> list[dict]:
    return [
        _event(1, "task_created", {"title": "Synthetic", "category": "misc"}, t),
        _event(
            2,
            "execution_started",
            {
                "execution_id": "exec-1",
                "step_id": "step-1",
                "tool_name": "internal.file_hash",
                "tool_version": "1.0",
                "argv": ["challenge.txt"],
                "cwd": "work",
                "tier": 0,
            },
            t + 10,
        ),
        _event(
            3,
            "execution_completed",
            {"execution_id": "exec-1", "status": "completed", "exit_code": 0, "stdout_preview": "ok"},
            t + 20,
        ),
    ]


def test_section_three_distinguishes_lead_native_calls_from_worker_versions(tmp_path: Path) -> None:
    t = 1_700_000_000_000
    skill_body_canary = "SKILL-BODY-CANARY-NOT-DELIVERED"
    reasoning_canary = "MODEL-REASONING-CANARY-NOT-DELIVERED"
    evidence = FakeEvidence()
    evidence.events = [
        _event(1, "task_created", {"title": "Synthetic", "category": "misc"}, t),
        _event(
            2,
            "assistant_message",
            {"text": reasoning_canary, "reasoning": reasoning_canary},
            t + 5,
        ),
        _event(
            3,
            "tool_call",
            {
                "call_id": "lead-1",
                "tool_name": "pwsh",
                "arguments": json.dumps({"command": "Get-ChildItem"}),
                "turn": 1,
                "step": 1,
            },
            t + 10,
        ),
        _event(
            4,
            "tool_result",
            {"call_id": "lead-1", "is_error": False, "content_preview": "total 1", "exit_code": 0},
            t + 11,
        ),
        _event(
            5,
            "tool_call",
            {
                "call_id": "lead-2",
                "tool_name": "skill",
                "arguments": json.dumps({"name": "ctf-misc"}),
                "turn": 1,
                "step": 2,
            },
            t + 20,
        ),
        _event(
            6,
            "tool_result",
            {
                "call_id": "lead-2",
                "tool_name": "skill",
                "is_error": False,
                "content_preview": skill_body_canary,
                "exit_code": 0,
            },
            t + 21,
        ),
        _event(
            7,
            "tool_call",
            {
                "call_id": "lead-3",
                "tool_name": "pwsh",
                "arguments": json.dumps({"command": "dir"}),
                "turn": 1,
                "step": 3,
            },
            t + 30,
        ),
        _event(
            8,
            "execution_started",
            {
                "execution_id": "exec-1",
                "step_id": "step-1",
                "tool_name": "internal.file_hash",
                "tool_version": "1.0",
                "argv": ["challenge.txt"],
                "cwd": "work",
                "tier": 0,
            },
            t + 40,
        ),
    ]
    text = WriteupBuilder(evidence).render(_task(tmp_path))
    section_3 = _section(text, "## 3. Tool and environment versions actually observed")
    assert "`internal.file_hash` — version `1.0` (1 execution record(s))" in section_3
    assert (
        "`pwsh` — Harness-native tool call (tool version not recorded separately); 2 call(s)"
        in section_3
    )
    assert (
        "`skill` — Harness-native tool call (tool version not recorded separately); 1 call(s)"
        in section_3
    )
    # A native call is never reported as "no tool executions were recorded".
    assert "No tool executions were recorded" not in text
    # The delivery projection keeps the shared privacy view for both paths.
    assert reasoning_canary not in text
    assert skill_body_canary not in text
    assert "Skill loaded: ctf-misc (content omitted by delivery privacy policy)" in text


def test_section_three_worker_version_covers_a_matching_native_tool_name(tmp_path: Path) -> None:
    t = 1_700_000_000_000
    evidence = FakeEvidence()
    evidence.events = [
        _event(1, "task_created", {"title": "Synthetic", "category": "misc"}, t),
        _event(
            2,
            "tool_call",
            {"call_id": "call-1", "tool_name": "internal.file_hash", "arguments": "{}", "turn": 1, "step": 1},
            t + 10,
        ),
        _event(
            3,
            "execution_started",
            {
                "execution_id": "exec-1",
                "step_id": "step-1",
                "tool_name": "internal.file_hash",
                "tool_version": "1.0",
                "argv": ["challenge.txt"],
                "cwd": "work",
                "tier": 0,
            },
            t + 20,
        ),
    ]
    text = WriteupBuilder(evidence).render(_task(tmp_path))
    section_3 = _section(text, "## 3. Tool and environment versions actually observed")
    assert "`internal.file_hash` — version `1.0` (1 execution record(s))" in section_3
    assert (
        "`internal.file_hash` — worker execution record version listed above; "
        "Harness-native tool version not recorded separately."
    ) in section_3
    assert "No tool executions were recorded" not in text


def test_screenshot_image_and_capture_metadata_render_under_the_step(tmp_path: Path) -> None:
    t = 1_700_000_000_000
    png = gradient_png()
    png_sha = sha256_hex(png)
    evidence = FakeEvidence()
    evidence.artifacts[png_sha] = png
    evidence.events = _screenshot_step_events(png_sha, t)
    evidence.events.append(
        _event(
            4,
            "screenshot_captured",
            {
                "screenshot_id": "shot-1",
                "sha256": png_sha,
                "width": 64,
                "height": 48,
                "capture_method": "win32-printwindow",
                "target_pid": 4242,
                "scope": "window",
                "session_id": "lead-session-9",
                "status": "ok",
            },
            t + 30,
        )
    )
    evidence.screenshots = [
        _writeup_screenshot("shot-1", step_id="step-1", sha256=png_sha)
    ]
    text = WriteupBuilder(evidence).render(_task(tmp_path))
    section_4 = _section(text, "## 4. Chronological steps")
    image = "![Screenshot shot-1](screenshots/shot-1.png)"
    assert image in section_4
    metadata_line = next(
        line for line in section_4.splitlines() if line.startswith("  - sha256:")
    )
    assert f"sha256: `{png_sha}`" in metadata_line
    assert "captured_at: `2023-11-14T22:13:20.000Z`" in metadata_line
    assert "dimensions: 64x48" in metadata_line
    assert "capture_method: `win32-printwindow`" in metadata_line
    assert "target_pid: `4242`" in metadata_line
    assert "scope: `window`" in metadata_line
    assert "session_id: `lead-session-9`" in metadata_line
    # The embed belongs to the step the capture is bound to.
    assert section_4.index("### Step 1") < section_4.index(image)


def test_standalone_writeup_materialises_linked_screenshots(tmp_path: Path) -> None:
    paths = SolverPaths.for_root(tmp_path)
    paths.ensure()
    task = _task(tmp_path)
    png = gradient_png()
    png_sha = sha256_hex(png)
    evidence = FakeEvidence()
    evidence.artifacts[png_sha] = png
    evidence.events = _screenshot_step_events(png_sha)
    evidence.screenshots = [
        _writeup_screenshot("shot-ok", step_id="step-1", sha256=png_sha)
    ]
    builder = WriteupBuilder(evidence)
    writeup_path = paths.writeup_path(task.task_id)
    info = builder.build(task, writeup_path)
    image_path = paths.task_dir(task.task_id) / "screenshots" / "shot-ok.png"
    assert image_path.is_file()
    assert image_path.read_bytes() == png
    text = writeup_path.read_text(encoding="utf-8")
    assert "![Screenshot shot-ok](screenshots/shot-ok.png)" in text
    # Capture metadata is not on the ScreenshotRecord; absent event fields are honest.
    assert "capture_method: `not recorded`" in text
    assert "target_pid: `not recorded`" in text
    assert "scope: `not recorded`" in text
    assert "session_id: `session-1`" in text
    second = builder.build(task, writeup_path)
    assert second["sha256"] == info["sha256"]
    assert image_path.read_bytes() == png


def test_evidence_zip_writeup_image_member_resolves_after_extraction(tmp_path: Path) -> None:
    paths = SolverPaths.for_root(tmp_path)
    paths.ensure()
    task = _task(tmp_path)
    png = gradient_png()
    png_sha = sha256_hex(png)
    evidence = FakeEvidence()
    evidence.artifacts[png_sha] = png
    evidence.events = _screenshot_step_events(png_sha)
    evidence.screenshots = [
        _writeup_screenshot("shot-ok", step_id="step-1", sha256=png_sha)
    ]
    (paths.task_workspace(task.task_id)).mkdir(parents=True, exist_ok=True)
    info = EvidenceBundleBuilder(evidence, paths).build(task)
    with zipfile.ZipFile(info.path) as archive:
        assert archive.read("writeup.md").decode("utf-8").count(
            "![Screenshot shot-ok](screenshots/shot-ok.png)"
        ) == 1
        assert archive.read("screenshots/shot-ok.png") == png
    extracted = tmp_path / "verify-image"
    report = EvidenceBundleBuilder.verify_zip(info.path, extracted)
    assert report["ok"] is True, report["problems"]
    # The same relative member path resolves the same bytes after extraction.
    assert (extracted / "screenshots" / "shot-ok.png").read_bytes() == png
    assert "![Screenshot shot-ok](screenshots/shot-ok.png)" in (
        extracted / "writeup.md"
    ).read_text(encoding="utf-8")


def test_failed_or_unreadable_screenshots_render_no_image_link(tmp_path: Path) -> None:
    paths = SolverPaths.for_root(tmp_path)
    paths.ensure()
    task = _task(tmp_path)
    t = 1_700_000_000_000
    missing_sha = "f" * 64
    evidence = FakeEvidence()
    evidence.events = _screenshot_step_events("0" * 64, t)
    evidence.events.append(
        _event(
            4,
            "execution_started",
            {
                "execution_id": "exec-2",
                "step_id": "step-2",
                "tool_name": "tool.python_version",
                "tool_version": "Python 3.14.7",
                "argv": ["--version"],
                "cwd": "work",
                "tier": 0,
            },
            t + 30,
        )
    )
    evidence.screenshots = [
        _writeup_screenshot(
            "shot-blank",
            step_id="step-1",
            status=CaptureStatus.BLANK,
            failure_reason="blank capture (stddev below threshold)",
        ),
        _writeup_screenshot("shot-lost", step_id="step-2", sha256=missing_sha),
    ]
    builder = WriteupBuilder(evidence)
    text = builder.render(task)
    assert "![Screenshot shot-blank]" not in text
    assert "![Screenshot shot-lost]" not in text
    assert "screenshot unavailable: capture status `blank`" in text
    assert (
        f"screenshot unavailable: CAS object sha256:{missing_sha} is not readable "
        "from the evidence store"
    ) in text
    writeup_path = paths.writeup_path(task.task_id)
    builder.build(task, writeup_path)
    shots_dir = paths.task_dir(task.task_id) / "screenshots"
    assert not shots_dir.exists() or not any(shots_dir.iterdir())
    assert "![Screenshot shot-lost]" not in writeup_path.read_text(encoding="utf-8")


def test_gap_tristate_resolved_unresolved_and_expected_capture_boundary(tmp_path: Path) -> None:
    t = 1_700_000_000_000
    ingest_tool = "mcp__ctf-solver__ctf_session_ingest"
    evidence = FakeEvidence()
    evidence.events = [
        _event(1, "task_created", {"title": "Synthetic", "category": "misc"}, t),
        # Two ingest calls; the latest ingest call's own result cannot be in the
        # snapshot it ingests, so its unmatched call is the expected boundary.
        _event(
            10,
            "tool_call",
            {"call_id": "call-ingest-old", "tool_name": ingest_tool, "arguments": "{}", "turn": 1, "step": 1},
            t + 10,
            source_seq=100,
        ),
        _event(
            11,
            "tool_call",
            {"call_id": "call-ingest-last", "tool_name": ingest_tool, "arguments": "{}", "turn": 1, "step": 2},
            t + 11,
            source_seq=200,
        ),
        _event(
            12,
            "evidence_gap",
            {
                "reason": "unmatched_call",
                "detail": "latest ingest call has no result in the snapshot it ingests",
                "call_id": "call-ingest-last",
                "tool_name": ingest_tool,
            },
            t + 12,
        ),
        _event(
            13,
            "evidence_gap",
            {
                "reason": "unmatched_call",
                "detail": "older ingest call has no result",
                "call_id": "call-ingest-old",
                "tool_name": ingest_tool,
            },
            t + 13,
        ),
        # Non-ingest unmatched call with no later result.
        _event(
            20,
            "tool_call",
            {"call_id": "call-p", "tool_name": "pwsh", "arguments": "{}", "turn": 2, "step": 1},
            t + 20,
            source_seq=5,
        ),
        _event(
            21,
            "evidence_gap",
            {"reason": "unmatched_call", "detail": "pwsh call has no result", "call_id": "call-p"},
            t + 21,
        ),
        # Unmatched call resolved by a tool_result recorded by a later ingestion.
        _event(
            30,
            "evidence_gap",
            {"reason": "unmatched_call", "detail": "resolved by later ingestion", "call_id": "call-recovered"},
            t + 30,
        ),
        _event(
            40,
            "tool_result",
            {"call_id": "call-recovered", "is_error": False, "content_preview": "ok", "exit_code": 0},
            t + 40,
        ),
        # Unmatched result with no matching call.
        _event(
            50,
            "evidence_gap",
            {"reason": "unmatched_result", "detail": "ghost result", "call_id": "call-ghost"},
            t + 50,
        ),
        # Unmatched result resolved by a call record.
        _event(
            60,
            "tool_call",
            {"call_id": "call-known", "tool_name": "read", "arguments": "{}", "turn": 3, "step": 1},
            t + 60,
        ),
        _event(
            61,
            "evidence_gap",
            {"reason": "unmatched_result", "detail": "resolved by call record", "call_id": "call-known"},
            t + 61,
        ),
        # Every other gap reason stays unresolved.
        _event(
            70,
            "evidence_gap",
            {"reason": "sequence_gap", "detail": "missing session sequences 5..6"},
            t + 70,
        ),
    ]
    builder = WriteupBuilder(evidence)
    text = builder.render(_task(tmp_path))
    section_5 = _section(text, "## 5. Failed attempts and meaningful negative results")
    section_7 = _section(text, "## 7. Unresolved or blocked steps")
    assert section_5.count("status **resolved (matched by a later ingestion)**") == 2
    assert section_5.count("status **Expected capture-boundary gap**") == 1
    assert section_5.count("status **unresolved**") == 4
    # Section 7 only lists open items: unresolved gaps and the labelled boundary.
    assert "Expected capture-boundary gap" in section_7
    assert "an expected ingestion-time boundary, not a missing solve step" in section_7
    assert "call-ingest-old" in section_7
    assert "call-p" in section_7
    assert "call-ghost" in section_7
    assert "sequence_gap" in section_7
    assert "call-recovered" not in section_7
    assert "call-known" not in section_7
    assert "resolved (matched by a later ingestion)" not in section_7
    # Rendering is derived and deterministic; the evidence stays untouched.
    assert builder.render(_task(tmp_path)) == text

