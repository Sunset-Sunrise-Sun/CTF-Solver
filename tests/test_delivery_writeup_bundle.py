"""Tests for deterministic Markdown Writeup and evidence ZIP generation."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

from ctf_solver.core.canonical import file_sha256, sha256_hex
from ctf_solver.core.config import SolverPaths
from ctf_solver.core.types import (
    CaptureStatus,
    Category,
    ExportInfo,
    FlagState,
    ScreenshotRecord,
    TaskRecord,
    TaskStatus,
)
from ctf_solver.delivery.bundle import EvidenceBundleBuilder, verify_manifest
from ctf_solver.delivery.writeup import WriteupBuilder
from tests.support.png import gradient_png


class FakeEvidence:
    def __init__(self) -> None:
        self.events: list[dict] = []
        self.screenshots: list[ScreenshotRecord] = []
        self.artifacts: dict[str, bytes] = {}
        self.exports: list[ExportInfo] = []

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
        lines = [
            json.dumps(event, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            for event in sorted(self.events, key=lambda item: item.get("seq", 0))
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
        return []


def _event(seq: int, event_type: str, payload: dict, timestamp: int | None = None) -> dict:
    return {
        "seq": seq,
        "record_id": f"ev-{seq:04d}",
        "task_id": "t-writeup0001",
        "worker_id": "w-1",
        "session_id": "session-1",
        "source": "runtime",
        "source_id": f"execution:exec-{seq}",
        "source_seq": 1,
        "event_type": event_type,
        "timestamp": 1_700_000_000_000 + seq,
        "payload": payload,
    }


def _task(tmp_path: Path) -> TaskRecord:
    return TaskRecord(
        task_id="t-writeup0001",
        conversation_id="conv-1",
        title="Synthetic Misc Challenge",
        category=Category.MISC,
        workspace_path=str(tmp_path / "tasks" / "t-writeup0001" / "work"),
        source="synthetic-local",
        scope_profile="synthetic-local",
        status=TaskStatus.RUNNING,
        created_at=1_700_000_000_000,
        updated_at=1_700_000_000_500,
        started_at=1_700_000_000_100,
        evidence_head="b" * 64,
        flag_state=FlagState.CANDIDATE,
        notes="Synthetic challenge description for the Writeup test.",
    )


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
    assert "Screenshot: _not captured for this step_" in text
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
