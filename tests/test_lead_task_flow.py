"""Service-level Lead-session flow tests (contract section 6, owner B).

These tests cover the Manager service behaviour added for Lead-session evidence:
one-time binding at Task creation, ``source``-selected ingestion, automatic
ingestion before completion, derived screenshot step ids and the runtime status
surface. No real ACP/model call is made: the fake ACP client and fake evidence
store from ``tests/support`` are used, and the session logs are synthetic
multi-frame zstd fixtures.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import replace
from pathlib import Path

import pytest

from ctf_solver.core.config import SolverConfig
from ctf_solver.core.errors import StateError, ValidationError
from ctf_solver.core.types import CaptureResult, CaptureStatus, TaskStatus
from ctf_solver.evidence.store import EvidenceStore
from ctf_solver.manager.service import ManagerService
from ctf_solver.manager.session_logs import SessionLogError
from ctf_solver.manager.store import ManagerStore
from tests.support.fakes import (
    FakeAcp,
    FakeCapturer,
    FakeDeliverables,
    FakeEvidence,
    FakePipeline,
)
from tests.support.session_events import session_header, standard_session, tool_call
from tests.support.zstd_fixtures import write_session_log
from tests.test_security_support import approving_channel

LEAD_SESSION_ID = "11111111-2222-3333-4444-555555555555"


class FakeWindowCapturer(FakeCapturer):
    """Fake capturer that reports itself as the real-window capturer (P0-1/P0-2)."""

    name = "real-window"

    def __init__(self, mode: str = "ok", *, target_pid: int = 4321) -> None:
        super().__init__(mode)
        self.target_pid = target_pid

    def capture(self, *, scope: str, workdir: str | None = None) -> CaptureResult:
        result = super().capture(scope=scope, workdir=workdir)
        return replace(result, method=self.name)


class RecordingEvidence(FakeEvidence):
    """Fake evidence that records every session-log ingestion attempt."""

    def __init__(self) -> None:
        super().__init__()
        self.ingest_calls: list[dict[str, object]] = []

    def ingest_session_log_file(
        self,
        *,
        task_id: str,
        worker_id: str | None,
        session_id: str | None,
        path: str,
        boundary: dict[str, object] | None = None,
    ):
        self.ingest_calls.append(
            {
                "task_id": task_id,
                "worker_id": worker_id,
                "session_id": session_id,
                "path": str(path),
                "boundary": boundary,
            }
        )
        return super().ingest_session_log_file(
            task_id=task_id,
            worker_id=worker_id,
            session_id=session_id,
            path=path,
            boundary=boundary,
        )


def _build_service(
    tmp_path: Path,
    *,
    lead_root: Path | None = None,
    evidence: FakeEvidence | None = None,
    config_extra: dict[str, str] | None = None,
    capturer: FakeCapturer | None = None,
) -> tuple[ManagerService, FakeAcp, FakeEvidence, ManagerStore]:
    config = SolverConfig(root=tmp_path, extra=dict(config_extra or {}))
    paths = config.ensure_layout()
    store = ManagerStore(str(paths.db_path))
    acp = FakeAcp()
    evidence = evidence if evidence is not None else RecordingEvidence()
    service = ManagerService(
        config=config,
        store=store,
        acp_factory=lambda: acp,
        evidence=evidence,
        pipeline=FakePipeline(),
        deliverables=FakeDeliverables(tmp_path),
        capturer=capturer if capturer is not None else FakeCapturer("ok"),
        lead_sessions_root=lead_root,
        workspace_root=tmp_path,
    )
    return service, acp, evidence, store


def _lead_log_records(session_id: str, *, cwd: str, header_id: str | None = None) -> list[dict]:
    return [
        session_header(header_id or session_id, cwd=cwd),
        *standard_session(session_id=session_id)[1:],
    ]


def _write_lead_log(
    root: Path,
    session_id: str,
    *,
    cwd: str,
    header_id: str | None = None,
    frames: int = 3,
) -> bytes:
    return write_session_log(
        root / "lead-slug" / session_id / "session.v4.jsonl.zstd",
        _lead_log_records(session_id, cwd=cwd, header_id=header_id),
        frames=frames,
    )


def _append_lead_records(root: Path, session_id: str, records: list[dict]) -> None:
    """Append a new zstd frame to the bound Lead log (post-Task creation)."""

    from tests.support.zstd_fixtures import frame_bytes, jsonl_bytes

    path = root / "lead-slug" / session_id / "session.v4.jsonl.zstd"
    path.write_bytes(path.read_bytes() + frame_bytes([jsonl_bytes(records)]))


def _write_worker_log(service: ManagerService, session_id: str) -> bytes:
    return write_session_log(
        service.config.session_log_root / "worker-slug" / session_id / "session.v4.jsonl.zstd",
        standard_session(session_id=session_id),
        frames=4,
    )


def _create(service: ManagerService, **overrides):
    arguments = {
        "title": "Synthetic Lead-driven challenge",
        "category": "web",
        "conversation_id": "conv-lead",
    }
    arguments.update(overrides)
    return service.create_task(**arguments)


def _events(evidence: FakeEvidence, event_type: str) -> list[dict]:
    return [event for event in evidence.events if event["event_type"] == event_type]


def test_create_task_binds_verified_lead_session(tmp_path) -> None:
    lead_root = tmp_path / "lead-sessions"
    lead_root.mkdir()
    raw = _write_lead_log(lead_root, LEAD_SESSION_ID, cwd=str(tmp_path))
    service, acp, evidence, store = _build_service(tmp_path, lead_root=lead_root)
    try:
        service.start()
        task = _create(service, notes="handoff: execute the Lead plan", lead_session_id=LEAD_SESSION_ID)
        # Worker/pump lifecycle is unchanged: a shell Worker still starts.
        assert task.status is TaskStatus.RUNNING
        assert task.worker_id and task.acp_session_id
        assert len(acp.new_session_calls) == 1
        # The one-time binding is durable and carries the verified log hash.
        binding = store.get_lead_binding(task.task_id)
        assert binding is not None
        assert binding.session_id == LEAD_SESSION_ID
        assert binding.bound_by == "lead"
        assert binding.log_sha256 == hashlib.sha256(raw).hexdigest()
        assert store.get_task_for_lead_session(LEAD_SESSION_ID) == task.task_id
        # task_created carries the candidate id and the intake notes (P1-1);
        # a second event records the binding.
        created = _events(evidence, "task_created")
        assert len(created) == 1
        assert created[0]["payload"]["lead_session_id"] == LEAD_SESSION_ID
        assert created[0]["payload"]["notes"] == "handoff: execute the Lead plan"
        bound = _events(evidence, "lead_session_bound")
        assert len(bound) == 1
        assert bound[0]["payload"]["session_id"] == LEAD_SESSION_ID
        assert bound[0]["payload"]["log_sha256"] == binding.log_sha256
        event_types = [event["event_type"] for event in evidence.events]
        assert event_types.index("lead_session_bound") > event_types.index("task_created")
    finally:
        service.shutdown()
        store.close()


def test_worker_only_task_creation_has_no_binding(tmp_path) -> None:
    service, _acp, evidence, store = _build_service(tmp_path)
    try:
        service.start()
        task = _create(service)
        assert store.get_lead_binding(task.task_id) is None
        created = _events(evidence, "task_created")
        assert created and created[0]["payload"]["lead_session_id"] is None
        assert _events(evidence, "lead_session_bound") == []
    finally:
        service.shutdown()
        store.close()


def test_create_task_rejects_invalid_lead_session_before_persistence(tmp_path) -> None:
    lead_root = tmp_path / "lead-sessions"
    lead_root.mkdir()
    _write_lead_log(lead_root, "session-present", cwd=str(tmp_path))
    _write_lead_log(
        lead_root, "session-mismatch", cwd=str(tmp_path), header_id="session-other"
    )
    service, _acp, evidence, store = _build_service(tmp_path, lead_root=lead_root)
    try:
        service.start()
        # Empty candidate: rejected as input validation, nothing persisted.
        with pytest.raises(ValidationError):
            _create(service, lead_session_id="")
        # Traversal attempt: never a valid single path component.
        with pytest.raises(SessionLogError):
            _create(service, lead_session_id="..\\escape")
        # No such log on disk.
        with pytest.raises(SessionLogError) as missing:
            _create(service, lead_session_id="session-absent")
        assert missing.value.reason_code == "log_missing"
        # Header content does not identify the candidate.
        with pytest.raises(SessionLogError) as mismatch:
            _create(service, lead_session_id="session-mismatch")
        assert mismatch.value.reason_code == "header_mismatch"
        assert store.list_tasks() == []
        assert _events(evidence, "task_created") == []
    finally:
        service.shutdown()
        store.close()


def test_create_task_rejects_lead_cwd_mismatch(tmp_path) -> None:
    lead_root = tmp_path / "lead-sessions"
    lead_root.mkdir()
    session_id = "session-wrong-cwd"
    write_session_log(
        lead_root / "lead-slug" / session_id / "session.v4.jsonl.zstd",
        [session_header(session_id, cwd=str(tmp_path / "some-other-project"))],
        frames=1,
    )
    service, _acp, _evidence, store = _build_service(tmp_path, lead_root=lead_root)
    try:
        service.start()
        with pytest.raises(SessionLogError) as mismatch:
            _create(service, lead_session_id=session_id)
        assert mismatch.value.reason_code == "lead_cwd_mismatch"
        assert store.list_tasks() == []
    finally:
        service.shutdown()
        store.close()


def test_create_task_rejects_missing_lead_sessions_root(tmp_path) -> None:
    missing_root = tmp_path / "missing-lead-sessions"
    service, _acp, _evidence, store = _build_service(tmp_path, lead_root=missing_root)
    try:
        service.start()
        with pytest.raises(SessionLogError) as excinfo:
            _create(service, lead_session_id=LEAD_SESSION_ID)
        assert excinfo.value.reason_code == "lead_sessions_root_missing"
        assert store.list_tasks() == []
        # The Manager must never create the live Lead sessions root itself.
        assert not missing_root.exists()
    finally:
        service.shutdown()
        store.close()


def test_duplicate_lead_session_binding_rejected(tmp_path) -> None:
    lead_root = tmp_path / "lead-sessions"
    lead_root.mkdir()
    _write_lead_log(lead_root, LEAD_SESSION_ID, cwd=str(tmp_path))
    service, _acp, _evidence, store = _build_service(tmp_path, lead_root=lead_root)
    try:
        service.start()
        first = _create(service, lead_session_id=LEAD_SESSION_ID)
        first_binding = store.get_lead_binding(first.task_id)
        assert first_binding is not None
        with pytest.raises(StateError):
            _create(service, lead_session_id=LEAD_SESSION_ID)
        # The duplicate attempt persisted no second Task and did not rebind.
        assert [task.task_id for task in store.list_tasks()] == [first.task_id]
        assert store.get_task_for_lead_session(LEAD_SESSION_ID) == first.task_id
        second_binding = store.get_lead_binding(first.task_id)
        assert second_binding is not None
        assert second_binding.bound_at == first_binding.bound_at
    finally:
        service.shutdown()
        store.close()


def test_ingest_session_source_worker_lead_auto(tmp_path) -> None:
    lead_root = tmp_path / "lead-sessions"
    lead_root.mkdir()
    _write_lead_log(lead_root, LEAD_SESSION_ID, cwd=str(tmp_path))
    service, _acp, evidence, store = _build_service(tmp_path, lead_root=lead_root)
    try:
        service.start()
        lead_task = _create(service, lead_session_id=LEAD_SESSION_ID)
        worker_log = _write_worker_log(service, str(lead_task.acp_session_id))

        report = service.ingest_session_log(lead_task.task_id, source="lead")
        ingested = _events(evidence, "evidence_ingested")
        assert ingested[-1]["payload"]["source"] == "lead"
        assert ingested[-1]["payload"]["session_id"] == LEAD_SESSION_ID
        assert ingested[-1]["worker_id"] is None
        # Never echo a local filesystem path through the control surface.
        assert "path" not in report and "raw_path" not in report

        report = service.ingest_session_log(lead_task.task_id, source="worker")
        ingested = _events(evidence, "evidence_ingested")
        assert ingested[-1]["payload"]["source"] == "worker"
        assert ingested[-1]["payload"]["session_id"] == str(lead_task.acp_session_id)
        assert ingested[-1]["worker_id"] == lead_task.worker_id
        assert "path" not in report

        # auto prefers the verified Lead binding even though a Worker log exists
        # (a Lead-bound Task also has a shell Worker row).
        assert worker_log  # the Worker log fixture exists and was NOT selected
        report = service.ingest_session_log(lead_task.task_id)
        ingested = _events(evidence, "evidence_ingested")
        assert ingested[-1]["payload"]["source"] == "lead"
        assert ingested[-1]["payload"]["session_id"] == LEAD_SESSION_ID
        assert "path" not in report

        # A Worker-only Task keeps resolving its registered Worker log.
        worker_task = _create(service, title="worker-only")
        _write_worker_log(service, str(worker_task.acp_session_id))
        service.ingest_session_log(worker_task.task_id)
        ingested = _events(evidence, "evidence_ingested")
        assert ingested[-1]["payload"]["source"] == "worker"
        assert ingested[-1]["payload"]["session_id"] == str(worker_task.acp_session_id)

        # Unknown source values fail closed.
        with pytest.raises(ValidationError):
            service.ingest_session_log(lead_task.task_id, source="bogus")
    finally:
        service.shutdown()
        store.close()


def test_complete_task_auto_ingests_bound_lead_session_once(tmp_path) -> None:
    lead_root = tmp_path / "lead-sessions"
    lead_root.mkdir()
    _write_lead_log(lead_root, LEAD_SESSION_ID, cwd=str(tmp_path))
    evidence = RecordingEvidence()
    service, _acp, _evidence, store = _build_service(
        tmp_path, lead_root=lead_root, evidence=evidence
    )
    try:
        service.start()
        task = _create(service, lead_session_id=LEAD_SESSION_ID)
        result = service.complete_task(
            task.task_id, result_state="solved_flag_candidate", note="flag reproduced locally"
        )
        assert result["status"] == TaskStatus.COMPLETED.value
        assert len(evidence.ingest_calls) == 1
        assert evidence.ingest_calls[0]["session_id"] == LEAD_SESSION_ID
        assert evidence.ingest_calls[0]["worker_id"] is None
        ingested = _events(evidence, "evidence_ingested")
        assert len(ingested) == 1
        assert ingested[0]["payload"]["source"] == "lead"
        # The completion note is persisted in the new completion_note column.
        completed = store.require_task(task.task_id)
        assert completed.status is TaskStatus.COMPLETED
        assert completed.completion_note == "flag reproduced locally"
        # Completing again is idempotent and never ingests a second time.
        again = service.complete_task(task.task_id, result_state="solved_flag_candidate")
        assert again["already_completed"] is True
        assert len(evidence.ingest_calls) == 1
    finally:
        service.shutdown()
        store.close()


def test_completion_preserves_intake_notes_and_uses_completion_note(tmp_path) -> None:
    """P1-1 live defect: the completion-pending write must not clobber intake notes."""

    lead_root = tmp_path / "lead-sessions"
    lead_root.mkdir()
    _write_lead_log(lead_root, LEAD_SESSION_ID, cwd=str(tmp_path))
    evidence = RecordingEvidence()
    service, _acp, _evidence, store = _build_service(
        tmp_path, lead_root=lead_root, evidence=evidence
    )
    try:
        service.start()
        intake = "Intake description that must survive completion"
        task = _create(service, notes=intake, lead_session_id=LEAD_SESSION_ID)
        service.complete_task(task.task_id, result_state="no_flag", note="outcome note")
        completed = store.require_task(task.task_id)
        assert completed.status is TaskStatus.COMPLETED
        assert completed.notes == intake
        assert completed.completion_note == "outcome note"
    finally:
        service.shutdown()
        store.close()


def test_complete_task_does_not_double_ingest_when_already_ingested(tmp_path) -> None:
    lead_root = tmp_path / "lead-sessions"
    lead_root.mkdir()
    _write_lead_log(lead_root, LEAD_SESSION_ID, cwd=str(tmp_path))
    evidence = RecordingEvidence()
    service, _acp, _evidence, store = _build_service(
        tmp_path, lead_root=lead_root, evidence=evidence
    )
    try:
        service.start()
        task = _create(service, lead_session_id=LEAD_SESSION_ID)
        service.ingest_session_log(task.task_id, source="lead")
        assert len(evidence.ingest_calls) == 1
        service.complete_task(task.task_id, result_state="no_flag")
        assert len(evidence.ingest_calls) == 1
        assert len(_events(evidence, "evidence_ingested")) == 1
    finally:
        service.shutdown()
        store.close()


def test_complete_task_auto_ingests_lead_after_worker_ingest(tmp_path) -> None:
    """A prior Worker-log ingest must not suppress the bound Lead-session ingest."""

    lead_root = tmp_path / "lead-sessions"
    lead_root.mkdir()
    write_session_log(
        lead_root / "lead-slug" / LEAD_SESSION_ID / "session.v4.jsonl.zstd",
        [
            session_header(LEAD_SESSION_ID, cwd=str(tmp_path)),
            *standard_session(session_id=LEAD_SESSION_ID)[1:],
        ],
        frames=3,
    )
    config = SolverConfig(root=tmp_path, capture_mode="fake")
    paths = config.ensure_layout()
    store = ManagerStore(str(paths.db_path))
    evidence = EvidenceStore(str(paths.db_path), str(paths.cas_dir))
    service = ManagerService(
        config=config,
        store=store,
        acp_factory=lambda: FakeAcp(),
        evidence=evidence,
        pipeline=FakePipeline(),
        deliverables=FakeDeliverables(tmp_path),
        capturer=FakeCapturer("ok"),
        lead_sessions_root=lead_root,
        workspace_root=tmp_path,
    )
    try:
        service.start()
        task = _create(service, lead_session_id=LEAD_SESSION_ID)
        worker_session_id = str(task.acp_session_id)
        # The Lead conversation continues after Task creation: append a new frame
        # so the post-boundary tool call exists (pre-Task records must be excluded).
        _append_lead_records(
            lead_root,
            LEAD_SESSION_ID,
            [
                tool_call(
                    9,
                    900,
                    "call-lead-post-boundary",
                    "mcp__ctf-exec__ctf_exec",
                    {"tool_id": "strings", "argv": ["challenge.txt"]},
                )
            ],
        )
        # Ingest only the shell Worker session's own (stub) log first.
        write_session_log(
            config.session_log_root
            / "worker-slug"
            / worker_session_id
            / "session.v4.jsonl.zstd",
            [
                session_header(worker_session_id, cwd=task.workspace_path),
                tool_call(1, 2, "call-worker", "worker-stub-tool", {"a": 1}),
            ],
            frames=2,
        )
        service.ingest_session_log(task.task_id, source="worker")
        worker_calls = evidence.list_events(task_id=task.task_id, event_type="tool_call")
        assert [event["payload"]["tool_name"] for event in worker_calls] == ["worker-stub-tool"]

        service.complete_task(task.task_id, result_state="no_flag")

        ingested = evidence.list_events(task_id=task.task_id, event_type="evidence_ingested")
        sources = {
            (event["payload"]["session_id"], event["payload"].get("source"))
            for event in ingested
        }
        assert (worker_session_id, "worker") in sources
        assert (LEAD_SESSION_ID, "lead") in sources
        # The chain now also contains the Lead session's executed tool calls, not
        # only the Worker stub's records.
        tool_calls = evidence.list_events(task_id=task.task_id, event_type="tool_call")
        lead_calls = [event for event in tool_calls if event["session_id"] == LEAD_SESSION_ID]
        assert lead_calls
        assert {
            event["payload"]["tool_name"] for event in lead_calls
        } >= {"mcp__ctf-exec__ctf_exec"}
        assert store.require_task(task.task_id).status is TaskStatus.COMPLETED
    finally:
        service.shutdown()
        store.close()


def test_complete_task_fails_closed_when_lead_ingest_fails(tmp_path) -> None:
    lead_root = tmp_path / "lead-sessions"
    lead_root.mkdir()
    log_path = lead_root / "lead-slug" / LEAD_SESSION_ID / "session.v4.jsonl.zstd"
    _write_lead_log(lead_root, LEAD_SESSION_ID, cwd=str(tmp_path))
    evidence = RecordingEvidence()
    service, _acp, _evidence, store = _build_service(
        tmp_path, lead_root=lead_root, evidence=evidence
    )
    try:
        service.start()
        task = _create(service, lead_session_id=LEAD_SESSION_ID)
        log_path.unlink()
        with pytest.raises(StateError):
            service.complete_task(task.task_id, result_state="no_flag")
        assert evidence.ingest_calls == []
        assert _events(evidence, "task_completed") == []
        current = store.require_task(task.task_id)
        assert current.status is TaskStatus.RUNNING
        assert current.completion_note == ""
        # allow_missing_session_log stays an explicit escape hatch and does not
        # trigger the automatic Lead ingestion.
        result = service.complete_task(
            task.task_id, result_state="no_flag", allow_missing_session_log=True
        )
        assert result["status"] == TaskStatus.COMPLETED.value
        assert evidence.ingest_calls == []
    finally:
        service.shutdown()
        store.close()


def test_worker_only_completion_requires_ingest_as_before(tmp_path) -> None:
    evidence = RecordingEvidence()
    service, _acp, _evidence, store = _build_service(tmp_path, evidence=evidence)
    try:
        service.start()
        task = _create(service)
        with pytest.raises(StateError, match="no ingested session log"):
            service.complete_task(task.task_id, result_state="no_flag")
        assert evidence.ingest_calls == []
        assert store.require_task(task.task_id).status is TaskStatus.RUNNING
        result = service.complete_task(
            task.task_id, result_state="no_flag", allow_missing_session_log=True
        )
        assert result["status"] == TaskStatus.COMPLETED.value
        assert evidence.ingest_calls == []
    finally:
        service.shutdown()
        store.close()


def test_take_screenshot_derives_latest_tool_step(tmp_path) -> None:
    evidence = RecordingEvidence()
    service, _acp, _evidence, store = _build_service(tmp_path, evidence=evidence)
    try:
        service.start()
        task = _create(service)
        # No recorded tool call yet: the screenshot stays honestly unbound.
        assert service.take_screenshot(task.task_id).step_id is None
        evidence.append_event(
            task_id=task.task_id,
            source="worker",
            event_type="tool_call",
            payload={"turn": 1, "step": 2, "name": "shell"},
        )
        assert service.take_screenshot(task.task_id).step_id == "turn1-step2"
        evidence.append_event(
            task_id=task.task_id,
            source="worker",
            event_type="tool_call",
            payload={"turn": 3, "step": 7, "name": "shell"},
        )
        derived = service.take_screenshot(task.task_id)
        assert derived.step_id == "turn3-step7"
        screenshot_event = _events(evidence, "screenshot_captured")[-1]
        assert screenshot_event["payload"]["step_id"] == "turn3-step7"
        # An explicit step id always wins and is still validated.
        explicit = service.take_screenshot(task.task_id, step_id="step-42")
        assert explicit.step_id == "step-42"
        with pytest.raises(ValueError):
            service.take_screenshot(task.task_id, step_id="not a step")
    finally:
        service.shutdown()
        store.close()


def test_lead_bound_screenshot_is_owned_by_the_lead_session(tmp_path) -> None:
    """P0-2: a Lead-bound screenshot belongs to the Lead session, never the Worker."""

    lead_root = tmp_path / "lead-sessions"
    lead_root.mkdir()
    _write_lead_log(lead_root, LEAD_SESSION_ID, cwd=str(tmp_path))
    capturer = FakeWindowCapturer("ok", target_pid=4321)
    service, _acp, evidence, store = _build_service(
        tmp_path, lead_root=lead_root, capturer=capturer
    )
    try:
        service.start()
        task = _create(service, lead_session_id=LEAD_SESSION_ID)
        assert store.get_lead_binding(task.task_id) is not None
        record = service.take_screenshot(task.task_id)
        # Ownership: the Lead session, not the shell Worker / Worker ACP session.
        assert record.worker_id is None
        assert record.session_id == LEAD_SESSION_ID
        # Default scope is the real-window target, never the desktop.
        assert record.scope == "window"
        assert record.status is CaptureStatus.OK
        assert capturer.calls == [
            {"scope": "window", "workdir": task.workspace_path}
        ]
        # Record and event ownership must match exactly.
        event = _events(evidence, "screenshot_captured")[-1]
        assert event["worker_id"] is None
        assert event["session_id"] == LEAD_SESSION_ID
        payload = event["payload"]
        assert payload["screenshot_id"] == record.screenshot_id
        assert payload["capture_method"] == "real-window"
        assert payload["target_pid"] == 4321
        assert payload["scope"] == "window"
        assert payload["status"] == "ok"
        assert payload["session_id"] == LEAD_SESSION_ID
        assert payload["worker_id"] is None
        assert payload["step_id"] is None
        assert payload["sha256"] == record.sha256 and payload["sha256"]
        assert payload["width"] == 96 and payload["height"] == 64
        assert payload["captured_at"] == record.captured_at
        assert payload["failure_reason"] == ""
        # Explicit real-window scopes are accepted and passed through unchanged.
        explicit = service.take_screenshot(task.task_id, scope="real-window")
        assert explicit.scope == "real-window"
        assert capturer.calls[-1] == {
            "scope": "real-window",
            "workdir": task.workspace_path,
        }
        # Other scopes are refused for a Lead-bound Task.
        with pytest.raises(ValidationError, match="unsupported screenshot scope"):
            service.take_screenshot(task.task_id, scope="screen")
    finally:
        service.shutdown()
        store.close()


def test_lead_bound_screenshot_refuses_desktop_without_any_capture(tmp_path) -> None:
    """P0-2: no silent desktop fallback for a Lead-bound Task process screenshot."""

    lead_root = tmp_path / "lead-sessions"
    lead_root.mkdir()
    _write_lead_log(lead_root, LEAD_SESSION_ID, cwd=str(tmp_path))
    capturer = FakeWindowCapturer("ok", target_pid=4321)
    service, _acp, evidence, store = _build_service(
        tmp_path, lead_root=lead_root, capturer=capturer
    )
    try:
        service.start()
        task = _create(service, lead_session_id=LEAD_SESSION_ID)
        with pytest.raises(ValidationError, match="desktop capture is refused"):
            service.take_screenshot(task.task_id, scope="desktop")
        # Refused before any capture attempt and without recording any screenshot.
        assert capturer.calls == []
        assert _events(evidence, "screenshot_captured") == []
        assert _events(evidence, "screenshot_failed") == []
        assert store.list_screenshots(task.task_id) == []
    finally:
        service.shutdown()
        store.close()


def test_worker_only_screenshot_keeps_legacy_ownership(tmp_path) -> None:
    """P0-2: a Worker-only Task keeps the existing Worker/Task ownership."""

    capturer = FakeCapturer("ok")
    service, _acp, evidence, store = _build_service(tmp_path, capturer=capturer)
    try:
        service.start()
        task = _create(service)
        worker = store.get_worker_for_task(task.task_id)
        assert worker is not None
        record = service.take_screenshot(task.task_id, step_id="step-1")
        assert record.worker_id == worker.worker_id == task.worker_id
        assert record.session_id == task.acp_session_id
        # A non-real-window capturer keeps the legacy desktop default scope.
        assert record.scope == "desktop"
        assert capturer.calls == [
            {"scope": "desktop", "workdir": task.workspace_path}
        ]
        event = _events(evidence, "screenshot_captured")[-1]
        assert event["worker_id"] == record.worker_id
        assert event["session_id"] == record.session_id
        assert event["payload"]["worker_id"] == record.worker_id
        assert event["payload"]["session_id"] == record.session_id
        assert event["payload"]["capture_method"] == "fake"
        assert event["payload"]["target_pid"] is None
        assert event["payload"]["scope"] == "desktop"
        assert event["payload"]["status"] == "ok"
    finally:
        service.shutdown()
        store.close()


def test_runtime_status_reports_lead_configuration(tmp_path) -> None:
    lead_root = tmp_path / "lead-sessions"
    service, _acp, _evidence, store = _build_service(tmp_path, lead_root=lead_root)
    try:
        status = service.runtime_status()
        assert Path(status["lead_sessions_root"]).resolve() == lead_root.resolve()
        limits = status["round1_limits"]
        assert "connected via project-scoped workspace MCP" in limits["main_conversation_entrypoint"]
        assert (
            status["security"]["lead_session_binding"]
            == "explicit Lead session id, Manager-verified header/cwd, one-time binding"
        )
    finally:
        service.shutdown()
        store.close()


def test_service_uses_config_lead_sessions_root_by_default(tmp_path, monkeypatch) -> None:
    from_config = tmp_path / "lead-from-config"
    service, _acp, _evidence, store = _build_service(
        tmp_path, config_extra={"lead_sessions_root": str(from_config)}
    )
    try:
        assert Path(service.runtime_status()["lead_sessions_root"]).resolve() == from_config.resolve()
    finally:
        service.shutdown()
        store.close()

    from_env = tmp_path / "lead-from-env"
    monkeypatch.setenv("CTF_SOLVER_LEAD_SESSIONS_ROOT", os.fspath(from_env))
    service, _acp, _evidence, store = _build_service(tmp_path)
    try:
        assert Path(service.runtime_status()["lead_sessions_root"]).resolve() == from_env.resolve()
    finally:
        service.shutdown()
        store.close()



def test_tool_action_approval_blocks_and_unblocks_completion(tmp_path) -> None:
    """Release-UAT remediation F1: the human console can decide a tool_action
    approval, and Task completion is blocked only while it is pending."""

    service, _acp, _evidence, store = _build_service(tmp_path)
    try:
        service.start()
        task = _create(service, title="approval completion gate")
        _write_worker_log(service, str(task.acp_session_id))
        service.ingest_session_log(task.task_id, source="worker")
        approval = service.request_approval(
            task.task_id,
            action_kind="tool_action",
            details={"purpose": "UAT regression: approve the synthetic tool action"},
            ttl_s=600,
        )
        with pytest.raises(StateError):
            service.complete_task(task.task_id, result_state="no_flag")
        assert store.require_task(task.task_id).status is not TaskStatus.COMPLETED
        decided = service.confirm_approval(
            approval.approval_id,
            channel=approving_channel(service.clock, approval.action_digest),
        )
        assert decided.status.value == "approved"
        service.complete_task(task.task_id, result_state="no_flag")
        assert store.require_task(task.task_id).status is TaskStatus.COMPLETED
    finally:
        service.shutdown()
        store.close()

