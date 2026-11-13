"""Release-UAT remediation F2: Lead-session task-boundary scoping tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ctf_solver.core.config import SolverConfig
from ctf_solver.core.errors import StateError, ValidationError
from ctf_solver.manager.session_logs import SessionLogError
from ctf_solver.delivery.deliverables import Deliverables
from ctf_solver.evidence.ingest import session_log_boundary
from ctf_solver.evidence.store import EvidenceStore
from ctf_solver.manager.service import ManagerService
from ctf_solver.manager.store import ManagerStore
from tests.support.fakes import FakeAcp, FakeCapturer, FakePipeline
from tests.support.session_events import session_header, standard_session, tool_call
from tests.support.zstd_fixtures import frame_bytes, jsonl_bytes, write_session_log

LEAD_SESSION_ID = "22222222-3333-4444-5555-666666666666"
PRE_CANARY = "PRE-TASK-CANARY-20261112"
POST_CANARY = "POST-BOUNDARY-CANARY-20261112"


def _lead_log(
    root: Path,
    *,
    cwd: str,
    pre_canary: str = PRE_CANARY,
) -> Path:
    records = [
        session_header(LEAD_SESSION_ID, cwd=cwd),
        *standard_session(session_id=LEAD_SESSION_ID)[1:],
        tool_call(20, 900, "call-pre-boundary", "pre-task-tool", {"canary": pre_canary}),
    ]
    path = root / "lead-slug" / LEAD_SESSION_ID / "session.v4.jsonl.zstd"
    write_session_log(path, records, frames=3)
    return path


def _append_frame(path: Path, records: list[dict]) -> None:
    path.write_bytes(path.read_bytes() + frame_bytes([jsonl_bytes(records)]))


def _build_service(tmp_path: Path, lead_root: Path):
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
        deliverables=Deliverables(evidence, paths),
        capturer=FakeCapturer("ok"),
        lead_sessions_root=lead_root,
        workspace_root=tmp_path,
    )
    return service, store, evidence


def _create(service: ManagerService):
    return service.create_task(
        title="UAT boundary fixture",
        category="misc",
        conversation_id="conv-boundary",
        lead_session_id=LEAD_SESSION_ID,
    )


def test_pre_task_lead_history_is_excluded_from_events_writeup_and_zip(tmp_path) -> None:
    lead_root = tmp_path / "lead-sessions"
    lead_root.mkdir()
    log_path = _lead_log(lead_root, cwd=str(tmp_path))
    service, store, evidence = _build_service(tmp_path, lead_root)
    try:
        service.start()
        task = _create(service)
        # The Lead conversation continues after Task creation: append a frame.
        _append_frame(
            log_path,
            [
                tool_call(
                    21,
                    901,
                    "call-post-boundary",
                    "post-boundary-tool",
                    {"canary": POST_CANARY},
                )
            ],
        )

        boundary = store.get_lead_session_boundary(task.task_id)
        assert isinstance(boundary, dict)
        assert boundary["version"] == 1
        assert boundary["payload_size"] > 0
        bound = evidence.list_events(task_id=task.task_id, event_type="lead_session_bound")
        assert bound and bound[-1]["payload"]["boundary"] == boundary

        report = service.ingest_session_log(task.task_id, source="lead")
        assert report["boundary_applied"] is True
        assert report["pre_boundary_excluded"] >= 1
        assert report["appended"] >= 1

        events = evidence.list_events(task_id=task.task_id)
        events_text = "\n".join(json.dumps(event, ensure_ascii=False) for event in events)
        assert PRE_CANARY not in events_text
        assert POST_CANARY in events_text
        tool_names = {
            event["payload"].get("tool_name")
            for event in events
            if event["event_type"] == "tool_call"
        }
        assert "post-boundary-tool" in tool_names
        assert "pre-task-tool" not in tool_names

        # The raw log remains in the local CAS for audit (pre-Task bytes included).
        from ctf_solver.evidence.zstd_frames import decode_all, iter_payload_segments

        raw = evidence.read_artifact(report["raw_sha256"])
        raw_payload = b"".join(
            segment.payload for segment in iter_payload_segments(decode_all(raw))
        )
        assert PRE_CANARY.encode() in raw_payload
        assert PRE_CANARY.encode() not in events_text.encode()

        writeup = service.build_writeup(task.task_id)
        writeup_text = Path(writeup.path).read_text(encoding="utf-8")
        assert PRE_CANARY not in writeup_text
        assert POST_CANARY in writeup_text or "post-boundary-tool" in writeup_text

        zip_info = service.export_evidence_zip(task.task_id)
        import zipfile

        with zipfile.ZipFile(zip_info.path) as archive:
            for name in archive.namelist():
                if name.endswith(".jsonl") or name.endswith(".md"):
                    text = archive.read(name).decode("utf-8", errors="ignore")
                    assert PRE_CANARY not in text
        # Chain stays intact after filtered ingestion.
        assert evidence.chain_status().ok is True
    finally:
        service.shutdown()
        store.close()


def test_duplicate_ingest_does_not_reintroduce_pre_task_history(tmp_path) -> None:
    lead_root = tmp_path / "lead-sessions"
    lead_root.mkdir()
    log_path = _lead_log(lead_root, cwd=str(tmp_path))
    service, store, evidence = _build_service(tmp_path, lead_root)
    try:
        service.start()
        task = _create(service)
        _append_frame(
            log_path,
            [tool_call(22, 902, "call-post", "post-tool", {"canary": POST_CANARY})],
        )
        first_boundary = store.get_lead_session_boundary(task.task_id)
        first = service.ingest_session_log(task.task_id, source="lead")
        second = service.ingest_session_log(task.task_id, source="lead")
        assert second["appended"] == 0
        assert second["skipped_duplicates"] >= 1
        events = evidence.list_events(task_id=task.task_id)
        text = "\n".join(json.dumps(event, ensure_ascii=False) for event in events)
        assert PRE_CANARY not in text
        assert events
        # Boundary is stable across repeated ingestion.
        assert store.get_lead_session_boundary(task.task_id) == first_boundary
        assert first["appended"] >= 1
    finally:
        service.shutdown()
        store.close()


def test_rotated_or_truncated_lead_log_fails_closed(tmp_path) -> None:
    lead_root = tmp_path / "lead-sessions"
    lead_root.mkdir()
    log_path = _lead_log(lead_root, cwd=str(tmp_path))
    service, store, evidence = _build_service(tmp_path, lead_root)
    try:
        service.start()
        task = _create(service)
        boundary = store.get_lead_session_boundary(task.task_id)
        assert boundary is not None
        raw = log_path.read_bytes()
        # Truncated: fewer compressed bytes than the recorded snapshot.
        log_path.write_bytes(raw[: max(1, len(raw) // 2)])
        with pytest.raises((ValidationError, SessionLogError)):
            service.ingest_session_log(task.task_id, source="lead")
        # Rewritten prefix (rotation / tampering).
        rewritten = bytearray(raw)
        rewritten[0] ^= 0xFF
        log_path.write_bytes(bytes(rewritten))
        with pytest.raises((ValidationError, SessionLogError)):
            service.ingest_session_log(task.task_id, source="lead")
    finally:
        service.shutdown()
        store.close()


def test_legacy_binding_without_boundary_fails_closed(tmp_path) -> None:
    lead_root = tmp_path / "lead-sessions"
    lead_root.mkdir()
    _lead_log(lead_root, cwd=str(tmp_path))
    service, store, evidence = _build_service(tmp_path, lead_root)
    try:
        service.start()
        # Simulate a Task bound by an older release: binding exists, no boundary
        # event. Ingestion must refuse instead of importing the whole history.
        task = service.create_task(
            title="legacy-bound-without-boundary",
            category="misc",
            conversation_id="conv",
        )
        store.bind_lead_session(
            task_id=task.task_id,
            session_id=LEAD_SESSION_ID,
            bound_by="lead",
            log_sha256=None,
        )
        with pytest.raises(StateError):
            service.ingest_session_log(task.task_id, source="lead")
    finally:
        service.shutdown()
        store.close()


def test_boundary_payload_is_validated_before_ingest(tmp_path) -> None:
    lead_root = tmp_path / "lead-sessions"
    lead_root.mkdir()
    log_path = _lead_log(lead_root, cwd=str(tmp_path))
    raw = log_path.read_bytes()
    boundary = session_log_boundary(raw)
    service, store, evidence = _build_service(tmp_path, lead_root)
    try:
        service.start()
        task = _create(service)
        # Direct evidence API: wrong version / size / digest all fail closed.
        with pytest.raises(ValidationError):
            evidence.ingest_session_log_bytes(
                task_id=task.task_id,
                worker_id=None,
                session_id=LEAD_SESSION_ID,
                data=raw,
                source_id="session:boundary-test",
                boundary={**boundary, "version": 99},
            )
        with pytest.raises(ValidationError):
            evidence.ingest_session_log_bytes(
                task_id=task.task_id,
                worker_id=None,
                session_id=LEAD_SESSION_ID,
                data=raw,
                source_id="session:boundary-test",
                boundary={**boundary, "payload_size": len(raw) + 1},
            )
        with pytest.raises(ValidationError):
            evidence.ingest_session_log_bytes(
                task_id=task.task_id,
                worker_id=None,
                session_id=LEAD_SESSION_ID,
                data=raw,
                source_id="session:boundary-test",
                boundary={**boundary, "payload_sha256": "0" * 64},
            )
    finally:
        service.shutdown()
        store.close()



