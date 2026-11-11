"""Manager service lifecycle tests (fake ACP/evidence/pipeline/delivery/capturer)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ctf_solver.core.config import SolverConfig
from ctf_solver.core.errors import AcpError, NotFoundError, StateError, ValidationError
from ctf_solver.core.types import CaptureStatus, Category, TaskStatus
from ctf_solver.manager.service import ManagerService
from ctf_solver.manager.store import ManagerStore
from tests.support.fakes import FakeAcp, FakeCapturer, FakeDeliverables, FakeEvidence, FakePipeline


class GuardedEvidence(FakeEvidence):
    def __init__(self) -> None:
        super().__init__()
        self.saw_worker_before_session: list[bool] = []


def build_service(
    tmp_path: Path,
    *,
    acp: FakeAcp | None = None,
    capturer=None,
    pipeline: FakePipeline | None = None,
) -> tuple[ManagerService, FakeAcp, FakeEvidence, FakePipeline, FakeDeliverables, ManagerStore]:
    acp = acp or FakeAcp()
    config = SolverConfig(root=tmp_path)
    paths = config.ensure_layout()
    store = ManagerStore(str(paths.db_path))
    evidence = GuardedEvidence()
    pipeline = pipeline or FakePipeline()
    deliverables = FakeDeliverables(tmp_path)
    capturer = capturer or FakeCapturer("ok")
    service = ManagerService(
        config=config,
        store=store,
        acp_factory=lambda: acp,
        evidence=evidence,
        pipeline=pipeline,
        deliverables=deliverables,
        capturer=capturer,
    )
    return service, acp, evidence, pipeline, deliverables, store


def test_create_task_runs_through_acp_and_persists_mapping(tmp_path) -> None:
    service, acp, evidence, _pipeline, _deliverables, store = build_service(tmp_path)
    try:
        service.start()
        task = service.create_task(
            title="Synthetic web challenge",
            category="web",
            conversation_id="conv-1",
            source="synthetic-local",
            notes="description",
        )
        assert task.status is TaskStatus.RUNNING
        assert task.acp_session_id and task.worker_id
        worker = store.get_worker_for_task(task.task_id)
        assert worker is not None
        assert worker.acp_session_id == task.acp_session_id
        assert worker.workspace_path == task.workspace_path
        assert Path(task.workspace_path).is_dir()
        assert len(acp.new_session_calls) == 1
        call = acp.new_session_calls[0]
        assert Path(call["cwd"]).is_absolute()
        assert Path(call["cwd"]).resolve() == Path(task.workspace_path).resolve()
        assert call["mcp_servers"][0]["name"] == "ctf-exec"
        assert call["mcp_servers"][0]["args"] == ["-m", "ctf_solver.mcp.exec_server"]
        env_entries = call["mcp_servers"][0]["env"]
        assert isinstance(env_entries, list), "ACP session/new mcpServers env must be {name,value} entries"
        env = {entry["name"]: entry["value"] for entry in env_entries}
        assert env["CTF_SOLVER_IPC_URL"].startswith("tcp://127.0.0.1:")
        assert env["CTF_SOLVER_WORKER_TOKEN"]
        assert "PYTHONPATH" in env
        assert any(event["event_type"] == "task_created" for event in evidence.events)
        assert any(event["event_type"] == "task_started" for event in evidence.events)
    finally:
        service.shutdown()
        store.close()


def test_two_active_workers_and_third_fifo_then_promotion(tmp_path) -> None:
    service, acp, _evidence, _pipeline, _deliverables, store = build_service(tmp_path)
    try:
        service.start()
        tasks = [
            service.create_task(title=f"challenge {index}", category="misc", conversation_id="conv")
            for index in range(3)
        ]
        statuses = [task.status for task in tasks]
        assert statuses == [TaskStatus.RUNNING, TaskStatus.RUNNING, TaskStatus.QUEUED]
        assert store.count_active_slots() == 2
        assert len(acp.new_session_calls) == 2
        status = service.get_task_status(tasks[2].task_id)
        assert status["queue_position"] == 1
        # Cancel the first running Task; the queued Task must be promoted.
        result = service.cancel_task(tasks[0].task_id, reason="synthetic")
        assert result["status"] == TaskStatus.CANCELLED.value
        promoted = service.get_task(tasks[2].task_id)
        assert promoted.status is TaskStatus.RUNNING
        assert len(acp.new_session_calls) == 3
        assert len({call["cwd"] for call in acp.new_session_calls}) == 3
        assert len({call["session_id"] for call in acp.new_session_calls}) == 3
    finally:
        service.shutdown()
        store.close()


def test_worker_mapping_persisted_before_ready(tmp_path) -> None:
    acp = FakeAcp()
    observed: dict[str, object] = {}

    def hook(cwd: str, mcp_servers) -> None:
        starting = service.store.list_tasks(status=TaskStatus.STARTING.value)
        observed["starting"] = [task.task_id for task in starting]
        observed["workers_before"] = len(service.store.list_workers())
        observed["cwd"] = cwd

    acp.on_new_session = hook
    service, _acp, _evidence, _pipeline, _deliverables, store = build_service(tmp_path, acp=acp)
    try:
        service.start()
        task = service.create_task(title="t", category="misc", conversation_id="conv")
        assert observed["starting"] == [task.task_id]
        assert observed["workers_before"] == 0
        assert observed["cwd"] == task.workspace_path
        assert len(store.list_workers()) == 1
    finally:
        service.shutdown()
        store.close()


def test_failure_isolation_on_session_creation(tmp_path) -> None:
    acp = FakeAcp(fail_new_session_for={"t-fail-a"})
    service, _acp, _evidence, _pipeline, _deliverables, store = build_service(tmp_path, acp=acp)
    try:
        paths = service.config.paths
        for task_id, marker in (("t-fail-a", "marker-a"), ("t-ok-b", "marker-b")):
            workspace = paths.task_workspace(task_id)
            workspace.mkdir(parents=True, exist_ok=True)
            from ctf_solver.core.types import TaskRecord

            store.create_task(
                TaskRecord(
                    task_id=task_id,
                    conversation_id="conv",
                    title=task_id,
                    category=Category.MISC,
                    workspace_path=str(workspace),
                    status=TaskStatus.CREATED,
                    created_at=1 if marker == "marker-a" else 2,
                )
            )
            store.set_task_status(task_id, TaskStatus.QUEUED)
        service.start()
        failed = service.get_task("t-fail-a")
        ok = service.get_task("t-ok-b")
        assert failed.status is TaskStatus.FAILED
        assert ok.status is TaskStatus.RUNNING
        assert store.count_active_slots() == 1
    finally:
        service.shutdown()
        store.close()


def test_pause_keeps_slot_and_uses_acp_cancel(tmp_path) -> None:
    service, acp, _evidence, _pipeline, _deliverables, store = build_service(tmp_path)
    try:
        service.start()
        task = service.create_task(title="t", category="misc", conversation_id="conv")
        result = service.pause_task(task.task_id, reason="user pause")
        assert result["status"] == TaskStatus.PAUSED.value
        assert result["os_kill"] is False
        assert acp.cancel_calls == [task.acp_session_id]
        assert store.count_active_slots() == 1
        assert service.get_task(task.task_id).status is TaskStatus.PAUSED
    finally:
        service.shutdown()
        store.close()


def test_cancel_unconfirmed_keeps_slot_then_confirms(tmp_path) -> None:
    service, acp, _evidence, _pipeline, _deliverables, store = build_service(tmp_path)
    try:
        service.start()
        task = service.create_task(title="t", category="misc", conversation_id="conv")
        acp.close_should_fail = True
        result = service.cancel_task(task.task_id, reason="user cancel")
        assert result["status"] == TaskStatus.CANCEL_REQUESTED.value
        assert result["quiescent"] is False
        assert "close_error" in result["diagnostics"]
        assert store.count_active_slots() == 1
        assert service.get_task(task.task_id).status is TaskStatus.CANCEL_REQUESTED
        acp.close_should_fail = False
        result2 = service.cancel_task(task.task_id, reason="retry")
        assert result2["status"] == TaskStatus.CANCELLED.value
        assert result2["quiescent"] is True
        assert store.count_active_slots() == 0
    finally:
        service.shutdown()
        store.close()


def test_cancel_queued_task_frees_nothing_and_promotes(tmp_path) -> None:
    service, _acp, _evidence, _pipeline, _deliverables, store = build_service(tmp_path)
    try:
        service.start()
        tasks = [
            service.create_task(title=f"t{index}", category="misc", conversation_id="conv")
            for index in range(3)
        ]
        assert tasks[2].status is TaskStatus.QUEUED
        result = service.cancel_task(tasks[2].task_id)
        assert result["status"] == TaskStatus.CANCELLED.value
        assert service.get_task(tasks[2].task_id).status is TaskStatus.CANCELLED
        assert store.count_active_slots() == 2
    finally:
        service.shutdown()
        store.close()


def test_acp_crash_interrupts_tasks_and_frees_slots(tmp_path) -> None:
    service, acp, _evidence, _pipeline, _deliverables, store = build_service(tmp_path)
    try:
        service.start()
        tasks = [
            service.create_task(title=f"t{index}", category="misc", conversation_id="conv")
            for index in range(2)
        ]
        assert store.count_active_slots() == 2
        acp.simulate_crash()
        report = service.handle_acp_failure("synthetic crash")
        assert len(report["interrupted"]) == 2
        for task in tasks:
            assert service.get_task(task.task_id).status is TaskStatus.INTERRUPTED
        assert store.count_active_slots() == 0
    finally:
        service.shutdown()
        store.close()


def test_recovery_never_duplicates_sessions(tmp_path) -> None:
    service1, acp1, _e1, _p1, _d1, store = build_service(tmp_path)
    try:
        service1.start()
        task = service1.create_task(title="t", category="misc", conversation_id="conv")
        assert task.status is TaskStatus.RUNNING
        service1.shutdown()
        new_acp = FakeAcp()
        service2 = ManagerService(
            config=service1.config,
            store=store,
            acp_factory=lambda: new_acp,
            evidence=GuardedEvidence(),
            pipeline=FakePipeline(),
            deliverables=FakeDeliverables(tmp_path),
            capturer=FakeCapturer(),
        )
        report = service2.start()
        recovered = service2.get_task(task.task_id)
        assert recovered.status is TaskStatus.INTERRUPTED
        assert new_acp.new_session_calls == []
        assert service2.runtime_status()["active_workers"] == 0
        assert report["acp"]["ready"] is True
        service2.shutdown()
    finally:
        store.close()


def test_continue_task_never_prompts(tmp_path) -> None:
    service, acp, evidence, _pipeline, _deliverables, store = build_service(tmp_path)
    try:
        service.start()
        task = service.create_task(title="t", category="misc", conversation_id="conv")
        result = service.continue_task(task.task_id, message="继续")
        assert result["model_call_suppressed"] is True
        assert acp.prompt_calls == []
        assert any(event["event_type"] == "model_call_suppressed" for event in evidence.events)
        service.cancel_task(task.task_id)
        with pytest.raises(StateError):
            service.continue_task(task.task_id)
    finally:
        service.shutdown()
        store.close()


class FakeHumanChannel:
    """Deterministic test double for the local-console confirmation channel."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def confirm(self, *, approval_digest: str, summary: str):
        from ctf_solver.security.confirmation import HumanConfirmation

        self.calls.append({"approval_digest": approval_digest, "summary": summary})
        return HumanConfirmation(
            channel="local_console",
            os_user="human-test",
            confirmed_at=1_700_000_000_000,
            confirmation_id=f"conf-test-{len(self.calls)}",
            approval_digest=approval_digest,
            note="test",
        )

    def reject(self, *, approval_digest: str, summary: str):
        confirmation = self.confirm(approval_digest=approval_digest, summary=summary)
        return confirmation


def _remote_target_details(host: str = "127.0.0.1", port: int = 31337, profile: str = "synthetic-local"):
    return {
        "target": {
            "host": host,
            "port": port,
            "protocol": "tcp",
            "method": "GET",
            "path_prefix": "/",
        },
        "profile": profile,
        "grant_ttl_s": 600,
        "max_calls": 3,
    }


def test_approvals_grants_and_candidate_flag(tmp_path) -> None:
    service, _acp, evidence, _pipeline, _deliverables, store = build_service(tmp_path)
    try:
        service.start()
        task = service.create_task(title="t", category="misc", conversation_id="conv")
        approval = service.request_approval(
            task.task_id,
            action_kind="remote_target",
            details=_remote_target_details(),
            ttl_s=600,
        )
        assert approval.status.value == "pending"
        # The Agent/MCP cannot decide an approval at all.
        with pytest.raises(StateError):
            service.decide_approval(approval.approval_id, approved=True, approver="human-owner")
        # Only the human local-console confirmation path can approve.
        channel = FakeHumanChannel()
        approved = service.confirm_approval(approval.approval_id, channel=channel)
        assert approved.status.value == "approved"
        assert approved.confirmation_channel == "local_console"
        assert approved.confirmation_os_user == "human-test"
        assert approved.approver == "human-test"
        assert channel.calls and channel.calls[0]["approval_digest"] == approval.action_digest
        assert service.list_approvals(task_id=task.task_id)

        grant = service.create_grant_from_approval(
            approval.approval_id,
            competition_profile="synthetic-local",
            host="127.0.0.1",
            port=31337,
            protocol="tcp",
            method="GET",
            path_prefix="/",
        )
        assert grant.grant_digest
        assert grant.calls_used == 0
        assert grant.max_calls == 3
        assert grant.approval_id == approval.approval_id
        assert grant.confirmation_os_user == "human-test"
        # Replaying the approval for a second grant fails closed.
        with pytest.raises(StateError):
            service.create_grant_from_approval(
                approval.approval_id,
                competition_profile="synthetic-local",
                host="127.0.0.1",
                port=31337,
            )
        revoked = service.revoke_grant(grant.grant_id)
        assert revoked.status.value == "revoked"
        assert service.list_grants(task_id=task.task_id)

        flag = service.record_candidate_flag(task.task_id, flag="flag{synthetic}", source="local")
        assert flag["flag_state"] == "candidate"
        assert flag["submitted"] is False
        assert service.get_task(task.task_id).flag_value == "flag{synthetic}"
        flag_events = [e for e in evidence.events if e["event_type"] == "flag_candidate"]
        assert flag_events
        payload_text = json.dumps(flag_events[0]["payload"])
        assert "flag{synthetic}" not in payload_text
        assert flag["flag_sha256"] in payload_text
    finally:
        service.shutdown()
        store.close()


def test_screenshots_ok_blank_failed(tmp_path) -> None:
    for mode, expected in (("ok", CaptureStatus.OK), ("blank", CaptureStatus.BLANK), ("fail", CaptureStatus.FAILED)):
        service, _acp, evidence, _pipeline, _deliverables, store = build_service(
            tmp_path / mode, capturer=FakeCapturer(mode)
        )
        try:
            service.start()
            task = service.create_task(title="t", category="misc", conversation_id="conv")
            record = service.take_screenshot(task.task_id, step_id="step-1", scope="desktop")
            assert record.status is expected
            assert record.step_id == "step-1"
            assert record.task_id == task.task_id
            assert record.session_id == task.acp_session_id
            if expected is CaptureStatus.OK:
                assert record.sha256 and record.width == 96 and record.height == 64
                assert record.sha256 in evidence.artifacts
                assert record.failure_reason == ""
            else:
                assert record.sha256 is None
                assert record.failure_reason
            assert evidence.screenshots[-1].screenshot_id == record.screenshot_id
        finally:
            service.shutdown()
            store.close()


def test_evidence_and_delivery_delegation(tmp_path) -> None:
    service, _acp, evidence, _pipeline, deliverables, store = build_service(tmp_path)
    try:
        service.start()
        task = service.create_task(title="t", category="misc", conversation_id="conv")
        # Register the Task's real Harness-layout session log under the Manager's
        # sessions root; the model can never pass a path to ingest.
        from tests.support.session_events import standard_session
        from tests.support.zstd_fixtures import write_session_log

        session_dir = service.config.session_log_root / "fake-slug" / str(task.acp_session_id)
        session_dir.mkdir(parents=True, exist_ok=True)
        write_session_log(
            session_dir / "session.v4.jsonl.zstd",
            standard_session(session_id=str(task.acp_session_id)),
            frames=4,
        )
        report = service.ingest_session_log(task.task_id)
        assert report["appended"] == 3
        assert "path" not in report and "raw_path" not in report
        # A second worker_id that does not match the Task's Worker fails closed.
        with pytest.raises(Exception):
            service.ingest_session_log(task.task_id, worker_id="w-not-this-worker")
        exported = service.export_events(task.task_id)
        assert exported.kind == "events_jsonl"
        writeup = service.build_writeup(task.task_id)
        assert writeup.kind == "writeup"
        assert deliverables.writeups == [task.task_id]
        zipped = service.export_evidence_zip(task.task_id)
        assert zipped.kind == "evidence_zip"
        assert deliverables.zips == [task.task_id]
        status = service.get_task_status(task.task_id)
        assert status["executions"] == []
        assert status["evidence"]["chain_status"]["ok"] is True
        assert status["inputs"] == []
    finally:
        service.shutdown()
        store.close()


def test_create_task_validation_and_unknown_lookups(tmp_path) -> None:
    service, _acp, _evidence, _pipeline, _deliverables, store = build_service(tmp_path)
    try:
        service.start()
        with pytest.raises(ValidationError):
            service.create_task(title="", category="misc", conversation_id="conv")
        with pytest.raises(ValidationError):
            service.create_task(title="t", category="misc", conversation_id="")
        with pytest.raises(ValueError):
            service.create_task(title="t", category="web3", conversation_id="conv")
        with pytest.raises(NotFoundError):
            service.get_task("t-missing")
        with pytest.raises(NotFoundError):
            service.get_task_status("t-missing")
    finally:
        service.shutdown()
        store.close()


def test_runtime_status_and_shutdown_cleanup(tmp_path) -> None:
    service, acp, evidence, _pipeline, _deliverables, store = build_service(tmp_path)
    service.start()
    status = service.runtime_status()
    assert status["ipc_url"].startswith("tcp://127.0.0.1:")
    assert status["acp"]["ready"] is True
    assert status["round1_limits"]["model_calls"].startswith("blocked")
    assert status["round1_limits"]["main_conversation_entrypoint"].startswith("BLOCKED")
    service.shutdown()
    assert acp.alive is False
    assert service.ipc_url is None
    assert evidence.closed is True
    store.close()
