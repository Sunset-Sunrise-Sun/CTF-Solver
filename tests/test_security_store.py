"""ManagerStore Round 2 security/atomicity tests (real SQLite schema 1.1)."""

from __future__ import annotations

import threading
import uuid

import pytest

from ctf_solver.core.errors import NotFoundError, StateError
from ctf_solver.core.types import (
    ApprovalRecord,
    ApprovalStatus,
    GrantRecord,
    GrantStatus,
    ImportedInput,
    TaskStatus,
    WorkerRecord,
    WorkerStatus,
)
from ctf_solver.manager.store import ManagerStore
from tests.test_security_support import (
    SYNTHETIC_PROFILE,
    approving_channel,
    build_environment,
    confirm_approval,
    new_confirmation,
    request_remote_approval,
)

HOST = "ctf-target.example"
PORT = 8443
PATH = "/api/challenge"


def _approved_remote(env):
    approval = request_remote_approval(env, host=HOST, port=PORT, path=PATH)
    decided = confirm_approval(env, approval.approval_id)
    return decided


def _grant_record(env, decided, *, grant_id: str, task_id: str | None = None) -> GrantRecord:
    target = decided.payload["target"]
    now = env.clock.now_ms()
    return GrantRecord(
        grant_id=grant_id,
        task_id=task_id or decided.task_id,
        competition_profile=decided.payload["profile"],
        host=target["host"],
        port=target["port"],
        protocol=target["protocol"],
        method=target["method"],
        path_prefix=target["path"],
        expires_at=now + 60_000,
        max_calls=2,
        approver=decided.confirmation_os_user,
        created_at=now,
        approval_id=decided.approval_id,
        confirmation_id=decided.confirmation_id,
        confirmation_os_user=decided.confirmation_os_user,
    )


# ---------------------------------------------------------------------------
# Approval confirmation persistence
# ---------------------------------------------------------------------------


def test_record_approval_confirmation_persists_all_fields(tmp_path) -> None:
    env = build_environment(tmp_path)
    try:
        approval = request_remote_approval(env)
        confirmation = new_confirmation(
            digest=approval.action_digest,
            os_user="console-owner",
            confirmed_at=env.clock.now_ms(),
            note="approved at the local console",
        )
        decided = env.store.record_approval_confirmation(
            approval.approval_id, approved=True, confirmation=confirmation
        )
        assert decided.status is ApprovalStatus.APPROVED
        assert decided.approver == "console-owner"
        assert decided.decided_at == env.clock.now_ms()
        assert decided.confirmation_channel == "local_console"
        assert decided.confirmation_id == confirmation.confirmation_id
        assert decided.confirmation_os_user == "console-owner"
        assert decided.confirmation_note == "approved at the local console"
        assert decided.note == "approved at the local console"

        reloaded = env.store.get_approval(approval.approval_id)
        assert reloaded is not None
        assert reloaded.confirmation_id == confirmation.confirmation_id
        assert reloaded.to_dict()["confirmation_os_user"] == "console-owner"
    finally:
        env.store.close()


def test_record_approval_confirmation_rejects_bad_confirmations(tmp_path) -> None:
    env = build_environment(tmp_path)
    try:
        approval = request_remote_approval(env)
        cases = [
            new_confirmation(digest=approval.action_digest, channel="mcp"),
            new_confirmation(digest=approval.action_digest, channel="model"),
            new_confirmation(digest=approval.action_digest, os_user=""),
            new_confirmation(digest=approval.action_digest, confirmation_id=""),
            new_confirmation(digest="b" * 64),
            new_confirmation(digest="not-a-digest"),
            object(),
        ]
        for confirmation in cases:
            with pytest.raises(StateError):
                env.store.record_approval_confirmation(
                    approval.approval_id, approved=True, confirmation=confirmation
                )
        with pytest.raises(StateError):
            env.store.record_approval_confirmation(
                approval.approval_id,
                approved="yes",  # type: ignore[arg-type]
                confirmation=new_confirmation(digest=approval.action_digest),
            )
        stored = env.store.get_approval(approval.approval_id)
        assert stored.status is ApprovalStatus.PENDING
        assert stored.approver is None
        assert env.store.consume_approval(approval.approval_id, env.clock.now_ms()) is False
    finally:
        env.store.close()


def test_record_approval_confirmation_replay_and_expiry(tmp_path) -> None:
    env = build_environment(tmp_path)
    try:
        approval = request_remote_approval(env)
        confirmation = new_confirmation(digest=approval.action_digest)
        env.store.record_approval_confirmation(
            approval.approval_id, approved=False, confirmation=confirmation
        )
        with pytest.raises(StateError):
            env.store.record_approval_confirmation(
                approval.approval_id,
                approved=True,
                confirmation=new_confirmation(digest=approval.action_digest),
            )
        assert env.store.get_approval(approval.approval_id).status is ApprovalStatus.REJECTED

        expiring = request_remote_approval(env, ttl_s=5)
        env.clock.advance(6_000)
        with pytest.raises(StateError):
            env.store.record_approval_confirmation(
                expiring.approval_id,
                approved=True,
                confirmation=new_confirmation(digest=expiring.action_digest),
            )
        stored = env.store.get_approval(expiring.approval_id)
        assert stored.status is ApprovalStatus.EXPIRED
        assert stored.approver is None
    finally:
        env.store.close()


# ---------------------------------------------------------------------------
# Consumption atomicity
# ---------------------------------------------------------------------------


def test_consume_approval_requires_human_confirmation_fields(tmp_path) -> None:
    env = build_environment(tmp_path)
    try:
        approval = request_remote_approval(env)
        env.store.conn.execute(
            "UPDATE approvals SET status = 'approved', approver = 'model'"
            " WHERE approval_id = ?",
            (approval.approval_id,),
        )
        assert env.store.consume_approval(approval.approval_id, env.clock.now_ms()) is False
        assert env.store.get_approval(approval.approval_id).consumed_at is None

        confirmed = request_remote_approval(env)
        decided = confirm_approval(env, confirmed.approval_id)
        assert decided.confirmation_id
        assert env.store.consume_approval(confirmed.approval_id, env.clock.now_ms()) is True
        assert env.store.consume_approval(confirmed.approval_id, env.clock.now_ms()) is False
    finally:
        env.store.close()


def test_consume_approval_rejects_expired_and_pending(tmp_path) -> None:
    env = build_environment(tmp_path)
    try:
        pending = request_remote_approval(env)
        assert env.store.consume_approval(pending.approval_id, env.clock.now_ms()) is False

        expiring = request_remote_approval(env, ttl_s=5)
        decided = confirm_approval(env, expiring.approval_id)
        assert decided.status is ApprovalStatus.APPROVED
        env.clock.advance(6_000)
        assert env.store.consume_approval(expiring.approval_id, env.clock.now_ms()) is False
        assert env.store.get_approval(expiring.approval_id).consumed_at is None
    finally:
        env.store.close()


def test_two_concurrent_consume_attempts_only_one_succeeds(tmp_path) -> None:
    env = build_environment(tmp_path)
    try:
        approval = request_remote_approval(env)
        confirm_approval(env, approval.approval_id)
        attempts = 8
        barrier = threading.Barrier(attempts)
        results: list[bool] = []

        def consume() -> None:
            barrier.wait()
            results.append(
                env.store.consume_approval(approval.approval_id, env.clock.now_ms())
            )

        threads = [threading.Thread(target=consume) for _ in range(attempts)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        assert len(results) == attempts
        assert results.count(True) == 1
        assert results.count(False) == attempts - 1
    finally:
        env.store.close()


def test_atomic_grant_creation_across_connections_only_one_winner(tmp_path) -> None:
    env = build_environment(tmp_path)
    second_store = ManagerStore(str(env.config.paths.db_path), clock=env.clock)
    try:
        decided = _approved_remote(env)
        grant_one = _grant_record(env, decided, grant_id="grant-race01")
        grant_two = _grant_record(env, decided, grant_id="grant-race02")
        barrier = threading.Barrier(2)
        results: dict[str, bool] = {}

        def attempt(name: str, store: ManagerStore, grant: GrantRecord) -> None:
            barrier.wait()
            results[name] = store.create_grant_from_approval(
                decided.approval_id, grant, env.clock.now_ms()
            )

        threads = [
            threading.Thread(target=attempt, args=("one", env.store, grant_one)),
            threading.Thread(target=attempt, args=("two", second_store, grant_two)),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        assert len(results) == 2
        assert sorted(results.values()) == [False, True]
        grants = env.store.list_grants(task_id=decided.task_id)
        assert len(grants) == 1
        assert env.store.get_approval(decided.approval_id).consumed_at is not None
    finally:
        second_store.close()
        env.store.close()


# ---------------------------------------------------------------------------
# Row mapping and unrelated Round 1 behaviour
# ---------------------------------------------------------------------------


def test_approval_and_grant_rows_map_confirmation_columns(tmp_path) -> None:
    env = build_environment(tmp_path)
    try:
        decided = _approved_remote(env)
        legacy = GrantRecord(
            grant_id=f"grant-{uuid.uuid4().hex[:8]}",
            task_id=decided.task_id,
            competition_profile=SYNTHETIC_PROFILE,
            host=HOST,
            port=PORT,
            protocol="https",
            method="POST",
            path_prefix=PATH,
            expires_at=env.clock.now_ms() + 10_000,
            max_calls=1,
            approver="console-owner",
            created_at=env.clock.now_ms(),
            approval_id=decided.approval_id,
            confirmation_id=decided.confirmation_id,
            confirmation_os_user=decided.confirmation_os_user,
        )
        env.store.create_grant(legacy)
        loaded = env.store.get_grant(legacy.grant_id)
        assert loaded is not None
        assert loaded.approval_id == decided.approval_id
        assert loaded.confirmation_id == decided.confirmation_id
        assert loaded.confirmation_os_user == decided.confirmation_os_user
        assert loaded.status is GrantStatus.ACTIVE
    finally:
        env.store.close()


def test_get_worker_by_session(tmp_path) -> None:
    env = build_environment(tmp_path)
    try:
        now = env.clock.now_ms()
        worker = WorkerRecord(
            worker_id="w-security01",
            task_id=env.task.task_id,
            acp_session_id="session-synthetic-01",
            workspace_path=env.task.workspace_path,
            status=WorkerStatus.READY,
            worker_token="synthetic-token",
            created_at=now,
            updated_at=now,
        )
        env.store.create_worker(worker)
        assert env.store.get_worker_by_session("session-synthetic-01").worker_id == "w-security01"
        assert env.store.get_worker_by_session("session-unknown") is None
        assert env.store.get_worker_by_session("") is None
        assert env.store.get_worker_by_session(None) is None  # type: ignore[arg-type]
    finally:
        env.store.close()


def test_task_inputs_upsert_and_list(tmp_path) -> None:
    env = build_environment(tmp_path)
    try:
        first = ImportedInput(
            rel_path="challenge.zip",
            sha256="a" * 64,
            size=123,
            media_type="application/zip",
            source_rel_path="uploads/challenge.zip",
            imported_at=env.clock.now_ms(),
        )
        second = {
            "rel_path": "notes/readme.txt",
            "sha256": "b" * 64,
            "size": 7,
            "media_type": "text/plain",
            "source_rel_path": "uploads/readme.txt",
            "imported_at": env.clock.now_ms(),
        }
        env.store.record_task_inputs(env.task.task_id, [first, second])
        listed = env.store.list_task_inputs(env.task.task_id)
        assert [item.rel_path for item in listed] == ["challenge.zip", "notes/readme.txt"]
        assert listed[0].sha256 == "a" * 64
        assert listed[1].source_rel_path == "uploads/readme.txt"

        updated = ImportedInput(
            rel_path="challenge.zip",
            sha256="c" * 64,
            size=456,
            media_type="application/zip",
            source_rel_path="uploads/challenge-v2.zip",
            imported_at=env.clock.now_ms() + 1,
        )
        env.store.record_task_inputs(env.task.task_id, [updated])
        listed = env.store.list_task_inputs(env.task.task_id)
        assert len(listed) == 2
        assert listed[0].sha256 == "c" * 64
        assert listed[0].size == 456
        assert listed[0].source_rel_path == "uploads/challenge-v2.zip"

        assert env.store.list_task_inputs("t-unknown") == []
        with pytest.raises(NotFoundError):
            env.store.record_task_inputs("t-unknown", [first])
    finally:
        env.store.close()


def test_service_emits_frozen_events_into_real_evidence_store(tmp_path) -> None:
    """The real SQLite evidence chain accepts the approval/grant event payloads."""

    from ctf_solver.evidence.store import EvidenceStore
    from ctf_solver.manager.approval_grant_service import ApprovalGrantService

    env = build_environment(tmp_path)
    evidence = EvidenceStore(
        str(env.config.paths.db_path), str(env.config.paths.cas_dir), clock=env.clock
    )
    service = ApprovalGrantService(env.store, evidence, env.clock, env.config)
    try:
        approval = service.request_approval(
            env.task.task_id,
            action_kind="remote_target",
            details={
                "target": {
                    "host": HOST,
                    "port": PORT,
                    "protocol": "https",
                    "method": "POST",
                    "path": PATH,
                },
                "profile": SYNTHETIC_PROFILE,
            },
            ttl_s=600,
        )
        channel = approving_channel(env.clock, approval.action_digest)
        decided = service.confirm_approval(approval.approval_id, channel=channel)
        grant = service.create_grant_from_approval(
            approval.approval_id,
            competition_profile=decided.payload["profile"],
            host=decided.payload["target"]["host"],
            port=decided.payload["target"]["port"],
            protocol=decided.payload["target"]["protocol"],
            method=decided.payload["target"]["method"],
            path_prefix=decided.payload["target"]["path"],
        )
        service.revoke_grant(grant.grant_id)

        events = evidence.list_events(task_id=env.task.task_id)
        assert [event["event_type"] for event in events] == [
            "approval_requested",
            "approval_decided",
            "grant_created",
            "grant_revoked",
        ]
        head_seq, head_hash = evidence.chain_head()
        assert head_seq == 4
        assert len(head_hash) == 64
        decided_event = events[1]
        assert decided_event["payload"]["approved"] is True
        assert decided_event["payload"]["approver"] == "human-owner"
        assert events[2]["payload"]["grant_id"] == grant.grant_id
        assert service.event_errors == []
    finally:
        evidence.close()
        env.store.close()


def test_round_one_store_behaviour_remains_intact(tmp_path) -> None:
    env = build_environment(tmp_path)
    try:
        store = env.store
        assert store.require_task(env.task.task_id).task_id == env.task.task_id
        store.set_task_status(env.task.task_id, TaskStatus.QUEUED)
        assert [task.task_id for task in store.list_queued()] == [env.task.task_id]
        assert store.count_queued() == 1
        store.record_execution(
            {
                "execution_id": "exec-security01",
                "task_id": env.task.task_id,
                "worker_id": "w-security01",
                "step_id": "step-1",
                "tool_name": "strings",
                "cwd": env.task.workspace_path,
                "tier": 0,
                "status": "completed",
                "started_at": env.clock.now_ms(),
                "request": {"tool": "strings"},
                "result": {"exit_code": 0},
            }
        )
        executions = store.list_executions(env.task.task_id)
        assert executions and executions[0]["execution_id"] == "exec-security01"
        assert store.get_worker_by_token("nope") is None
    finally:
        env.store.close()
