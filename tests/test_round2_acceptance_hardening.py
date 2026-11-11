"""Final acceptance hardening: dual-record approval tamper attacks.

These tests use the **real** SQLite ManagerStore and the real append-only
EvidenceStore hash chain (not mocks) to reproduce the reported P0 attack:
rewrite ``approvals.payload_json`` + ``action_digest`` together and try to mint a
grant for a different port. The independent ``approval_decided`` event must make
the tampering detectable, and every failure path must fail closed.
"""

from __future__ import annotations

import json
import threading

import pytest

from ctf_solver.core.canonical import canonical_json
from ctf_solver.core.config import SolverConfig
from ctf_solver.core.errors import StateError
from ctf_solver.core.types import Category, TaskRecord, TaskStatus
from ctf_solver.evidence.store import EvidenceStore
from ctf_solver.manager.approval_grant_service import (
    ApprovalGrantService,
    canonical_remote_target_details,
)
from ctf_solver.manager.store import ManagerStore
from ctf_solver.policy.models import action_digest
from tests.test_security_support import (
    FixedClock,
    approving_channel,
    SYNTHETIC_PROFILE,
)

ORIGINAL_PORT = 8443
ATTACK_PORT = 9443


class _Environment:
    def __init__(self, tmp_path):
        self.clock = FixedClock()
        self.config = SolverConfig(root=tmp_path)
        paths = self.config.ensure_layout()
        self.store = ManagerStore(str(paths.db_path), clock=self.clock)
        self.evidence = EvidenceStore(
            str(paths.db_path), str(paths.cas_dir), clock=self.clock
        )
        self.service = ApprovalGrantService(
            self.store, self.evidence, self.clock, self.config
        )
        self.task = self._task("t-hardening01")
        self.other = self._task("t-hardening02")

    def _task(self, task_id: str) -> TaskRecord:
        return self.store.create_task(
            TaskRecord(
                task_id=task_id,
                conversation_id="conv-hardening",
                title="Dual-record tamper fixture",
                category=Category.MISC,
                workspace_path=str(self.config.paths.task_workspace(task_id)),
                scope_profile=SYNTHETIC_PROFILE,
                status=TaskStatus.CREATED,
                created_at=self.clock.now_ms(),
                updated_at=self.clock.now_ms(),
            )
        )

    def close(self):
        self.evidence.close()
        self.store.close()


@pytest.fixture()
def env(tmp_path):
    environment = _Environment(tmp_path)
    try:
        yield environment
    finally:
        environment.close()


def _request(environment: _Environment, *, port: int = ORIGINAL_PORT, task_id: str | None = None):
    return environment.service.request_approval(
        task_id or environment.task.task_id,
        action_kind="remote_target",
        details={
            "target": {
                "host": "ctf-target.example",
                "port": port,
                "protocol": "https",
                "method": "POST",
                "path_prefix": "/api/challenge",
            },
            "profile": SYNTHETIC_PROFILE,
            "grant_ttl_s": 120,
            "max_calls": 3,
        },
        ttl_s=600,
    )


def _approve(environment: _Environment, approval_id: str):
    approval = environment.store.get_approval(approval_id)
    channel = approving_channel(environment.clock, approval.action_digest)
    return environment.service.confirm_approval(approval_id, channel=channel)


def _grant(environment: _Environment, approval, *, port: int = ORIGINAL_PORT):
    payload = approval.payload
    return environment.service.create_grant_from_approval(
        approval.approval_id,
        competition_profile=payload["profile"],
        host=payload["target"]["host"],
        port=port,
        protocol=payload["target"]["protocol"],
        method=payload["target"]["method"],
        path_prefix=payload["target"]["path_prefix"],
    )


def _tampered_payload(environment: _Environment, approval, *, port: int = ATTACK_PORT):
    """A fully self-consistent payload+digest for a different port."""

    payload = canonical_remote_target_details(
        task_id=approval.task_id,
        host=approval.payload["target"]["host"],
        port=port,
        protocol=approval.payload["target"]["protocol"],
        method=approval.payload["target"]["method"],
        path_prefix=approval.payload["target"]["path_prefix"],
        competition_profile=approval.payload["profile"],
        grant_ttl_s=approval.payload["grant_ttl_s"],
        max_calls=approval.payload["max_calls"],
    )
    return payload, action_digest("remote_target", payload)


def _update_row(environment: _Environment, approval_id: str, **fields):
    if not fields:
        return
    assignments = ", ".join(f"{name} = ?" for name in fields)
    environment.store.conn.execute(
        f"UPDATE approvals SET {assignments} WHERE approval_id = ?",
        [*fields.values(), approval_id],
    )
    environment.store.conn.commit()


def test_complete_payload_and_digest_rewrite_is_rejected(env) -> None:
    """The reported P0: approve 8443, rewrite row payload+digest to 9443."""

    approval = _request(env)
    decided = _approve(env, approval.approval_id)
    assert decided.status.value == "approved"
    payload, digest = _tampered_payload(env, decided)
    _update_row(
        env,
        approval.approval_id,
        payload_json=canonical_json(payload),
        action_digest=digest,
    )
    rewritten = env.store.get_approval(approval.approval_id)
    # The row is internally self-consistent...
    assert rewritten.payload["target"]["port"] == ATTACK_PORT
    assert rewritten.action_digest == digest
    # ...but the independent human-decision event still binds 8443.
    with pytest.raises(StateError):
        _grant(env, rewritten, port=ATTACK_PORT)
    assert env.store.list_grants(task_id=env.task.task_id) == []
    assert env.store.get_approval(approval.approval_id).consumed_at is None
    # The original approved scope is no longer usable either after the row rewrite.
    with pytest.raises(StateError):
        _grant(env, rewritten, port=ORIGINAL_PORT)
    grants = env.store.list_grants(task_id=env.task.task_id)
    assert grants == []


@pytest.mark.parametrize("change", ["payload_only", "digest_only", "confirmation_id", "confirmation_os_user"])
def test_isolated_approval_row_field_tampering_is_rejected(env, change: str) -> None:
    approval = _request(env)
    decided = _approve(env, approval.approval_id)
    if change == "payload_only":
        payload, _ = _tampered_payload(env, decided)
        _update_row(env, approval.approval_id, payload_json=canonical_json(payload))
    elif change == "digest_only":
        _update_row(env, approval.approval_id, action_digest="c" * 64)
    elif change == "confirmation_id":
        _update_row(env, approval.approval_id, confirmation_id="forged-confirmation-id")
    elif change == "confirmation_os_user":
        _update_row(env, approval.approval_id, confirmation_os_user="attacker-user")
    with pytest.raises(StateError):
        _grant(env, env.store.get_approval(approval.approval_id))
    assert env.store.list_grants() == []
    assert env.store.get_approval(approval.approval_id).consumed_at is None


def test_cross_task_row_rewrite_is_rejected(env) -> None:
    approval = _request(env)
    decided = _approve(env, approval.approval_id)
    payload, digest = _tampered_payload(env, decided)
    payload["task_id"] = env.other.task_id
    digest = action_digest("remote_target", payload)
    _update_row(
        env,
        approval.approval_id,
        task_id=env.other.task_id,
        payload_json=canonical_json(payload),
        action_digest=digest,
    )
    with pytest.raises(StateError):
        _grant(env, env.store.get_approval(approval.approval_id))
    assert env.store.list_grants() == []


def _drop_append_only_triggers(env: _Environment) -> None:
    """Simulate an attacker with direct SQLite access bypassing SQL triggers."""

    env.evidence.connection.execute("DROP TRIGGER IF EXISTS events_no_update")
    env.evidence.connection.execute("DROP TRIGGER IF EXISTS events_no_delete")
    env.evidence.connection.commit()


def test_deleted_decision_event_breaks_chain_and_is_rejected(env) -> None:
    approval = _request(env)
    decided = _approve(env, approval.approval_id)
    _drop_append_only_triggers(env)
    env.evidence.connection.execute(
        "DELETE FROM events WHERE event_type = 'approval_decided' AND task_id = ?",
        (decided.task_id,),
    )
    env.evidence.connection.commit()
    with pytest.raises(StateError):
        _grant(env, decided)
    assert env.store.get_approval(approval.approval_id).consumed_at is None
    assert env.store.list_grants() == []
    assert env.evidence.chain_status().ok is False


def test_modified_decision_event_is_detected_by_hash_chain(env) -> None:
    approval = _request(env)
    decided = _approve(env, approval.approval_id)
    row = env.evidence.connection.execute(
        "SELECT record_id, payload_json FROM events WHERE event_type = 'approval_decided'"
        " AND task_id = ?",
        (decided.task_id,),
    ).fetchone()
    assert row is not None
    payload = json.loads(row["payload_json"])
    payload["action_digest"] = "d" * 64
    _drop_append_only_triggers(env)
    env.evidence.connection.execute(
        "UPDATE events SET payload_json = ? WHERE record_id = ?",
        (json.dumps(payload), row["record_id"]),
    )
    env.evidence.connection.commit()
    assert env.evidence.chain_status().ok is False
    with pytest.raises(StateError):
        _grant(env, decided)
    assert env.store.list_grants() == []


def test_duplicate_conflicting_decision_events_are_rejected(env) -> None:
    approval = _request(env)
    decided = _approve(env, approval.approval_id)
    env.evidence.append_event(
        task_id=decided.task_id,
        worker_id=None,
        session_id=None,
        source="manager",
        source_id="manager:approval_decided:conflict",
        event_type="approval_decided",
        payload={
            "approval_id": decided.approval_id,
            "task_id": decided.task_id,
            "action_kind": decided.action_kind,
            "action_digest": decided.action_digest,
            "approved": True,
            "approver": "conflicting-user",
            "confirmation_channel": "local_console",
            "confirmation_id": "conflicting-confirmation",
            "confirmation_os_user": "conflicting-user",
            "decided_at": decided.decided_at,
            "note": "",
        },
        timestamp=env.clock.now_ms(),
    )
    with pytest.raises(StateError):
        _grant(env, decided)
    assert env.store.get_approval(approval.approval_id).consumed_at is None
    assert env.store.list_grants() == []


def test_replayed_consumed_approval_is_rejected(env) -> None:
    approval = _request(env)
    decided = _approve(env, approval.approval_id)
    grant = _grant(env, decided)
    assert grant.approval_id == approval.approval_id
    with pytest.raises(StateError):
        _grant(env, decided)
    assert len(env.store.list_grants(task_id=env.task.task_id)) == 1


def test_concurrent_grant_creation_succeeds_once(env) -> None:
    approval = _request(env)
    decided = _approve(env, approval.approval_id)

    def attempt() -> None:
        _grant(env, decided)

    results: list[BaseException | None] = []

    def runner() -> None:
        try:
            attempt()
            results.append(None)
        except BaseException as exc:  # noqa: BLE001
            results.append(exc)

    threads = [threading.Thread(target=runner) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    successes = [item for item in results if item is None]
    failures = [item for item in results if item is not None]
    assert len(successes) == 1, results
    assert all(isinstance(item, StateError) for item in failures), failures
    assert len(env.store.list_grants(task_id=env.task.task_id)) == 1
    # A second call after the concurrent race is also rejected.
    with pytest.raises(StateError):
        _grant(env, decided)


class _FailingDecisionEvidence:
    """Delegating evidence store that cannot persist approval_decided events."""

    def __init__(self, inner: EvidenceStore) -> None:
        self._inner = inner

    def append_event(self, **kwargs):
        if kwargs.get("event_type") == "approval_decided":
            raise OSError("synthetic evidence write failure")
        return self._inner.append_event(**kwargs)

    def __getattr__(self, name):
        return getattr(self._inner, name)


def test_confirmation_event_write_failure_invalidates_approval(env) -> None:
    failing = _FailingDecisionEvidence(env.evidence)
    service = ApprovalGrantService(env.store, failing, env.clock, env.config)
    approval = _request(env)
    channel = approving_channel(env.clock, approval.action_digest)
    with pytest.raises(StateError):
        service.confirm_approval(approval.approval_id, channel=channel)
    stored = env.store.get_approval(approval.approval_id)
    assert stored.status.value == "cancelled"
    assert stored.consumed_at is None
    with pytest.raises(StateError):
        service.create_grant_from_approval(
            approval.approval_id,
            competition_profile=approval.payload["profile"],
            host=approval.payload["target"]["host"],
            port=approval.payload["target"]["port"],
            protocol=approval.payload["target"]["protocol"],
            method=approval.payload["target"]["method"],
            path_prefix=approval.payload["target"]["path_prefix"],
        )
    assert env.store.list_grants() == []


def test_event_chain_damage_blocks_grant_creation(env) -> None:
    approval = _request(env)
    decided = _approve(env, approval.approval_id)
    _drop_append_only_triggers(env)
    row = env.evidence.connection.execute(
        "SELECT record_id, payload_json FROM events WHERE event_type = 'approval_requested'"
    ).fetchone()
    assert row is not None
    damaged = json.loads(row["payload_json"])
    damaged["tampered_field"] = "attacker"
    env.evidence.connection.execute(
        "UPDATE events SET payload_json = ? WHERE record_id = ?",
        (json.dumps(damaged), row["record_id"]),
    )
    env.evidence.connection.commit()
    assert env.evidence.chain_status().ok is False
    with pytest.raises(StateError):
        _grant(env, decided)
    assert env.store.get_approval(approval.approval_id).consumed_at is None


# ---------------------------------------------------------------------------
# Final acceptance follow-up: cross-Task decision-event uniqueness
# ---------------------------------------------------------------------------


def _cross_task_conflict_event(env, decided, task_b, *, conflict: bool = True):
    return env.evidence.append_event(
        task_id=task_b.task_id,
        source="manager",
        source_id="manager:approval_decided:cross-task",
        event_type="approval_decided",
        payload={
            "approval_id": decided.approval_id,
            "task_id": task_b.task_id if conflict else decided.task_id,
            "action_kind": decided.action_kind,
            "action_digest": decided.action_digest if not conflict else "f" * 64,
            "approved": True,
            "approver": "cross-task-conflict",
            "confirmation_channel": "local_console",
            "confirmation_id": "cross-task-confirmation",
            "confirmation_os_user": "cross-task-conflict",
            "decided_at": decided.decided_at,
            "note": "cross-task conflict",
        },
        timestamp=env.clock.now_ms(),
    )


def test_cross_task_duplicate_decision_event_is_rejected(env) -> None:
    approval = _request(env)
    decided = _approve(env, approval.approval_id)
    _cross_task_conflict_event(env, decided, env.other, conflict=True)
    with pytest.raises(StateError):
        _grant(env, decided)
    assert env.store.get_approval(approval.approval_id).consumed_at is None
    assert env.store.list_grants() == []


def test_cross_task_duplicate_with_matching_fields_is_still_rejected(env) -> None:
    """Even a byte-identical second event in another Task breaks uniqueness."""

    approval = _request(env)
    decided = _approve(env, approval.approval_id)
    _cross_task_conflict_event(env, decided, env.other, conflict=False)
    with pytest.raises(StateError):
        _grant(env, decided)
    assert env.store.list_grants() == []


def test_cross_task_event_with_rewritten_task_id_is_rejected(env) -> None:
    approval = _request(env)
    decided = _approve(env, approval.approval_id)
    # Event row belongs to Task B but payload claims Task A.
    env.evidence.append_event(
        task_id=env.other.task_id,
        source="manager",
        source_id="manager:approval_decided:rewritten-task",
        event_type="approval_decided",
        payload={
            "approval_id": decided.approval_id,
            "task_id": decided.task_id,
            "action_kind": decided.action_kind,
            "action_digest": decided.action_digest,
            "approved": True,
            "approver": decided.confirmation_os_user,
            "confirmation_channel": "local_console",
            "confirmation_id": decided.confirmation_id,
            "confirmation_os_user": decided.confirmation_os_user,
            "decided_at": decided.decided_at,
            "note": "",
        },
        timestamp=env.clock.now_ms(),
    )
    with pytest.raises(StateError):
        _grant(env, decided)
    assert env.store.list_grants() == []


def test_legitimate_approval_still_creates_one_grant(env) -> None:
    approval = _request(env)
    decided = _approve(env, approval.approval_id)
    grant = _grant(env, decided)
    assert grant.approval_id == approval.approval_id
    assert grant.task_id == env.task.task_id
    assert len(env.store.list_grants(task_id=env.task.task_id)) == 1
    assert len(env.store.list_grants(task_id=env.other.task_id)) == 0
