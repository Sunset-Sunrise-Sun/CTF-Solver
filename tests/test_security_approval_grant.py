"""Approval/grant use-case security tests: human confirmation is the only decision path."""

from __future__ import annotations

import inspect
import uuid

import pytest

from ctf_solver.core.canonical import canonical_json
from ctf_solver.core.errors import NotFoundError, StateError, ValidationError
from ctf_solver.core.types import (
    ApprovalStatus,
    GrantRecord,
    GrantStatus,
)
from ctf_solver.manager.approval_grant_service import (
    ApprovalGrantService,
    canonical_approval_details,
    remote_target_action_digest,
)
from ctf_solver.policy.models import action_digest
from ctf_solver.security.confirmation import (
    ConfirmationError,
    ConfirmationUnavailable,
    ConsoleConfirmationChannel,
    HumanConfirmation,
)
from tests.test_security_support import (
    SYNTHETIC_HOST,
    SYNTHETIC_PROFILE,
    SecurityEnvironment,
    approving_channel,
    build_environment,
    confirm_approval,
    new_confirmation,
    rejecting_channel,
    request_remote_approval,
    scripted_channel,
)

TARGET = {
    "host": "ctf-target.example",
    "port": 8443,
    "protocol": "https",
    "method": "POST",
    "path": "/api/challenge",
}


def _approve(env: SecurityEnvironment, approval_id: str):
    return confirm_approval(env, approval_id)


def _grant_args(approval) -> dict:
    target = approval.payload["target"]
    return {
        "competition_profile": approval.payload["profile"],
        "host": target["host"],
        "port": target["port"],
        "protocol": target["protocol"],
        "method": target["method"],
        "path_prefix": target["path_prefix"],
    }


class _WrongDigestChannel(ConsoleConfirmationChannel):
    """A compromised/fake channel that echoes a different digest."""

    def __init__(self, clock) -> None:
        super().__init__(clock, is_tty=True, os_user="human-owner")

    def confirm(self, *, approval_digest: str, summary: str) -> HumanConfirmation:
        return HumanConfirmation(
            channel="local_console",
            os_user="human-owner",
            confirmed_at=self.clock.now_ms(),
            confirmation_id=str(uuid.uuid4()),
            approval_digest="b" * 64,
        )


# ---------------------------------------------------------------------------
# Request-only path
# ---------------------------------------------------------------------------


def test_request_approval_is_pending_and_never_decided(tmp_path) -> None:
    env = build_environment(tmp_path)
    try:
        approval = request_remote_approval(env)
        assert approval.status is ApprovalStatus.PENDING
        assert approval.approver is None
        assert approval.decided_at is None
        assert approval.consumed_at is None
        assert approval.confirmation_channel is None
        assert approval.confirmation_id is None
        assert approval.confirmation_os_user is None
        assert set(approval.payload) == {
            "task_id",
            "profile",
            "target",
            "grant_ttl_s",
            "max_calls",
        }
        assert approval.payload["task_id"] == env.task.task_id
        assert approval.payload["target"] == {
            "host": TARGET["host"],
            "port": TARGET["port"],
            "protocol": TARGET["protocol"],
            "method": TARGET["method"],
            "path_prefix": TARGET["path"],
        }
        assert approval.payload["profile"] == SYNTHETIC_PROFILE
        assert approval.payload["grant_ttl_s"] == 3600
        assert approval.payload["max_calls"] == 10
        expected_digest = remote_target_action_digest(
            task_id=env.task.task_id,
            host=TARGET["host"],
            port=TARGET["port"],
            protocol=TARGET["protocol"],
            method=TARGET["method"],
            path_prefix=TARGET["path"],
            competition_profile=SYNTHETIC_PROFILE,
            grant_ttl_s=3600,
            max_calls=10,
        )
        assert approval.action_digest == expected_digest

        events = env.evidence.of_type("approval_requested")
        assert len(events) == 1
        payload = events[0]["payload"]
        for key in ("approval_id", "action_kind", "action_digest", "approved", "approver"):
            assert key in payload
        assert payload["approved"] is False
        assert payload["approver"] is None
        assert payload["approval_id"] == approval.approval_id
    finally:
        env.store.close()


def test_model_supplied_decision_strings_cannot_decide(tmp_path) -> None:
    env = build_environment(tmp_path)
    try:
        approval = env.service.request_approval(
            env.task.task_id,
            action_kind="tool_action",
            details={"action": "inspect", "approved": "true", "approver": "model", "decision": "true"},
        )
        # A request stays pending no matter what strings the model puts in details.
        stored = env.store.get_approval(approval.approval_id)
        assert stored is not None
        assert stored.status is ApprovalStatus.PENDING
        assert stored.approver is None
        assert stored.decided_at is None

        channel = scripted_channel(env.clock, ["CONFIRM 00000000"])
        with pytest.raises(TypeError):
            env.service.confirm_approval(  # type: ignore[call-arg]
                approval.approval_id, channel=channel, approved="true"
            )
        with pytest.raises(TypeError):
            env.service.confirm_approval(  # type: ignore[call-arg]
                approval.approval_id, channel=channel, approver="model"
            )
        with pytest.raises(TypeError):
            env.service.request_approval(  # type: ignore[call-arg]
                env.task.task_id,
                action_kind="tool_action",
                details={},
                approver="model",
            )

        # No free-form approval-decision or direct grant-creation API exists.
        for forbidden in ("decide_approval", "approve", "create_grant", "create_network_grant"):
            assert not hasattr(env.service, forbidden), forbidden
        for forbidden in ("decide_approval",):
            assert not hasattr(env.store, forbidden), forbidden

        request_params = inspect.signature(env.service.request_approval).parameters
        assert "approver" not in request_params
        assert "approved" not in request_params
        confirm_params = inspect.signature(env.service.confirm_approval).parameters
        assert set(confirm_params) == {"approval_id", "channel", "reject", "note"}
        grant_params = inspect.signature(env.service.create_grant_from_approval).parameters
        assert "approver" not in grant_params
        assert "task_id" not in grant_params
    finally:
        env.store.close()


# ---------------------------------------------------------------------------
# Confirm / reject
# ---------------------------------------------------------------------------


def test_confirm_approval_records_human_confirmation(tmp_path) -> None:
    env = build_environment(tmp_path)
    try:
        approval = request_remote_approval(env)
        output: list[str] = []
        channel = approving_channel(env.clock, approval.action_digest, output=output)
        decided = env.service.confirm_approval(approval.approval_id, channel=channel)

        assert decided.status is ApprovalStatus.APPROVED
        assert decided.approver == "human-owner"
        assert decided.decided_at == env.clock.now_ms()
        assert decided.confirmation_channel == "local_console"
        assert decided.confirmation_os_user == "human-owner"
        assert decided.confirmation_id
        uuid.UUID(decided.confirmation_id)
        assert decided.confirmation_note == ""
        assert decided.action_digest == approval.action_digest
        assert approval.action_digest[:8] in "\n".join(output)

        events = env.evidence.of_type("approval_decided")
        assert len(events) == 1
        payload = events[0]["payload"]
        for key in ("approval_id", "action_kind", "action_digest", "approved", "approver"):
            assert key in payload
        assert payload["approved"] is True
        assert payload["approver"] == "human-owner"
        assert payload["confirmation_channel"] == "local_console"
        assert payload["confirmation_id"] == decided.confirmation_id
    finally:
        env.store.close()


def test_confirm_rejection_is_recorded_and_cannot_authorize(tmp_path) -> None:
    env = build_environment(tmp_path)
    try:
        approval = request_remote_approval(env)
        decided = env.service.confirm_approval(
            approval.approval_id,
            channel=rejecting_channel(env.clock),
            reject=True,
        )
        assert decided.status is ApprovalStatus.REJECTED
        assert decided.approver == "human-owner"
        assert decided.confirmation_note == "explicit human rejection"
        assert env.evidence.of_type("approval_decided")[0]["payload"]["approved"] is False
        with pytest.raises(StateError):
            env.service.create_grant_from_approval(
                approval.approval_id, **_grant_args(decided)
            )
        assert env.store.list_grants() == []
        assert env.store.get_approval(approval.approval_id).consumed_at is None
    finally:
        env.store.close()


def test_service_confirm_refuses_non_tty_and_unknown_channel(tmp_path) -> None:
    env = build_environment(tmp_path)
    try:
        approval = request_remote_approval(env)
        non_tty = approving_channel(
            env.clock, approval.action_digest, is_tty=False
        )
        with pytest.raises(ConfirmationUnavailable):
            env.service.confirm_approval(approval.approval_id, channel=non_tty)
        with pytest.raises(ConfirmationError):
            env.service.confirm_approval(approval.approval_id, channel=object())  # type: ignore[arg-type]
        stored = env.store.get_approval(approval.approval_id)
        assert stored.status is ApprovalStatus.PENDING
        assert stored.approver is None
    finally:
        env.store.close()


def test_approval_decision_replay_fails(tmp_path) -> None:
    env = build_environment(tmp_path)
    try:
        approval = request_remote_approval(env)
        first = _approve(env, approval.approval_id)
        with pytest.raises(StateError):
            env.service.confirm_approval(
                approval.approval_id,
                channel=approving_channel(env.clock, approval.action_digest),
            )
        stored = env.store.get_approval(approval.approval_id)
        assert stored.status is ApprovalStatus.APPROVED
        assert stored.decided_at == first.decided_at
        assert stored.confirmation_id == first.confirmation_id
    finally:
        env.store.close()


def test_expired_approval_cannot_be_confirmed(tmp_path) -> None:
    env = build_environment(tmp_path)
    try:
        approval = request_remote_approval(env, ttl_s=10)
        env.clock.advance(11_000)
        with pytest.raises(StateError):
            env.service.confirm_approval(
                approval.approval_id,
                channel=approving_channel(env.clock, approval.action_digest),
            )
        stored = env.store.get_approval(approval.approval_id)
        assert stored.status is ApprovalStatus.EXPIRED
        assert stored.approver is None
        assert env.store.consume_approval(approval.approval_id, env.clock.now_ms()) is False
    finally:
        env.store.close()


def test_confirmation_digest_mismatch_fails_closed(tmp_path) -> None:
    env = build_environment(tmp_path)
    try:
        approval = request_remote_approval(env)
        with pytest.raises(ConfirmationError):
            env.service.confirm_approval(
                approval.approval_id, channel=_WrongDigestChannel(env.clock)
            )
        stored = env.store.get_approval(approval.approval_id)
        assert stored.status is ApprovalStatus.PENDING
        assert stored.approver is None
        assert env.evidence.of_type("approval_decided") == []
    finally:
        env.store.close()


# ---------------------------------------------------------------------------
# Grant creation requires a confirmed approval
# ---------------------------------------------------------------------------


def test_grant_requires_a_human_confirmed_approval(tmp_path) -> None:
    env = build_environment(tmp_path)
    try:
        pending = request_remote_approval(env)
        with pytest.raises(StateError):
            env.service.create_grant_from_approval(
                pending.approval_id, **_grant_args(pending)
            )

        rejected = request_remote_approval(env)
        env.service.confirm_approval(
            rejected.approval_id,
            channel=rejecting_channel(env.clock),
            reject=True,
        )
        with pytest.raises(StateError):
            env.service.create_grant_from_approval(
                rejected.approval_id, **_grant_args(rejected)
            )

        # An APPROVED row without a recorded human confirmation (legacy/tampered)
        # can never mint a grant.
        import copy

        forged = copy.deepcopy(pending)
        forged.approval_id = "apr-forged01"
        forged.action_digest = action_digest("remote_target", forged.payload)
        env.store.create_approval(forged)
        env.store.conn.execute(
            "UPDATE approvals SET status = 'approved', approver = 'model'"
            " WHERE approval_id = ?",
            (forged.approval_id,),
        )
        with pytest.raises(StateError):
            env.service.create_grant_from_approval(
                forged.approval_id, **_grant_args(forged)
            )
        assert env.store.get_approval(forged.approval_id).consumed_at is None
        assert env.store.list_grants() == []
    finally:
        env.store.close()


def test_grant_creation_binds_task_target_profile_and_confirmation(tmp_path) -> None:
    env = build_environment(tmp_path)
    try:
        approval = request_remote_approval(env)
        decided = _approve(env, approval.approval_id)
        grant = env.service.create_grant_from_approval(
            approval.approval_id, **_grant_args(decided)
        )
        assert grant.task_id == env.task.task_id
        assert grant.competition_profile == SYNTHETIC_PROFILE
        assert grant.host == SYNTHETIC_HOST
        assert grant.port == 8443
        assert grant.protocol == "https"
        assert grant.method == "POST"
        assert grant.path_prefix == "/api/challenge"
        # Round 2 P0-1: TTL and call budget come from the human-approved payload.
        assert grant.max_calls == 10
        assert grant.calls_used == 0
        assert grant.expires_at == env.clock.now_ms() + 3_600_000
        assert grant.status is GrantStatus.ACTIVE
        assert grant.approver == "human-owner"
        assert grant.approval_id == approval.approval_id
        assert grant.confirmation_id == decided.confirmation_id
        assert grant.confirmation_os_user == "human-owner"
        assert len(grant.grant_digest) == 64

        consumed = env.store.get_approval(approval.approval_id)
        assert consumed.consumed_at == env.clock.now_ms()

        events = env.evidence.of_type("grant_created")
        assert len(events) == 1
        payload = events[0]["payload"]
        for key in (
            "grant_id",
            "host",
            "port",
            "protocol",
            "method",
            "expires_at",
            "max_calls",
            "approval_id",
            "confirmation_id",
            "confirmation_os_user",
        ):
            assert key in payload
        assert payload["confirmation_os_user"] == "human-owner"
        assert payload["approval_id"] == approval.approval_id
    finally:
        env.store.close()


def test_grant_consumes_the_approval_exactly_once(tmp_path) -> None:
    env = build_environment(tmp_path)
    try:
        approval = request_remote_approval(env)
        decided = _approve(env, approval.approval_id)
        args = _grant_args(decided)
        first = env.service.create_grant_from_approval(approval.approval_id, **args)
        with pytest.raises(StateError):
            env.service.create_grant_from_approval(approval.approval_id, **args)
        grants = env.store.list_grants(task_id=env.task.task_id)
        assert [grant.grant_id for grant in grants] == [first.grant_id]
        assert env.store.consume_approval(approval.approval_id, env.clock.now_ms()) is False
    finally:
        env.store.close()


def test_grant_target_or_profile_mismatch_fails_before_consumption(tmp_path) -> None:
    env = build_environment(tmp_path)
    try:
        approval = request_remote_approval(env)
        decided = _approve(env, approval.approval_id)
        base = _grant_args(decided)
        mismatches = [
            {"host": "other-target.example"},
            {"port": 8444},
            {"protocol": "http"},
            {"method": "GET"},
            {"path_prefix": "/api/other"},
            {"competition_profile": "another-profile"},
            {"host": "CTF-TARGET.EXAMPLE"},  # normalisation makes this EQUAL (control case)
        ]
        for mismatch in mismatches:
            args = dict(base)
            args.update(mismatch)
            if mismatch == {"host": "CTF-TARGET.EXAMPLE"}:
                # Host case/format normalisation is not a mismatch: the digest is
                # canonical, so this attempt is accepted. Consume it as the control.
                grant = env.service.create_grant_from_approval(
                    approval.approval_id, **args
                )
                assert grant.host == SYNTHETIC_HOST
                continue
            with pytest.raises(StateError):
                env.service.create_grant_from_approval(approval.approval_id, **args)
            stored = env.store.get_approval(approval.approval_id)
            assert stored.consumed_at is None, mismatch
            assert env.store.list_grants(task_id=env.task.task_id) == []
    finally:
        env.store.close()


def test_tampered_approval_payload_or_digest_fails_closed(tmp_path) -> None:
    env = build_environment(tmp_path)
    try:
        approval = request_remote_approval(env)
        decided = _approve(env, approval.approval_id)
        args = _grant_args(decided)

        tampered_payload = {
            "task_id": decided.payload["task_id"],
            "target": {**decided.payload["target"], "port": 9999},
            "profile": SYNTHETIC_PROFILE,
            "grant_ttl_s": decided.payload["grant_ttl_s"],
            "max_calls": decided.payload["max_calls"],
        }
        env.store.conn.execute(
            "UPDATE approvals SET payload_json = ? WHERE approval_id = ?",
            (canonical_json(tampered_payload), approval.approval_id),
        )
        with pytest.raises(StateError):
            env.service.create_grant_from_approval(approval.approval_id, **args)
        assert env.store.get_approval(approval.approval_id).consumed_at is None
        assert env.store.list_grants() == []

        env.store.conn.execute(
            "UPDATE approvals SET payload_json = ?, action_digest = ? WHERE approval_id = ?",
            (canonical_json(decided.payload), "c" * 64, approval.approval_id),
        )
        with pytest.raises(StateError):
            env.service.create_grant_from_approval(approval.approval_id, **args)
        assert env.store.get_approval(approval.approval_id).consumed_at is None
    finally:
        env.store.close()


def test_cross_task_approval_cannot_mint_another_tasks_grant(tmp_path) -> None:
    env = build_environment(tmp_path, extra_task_ids=("t-security02",))
    other_task = env.extra_tasks["t-security02"]
    try:
        other_approval = request_remote_approval(env, task_id=other_task.task_id)
        decided = _approve(env, other_approval.approval_id)
        target = decided.payload["target"]
        now = env.clock.now_ms()
        wrong_task_grant = GrantRecord(
            grant_id="grant-wrongtask01",
            task_id=env.task.task_id,  # not the approval's Task
            competition_profile=decided.payload["profile"],
            host=target["host"],
            port=target["port"],
            protocol=target["protocol"],
            method=target["method"],
            path_prefix=target["path_prefix"],
            expires_at=now + 60_000,
            max_calls=1,
            approver=decided.confirmation_os_user,
            created_at=now,
            approval_id=decided.approval_id,
            confirmation_id=decided.confirmation_id,
            confirmation_os_user=decided.confirmation_os_user,
        )
        assert (
            env.store.create_grant_from_approval(
                decided.approval_id, wrong_task_grant, now
            )
            is False
        )
        assert env.store.get_grant("grant-wrongtask01") is None
        assert env.store.get_approval(decided.approval_id).consumed_at is None

        # The service always mints the grant on the approval's own Task.
        grant = env.service.create_grant_from_approval(
            decided.approval_id, **_grant_args(decided)
        )
        assert grant.task_id == other_task.task_id
        assert env.store.list_grants(task_id=env.task.task_id) == []
    finally:
        env.store.close()


# ---------------------------------------------------------------------------
# Lifecycle / queries / validation
# ---------------------------------------------------------------------------


def test_revoke_grant_is_durable_and_idempotent(tmp_path) -> None:
    env = build_environment(tmp_path)
    try:
        approval = request_remote_approval(env)
        decided = _approve(env, approval.approval_id)
        grant = env.service.create_grant_from_approval(
            approval.approval_id, **_grant_args(decided)
        )
        revoked = env.service.revoke_grant(grant.grant_id)
        assert revoked.status is GrantStatus.REVOKED
        assert env.evidence.of_type("grant_revoked")[0]["payload"]["grant_id"] == grant.grant_id
        assert env.service.revoke_grant(grant.grant_id).status is GrantStatus.REVOKED
        with pytest.raises(NotFoundError):
            env.service.revoke_grant("grant-unknown")
    finally:
        env.store.close()


def test_list_approvals_and_grants_are_task_scoped(tmp_path) -> None:
    env = build_environment(tmp_path, extra_task_ids=("t-security02",))
    other = env.extra_tasks["t-security02"]
    try:
        first = request_remote_approval(env)
        second = request_remote_approval(env, task_id=other.task_id, port=9443)
        assert [item.approval_id for item in env.service.list_approvals(task_id=env.task.task_id)] == [
            first.approval_id
        ]
        assert [item.approval_id for item in env.service.list_approvals(task_id=other.task_id)] == [
            second.approval_id
        ]
        decided = _approve(env, first.approval_id)
        env.service.create_grant_from_approval(first.approval_id, **_grant_args(decided))
        assert len(env.service.list_grants(task_id=env.task.task_id)) == 1
        assert env.service.list_grants(task_id=other.task_id) == []
    finally:
        env.store.close()


def test_request_approval_validation_is_fail_closed(tmp_path) -> None:
    env = build_environment(tmp_path)
    try:
        with pytest.raises(NotFoundError):
            env.service.request_approval("t-unknown", action_kind="remote_target", details={})
        with pytest.raises(ValidationError):
            env.service.request_approval(
                env.task.task_id, action_kind="root_shell", details={}
            )
        with pytest.raises(ValidationError):
            env.service.request_approval(
                env.task.task_id, action_kind="remote_target", details=["not", "a", "mapping"]
            )
        bad_details = [
            {},
            {"target": TARGET},
            {"target": TARGET, "profile": "", "grant_ttl_s": 60, "max_calls": 1},
            {"target": {**TARGET, "port": 0}, "profile": SYNTHETIC_PROFILE, "grant_ttl_s": 60, "max_calls": 1},
            {"target": {**TARGET, "port": 70000}, "profile": SYNTHETIC_PROFILE, "grant_ttl_s": 60, "max_calls": 1},
            {"target": {**TARGET, "host": ""}, "profile": SYNTHETIC_PROFILE, "grant_ttl_s": 60, "max_calls": 1},
            {"target": {**TARGET, "protocol": "gopher"}, "profile": SYNTHETIC_PROFILE, "grant_ttl_s": 60, "max_calls": 1},
            # Non-string paths are rejected (a string path is normalised, see the
            # canonicalisation test below).
            {"target": {**TARGET, "path": None}, "profile": SYNTHETIC_PROFILE, "grant_ttl_s": 60, "max_calls": 1},
            # Round 2 P0-1: the network authorization scope must be explicit and
            # strictly integral (bool/float/string/zero/negative/oversized fail).
            {"target": TARGET, "profile": SYNTHETIC_PROFILE, "grant_ttl_s": True, "max_calls": 1},
            {"target": TARGET, "profile": SYNTHETIC_PROFILE, "grant_ttl_s": 1.5, "max_calls": 1},
            {"target": TARGET, "profile": SYNTHETIC_PROFILE, "grant_ttl_s": "60", "max_calls": 1},
            {"target": TARGET, "profile": SYNTHETIC_PROFILE, "grant_ttl_s": 0, "max_calls": 1},
            {"target": TARGET, "profile": SYNTHETIC_PROFILE, "grant_ttl_s": -1, "max_calls": 1},
            {"target": TARGET, "profile": SYNTHETIC_PROFILE, "grant_ttl_s": 60, "max_calls": True},
            {"target": TARGET, "profile": SYNTHETIC_PROFILE, "grant_ttl_s": 60, "max_calls": 1.5},
            {"target": TARGET, "profile": SYNTHETIC_PROFILE, "grant_ttl_s": 60, "max_calls": "1"},
            {"target": TARGET, "profile": SYNTHETIC_PROFILE, "grant_ttl_s": 60},
            {"target": TARGET, "profile": SYNTHETIC_PROFILE, "max_calls": 1},
        ]
        for details in bad_details:
            with pytest.raises(ValidationError):
                env.service.request_approval(
                    env.task.task_id, action_kind="remote_target", details=details
                )
        with pytest.raises(ValidationError):
            env.service.request_approval(
                env.task.task_id,
                action_kind="remote_target",
                details={
                    "target": TARGET,
                    "profile": SYNTHETIC_PROFILE,
                    "grant_ttl_s": 60,
                    "max_calls": 1,
                },
                ttl_s=0,
            )
        assert env.store.list_approvals() == []
    finally:
        env.store.close()


def test_remote_target_details_are_canonicalized_before_digesting(tmp_path) -> None:
    env = build_environment(tmp_path)
    try:
        details = {
            "target": {
                "host": "CTF-Target.Example.",
                "port": 8443,
                "protocol": "HTTPS",
                "method": "post",
                "path_prefix": "api/challenge",
            },
            "profile": SYNTHETIC_PROFILE,
            "grant_ttl_s": 120,
            "max_calls": 3,
        }
        canonical = canonical_approval_details(
            "remote_target", details, task_id=env.task.task_id
        )
        assert canonical["target"]["host"] == SYNTHETIC_HOST
        assert canonical["target"]["port"] == 8443
        assert canonical["target"]["protocol"] == "https"
        assert canonical["target"]["method"] == "POST"
        assert canonical["target"]["path_prefix"] == "/api/challenge"
        assert canonical["task_id"] == env.task.task_id
        assert canonical["grant_ttl_s"] == 120
        assert canonical["max_calls"] == 3
        approval = env.service.request_approval(
            env.task.task_id, action_kind="remote_target", details=details
        )
        assert approval.payload == canonical
        assert approval.action_digest == action_digest("remote_target", canonical)
        # Non-remote kinds keep their caller payload verbatim (Broker recomputes
        # its own digest from the typed execution request).
        other = env.service.request_approval(
            env.task.task_id, action_kind="tool_action", details={"tool": "strings", "x": 1}
        )
        assert other.payload == {"tool": "strings", "x": 1}
    finally:
        env.store.close()


def test_confirmation_without_console_channel_is_impossible(tmp_path) -> None:
    env = build_environment(tmp_path)
    try:
        approval = request_remote_approval(env)
        for fake in (None, object(), {"channel": "local_console", "os_user": "human-owner"}):
            with pytest.raises(ConfirmationError):
                env.service.confirm_approval(
                    approval.approval_id, channel=fake  # type: ignore[arg-type]
                )
        assert env.store.get_approval(approval.approval_id).status is ApprovalStatus.PENDING
        assert isinstance(env.service, ApprovalGrantService)
    finally:
        env.store.close()
