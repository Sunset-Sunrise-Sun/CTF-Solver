"""Round 2 final acceptance remediation: P0-1 scope binding and P0-2 terminal safety."""

from __future__ import annotations

import json
import threading

import pytest

from ctf_solver.core.errors import StateError, ValidationError
from ctf_solver.manager.approval_grant_service import (
    ApprovalGrantService,
    canonical_remote_target_details,
    remote_target_action_digest,
)
from ctf_solver.policy.models import action_digest
from ctf_solver.security.confirmation import ConfirmationError, ConsoleConfirmationChannel
from ctf_solver.security.textsafe import (
    UnsafeTextError,
    normalize_field,
    require_displayable,
    terminal_safe,
)
from tests.test_security_support import (
    SYNTHETIC_PROFILE,
    build_environment,
    request_remote_approval,
)
from tests.test_security_support import confirm_approval as approve


def _grant_args(approval: object) -> dict:
    payload = approval.payload  # type: ignore[attr-defined]
    target = payload["target"]
    return {
        "competition_profile": payload["profile"],
        "host": target["host"],
        "port": target["port"],
        "protocol": target["protocol"],
        "method": target["method"],
        "path_prefix": target["path_prefix"],
    }


# ---------------------------------------------------------------------------
# P0-1: the human-approved scope includes TTL and call budget and cannot widen
# ---------------------------------------------------------------------------


def test_approved_scope_digest_binds_task_ttl_and_calls(tmp_path) -> None:
    env = build_environment(tmp_path)
    try:
        approval = request_remote_approval(env, grant_ttl_s=120, max_calls=3)
        assert approval.payload["task_id"] == env.task.task_id
        assert approval.payload["grant_ttl_s"] == 120
        assert approval.payload["max_calls"] == 3
        expected = remote_target_action_digest(
            task_id=env.task.task_id,
            host=approval.payload["target"]["host"],
            port=approval.payload["target"]["port"],
            protocol=approval.payload["target"]["protocol"],
            method=approval.payload["target"]["method"],
            path_prefix=approval.payload["target"]["path_prefix"],
            competition_profile=approval.payload["profile"],
            grant_ttl_s=120,
            max_calls=3,
        )
        assert approval.action_digest == expected
        # Changing either scope field changes the digest (they are not cosmetic).
        widened = remote_target_action_digest(
            task_id=env.task.task_id,
            host=approval.payload["target"]["host"],
            port=approval.payload["target"]["port"],
            protocol=approval.payload["target"]["protocol"],
            method=approval.payload["target"]["method"],
            path_prefix=approval.payload["target"]["path_prefix"],
            competition_profile=approval.payload["profile"],
            grant_ttl_s=3600,
            max_calls=3,
        )
        assert widened != expected
    finally:
        env.store.close()


def test_widening_ttl_or_call_budget_after_approval_fails_closed(tmp_path) -> None:
    env = build_environment(tmp_path)
    try:
        approval = request_remote_approval(env, grant_ttl_s=120, max_calls=3)
        decided = approve(env, approval.approval_id)
        args = _grant_args(decided)
        with pytest.raises(StateError):
            env.service.create_grant_from_approval(
                approval.approval_id, **args, ttl_s=3600
            )
        with pytest.raises(StateError):
            env.service.create_grant_from_approval(
                approval.approval_id, **args, max_calls=1000
            )
        stored = env.store.get_approval(approval.approval_id)
        assert stored.consumed_at is None
        assert env.store.list_grants() == []
        # The approved values themselves are accepted as a compatibility check.
        grant = env.service.create_grant_from_approval(
            approval.approval_id, **args, ttl_s=120, max_calls=3
        )
        assert grant.max_calls == 3
        assert grant.expires_at == env.clock.now_ms() + 120_000
    finally:
        env.store.close()


def test_grant_creation_rejects_non_integer_compat_values(tmp_path) -> None:
    env = build_environment(tmp_path)
    try:
        approval = request_remote_approval(env)
        decided = approve(env, approval.approval_id)
        args = _grant_args(decided)
        for bad_ttl in (True, 1.5, "3600", 0, -5):
            with pytest.raises(ValidationError):
                env.service.create_grant_from_approval(
                    approval.approval_id, **args, ttl_s=bad_ttl  # type: ignore[arg-type]
                )
        for bad_calls in (False, 2.5, "10", 0, -1):
            with pytest.raises(ValidationError):
                env.service.create_grant_from_approval(
                    approval.approval_id, **args, max_calls=bad_calls  # type: ignore[arg-type]
                )
        assert env.store.get_approval(approval.approval_id).consumed_at is None
        assert env.store.list_grants() == []
    finally:
        env.store.close()


def test_approved_profile_or_path_or_task_change_fails_closed(tmp_path) -> None:
    env = build_environment(tmp_path, extra_task_ids=("t-security02",))
    try:
        approval = request_remote_approval(env, grant_ttl_s=60, max_calls=2)
        decided = approve(env, approval.approval_id)
        base = _grant_args(decided)
        for field, value in (
            ("competition_profile", "other-profile"),
            ("path_prefix", "/other"),
            ("host", "other.example"),
            ("port", 9443),
            ("protocol", "http"),
            ("method", "GET"),
        ):
            args = dict(base)
            args[field] = value
            with pytest.raises(StateError):
                env.service.create_grant_from_approval(approval.approval_id, **args)
            assert env.store.get_approval(approval.approval_id).consumed_at is None
        # A different Task cannot consume this approval through the service.
        other = env.extra_tasks["t-security02"]
        args = dict(base)
        args["task_id"] = other.task_id
        with pytest.raises(TypeError):
            env.service.create_grant_from_approval(approval.approval_id, **args)  # type: ignore[call-arg]
        assert env.store.get_approval(approval.approval_id).consumed_at is None
    finally:
        env.store.close()


def test_tampered_sqlite_ttl_or_calls_fail_closed(tmp_path) -> None:
    env = build_environment(tmp_path)
    try:
        approval = request_remote_approval(env, grant_ttl_s=60, max_calls=2)
        decided = approve(env, approval.approval_id)
        args = _grant_args(decided)
        for field, value in (("grant_ttl_s", 3600), ("max_calls", 999)):
            tampered = json.loads(json.dumps(decided.payload))
            tampered[field] = value
            env.store.conn.execute(
                "UPDATE approvals SET payload_json = ? WHERE approval_id = ?",
                (json.dumps(tampered), approval.approval_id),
            )
            with pytest.raises(StateError):
                env.service.create_grant_from_approval(approval.approval_id, **args)
            assert env.store.get_approval(approval.approval_id).consumed_at is None
            assert env.store.list_grants() == []
            # restore for the next iteration
            env.store.conn.execute(
                "UPDATE approvals SET payload_json = ? WHERE approval_id = ?",
                (json.dumps(decided.payload), approval.approval_id),
            )
    finally:
        env.store.close()


def test_concurrent_grant_creation_has_one_winner(tmp_path) -> None:
    env = build_environment(tmp_path)
    try:
        approval = request_remote_approval(env)
        decided = approve(env, approval.approval_id)
        args = _grant_args(decided)
        barrier = threading.Barrier(6)
        successes: list[str] = []
        failures: list[BaseException] = []

        def worker() -> None:
            try:
                barrier.wait(timeout=5)
                grant = env.service.create_grant_from_approval(
                    approval.approval_id, **args
                )
                successes.append(grant.grant_id)
            except BaseException as exc:  # noqa: BLE001 - collected for assertion
                failures.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(6)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        assert len(successes) == 1, (successes, failures)
        assert all(isinstance(exc, StateError) for exc in failures), failures
        assert len(env.store.list_grants(task_id=env.task.task_id)) == 1
        assert env.store.get_approval(approval.approval_id).consumed_at is not None
    finally:
        env.store.close()


# ---------------------------------------------------------------------------
# P0-2: terminal injection / display-vs-approved consistency
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad_profile",
    [
        "synthetic\x1b[2J",
        "synthetic\x1b[31mred",
        "synthetic\x1b]0;owned\x07",
        "synthetic\r\nINJECTED",
        "synthetic\u202eoverride",
        "x" * 300,
        "bad profile",
        "",
    ],
)
def test_unsafe_profile_rejected_before_payload_creation(tmp_path, bad_profile: str) -> None:
    env = build_environment(tmp_path)
    try:
        with pytest.raises(ValidationError):
            request_remote_approval(env, profile=bad_profile)
        assert env.store.list_approvals() == []
    finally:
        env.store.close()


@pytest.mark.parametrize(
    "field,value",
    [
        ("host", "evil\x1b[2J.example"),
        ("host", "evil.example\r\nX"),
        ("host", "evil/example"),
        ("host", "a" * 300),
        ("path_prefix", "/api\x1b[2J"),
        ("path_prefix", "/api\r\nINJECTED"),
        ("path_prefix", "/a/../b"),
        ("path_prefix", "/api?x=1"),
        ("method", "GET\nPOST"),
        ("protocol", "http\x1b[31m"),
    ],
)
def test_unsafe_target_fields_rejected(tmp_path, field: str, value: str) -> None:
    env = build_environment(tmp_path)
    try:
        kwargs = {
            "host": "ctf-target.example",
            "port": 8443,
            "protocol": "https",
            "method": "POST",
            "path": "/api/challenge",
        }
        if field == "path_prefix":
            kwargs["path"] = value
        else:
            kwargs[field] = value
        with pytest.raises(ValidationError):
            request_remote_approval(env, **kwargs)
        assert env.store.list_approvals() == []
    finally:
        env.store.close()


@pytest.mark.parametrize(
    "text",
    [
        "safe\x1b[2Jjunk",
        "safe\x1b[31mcolour",
        "safe\x1b]0;title\x07",
        "safe\r\nsecond line",
        "safe\u202eoverride",
        "safe\x00nul",
        "x" * 2000,
    ],
)
def test_confirmation_channel_rejects_unsafe_summary(text: str) -> None:
    channel = ConsoleConfirmationChannel(
        is_tty=True,
        os_user="human-owner",
        input_fn=lambda prompt: "CONFIRM 00000000",
        output_fn=lambda line: None,
    )
    with pytest.raises(ConfirmationError):
        channel.confirm(approval_digest="a" * 64, summary=text)


def test_terminal_safe_escapes_without_deleting() -> None:
    escaped = terminal_safe("a\x1b[2Jb\r\nc\u202ed")
    assert "\x1b" not in escaped
    assert "\r" not in escaped and "\n" not in escaped
    assert "\\x1b" in escaped
    assert "\\r" in escaped
    assert "\\u202e" in escaped


def test_human_summary_matches_approved_digest_payload(tmp_path) -> None:
    env = build_environment(tmp_path)
    try:
        approval = request_remote_approval(env, grant_ttl_s=120, max_calls=3)
        recorded = env.service.summarize(approval)
        for needle in (
            f"approval={approval.approval_id}",
            f"task={env.task.task_id}",
            "target=ctf-target.example:8443 https POST /api/challenge",
            f"profile={SYNTHETIC_PROFILE}",
            "grant_ttl_s=120",
            "max_calls=3",
        ):
            assert needle in recorded, recorded
        # No raw control/format characters can reach the terminal summary.
        assert require_displayable(recorded) == recorded
        assert "\x1b" not in recorded
        # The digest was computed from exactly this payload.
        assert approval.action_digest == action_digest("remote_target", approval.payload)
    finally:
        env.store.close()


def test_normalized_payload_is_what_was_displayed_and_approved(tmp_path) -> None:
    env = build_environment(tmp_path)
    try:
        approval = request_remote_approval(
            env, host="CTF-TARGET.EXAMPLE.", protocol="HTTPS", method="post"
        )
        assert approval.payload["target"]["host"] == "ctf-target.example"
        assert approval.payload["target"]["protocol"] == "https"
        assert approval.payload["target"]["method"] == "POST"
        output: list[str] = []
        from tests.test_security_support import approving_channel

        channel = approving_channel(
            env.clock, approval.action_digest, output=output
        )
        env.service.confirm_approval(approval.approval_id, channel=channel)
        rendered = "\n".join(output)
        # The human saw the normalized values that were hashed, not raw input.
        assert "ctf-target.example:8443 https POST /api/challenge" in rendered
        assert "CTF-TARGET.EXAMPLE" not in rendered
        assert "grant_ttl_s=3600" in rendered
        assert "max_calls=10" in rendered
    finally:
        env.store.close()


def test_normalize_field_and_display_helpers() -> None:
    with pytest.raises(UnsafeTextError):
        normalize_field("ok\x1b[2J", field="f", max_length=10)
    assert normalize_field("  token  ", field="f", max_length=10) == "token"
    with pytest.raises(UnsafeTextError):
        require_displayable("line1\nline2")
    assert terminal_safe("ok") == "ok"
