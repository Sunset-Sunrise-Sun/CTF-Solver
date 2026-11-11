"""Human confirmation channel security tests (TTY-only, exact phrase, no identity input)."""

from __future__ import annotations

import inspect
import uuid

import pytest

from ctf_solver.security.confirmation import (
    CHANNEL_LOCAL_CONSOLE,
    ConfirmationError,
    ConfirmationUnavailable,
    ConsoleConfirmationChannel,
    HumanConfirmation,
)
from tests.test_security_support import (
    FixedClock,
    scripted_channel,
)

DIGEST = "a1b2c3d4" + "0" * 56  # 64 lowercase hex chars
PREFIX = DIGEST[:8]
SUMMARY = "task=t-security01 kind=remote_target target=ctf-target.example:8443"


def test_non_tty_fails_closed_without_prompting() -> None:
    clock = FixedClock()
    prompts: list[str] = []
    channel = ConsoleConfirmationChannel(
        clock,
        input_fn=lambda prompt: prompts.append(prompt) or "SHOULD NOT HAPPEN",
        output_fn=lambda _line: None,
        is_tty=False,
        os_user="human-owner",
    )
    assert channel.available() is False
    with pytest.raises(ConfirmationUnavailable) as excinfo:
        channel.confirm(approval_digest=DIGEST, summary=SUMMARY)
    assert excinfo.value.reason_code == "confirmation_unavailable"
    with pytest.raises(ConfirmationUnavailable):
        channel.reject(approval_digest=DIGEST, summary=SUMMARY)
    assert prompts == []


def test_non_tty_stdin_detection_rejects_console(monkeypatch) -> None:
    class _FakeStdin:
        def isatty(self) -> bool:
            return False

    monkeypatch.setattr("sys.stdin", _FakeStdin())
    channel = ConsoleConfirmationChannel(
        FixedClock(), input_fn=lambda _prompt: "", output_fn=lambda _line: None
    )
    assert channel.available() is False
    with pytest.raises(ConfirmationUnavailable):
        channel.confirm(approval_digest=DIGEST, summary=SUMMARY)


def test_agent_or_mcp_process_context_is_never_a_console(monkeypatch) -> None:
    class _TtyStdin:
        def isatty(self) -> bool:
            return True

    monkeypatch.setattr("sys.stdin", _TtyStdin())
    monkeypatch.setenv("CTF_SOLVER_WORKER_TOKEN", "synthetic-worker-token")
    channel = ConsoleConfirmationChannel(
        FixedClock(), input_fn=lambda _prompt: "", output_fn=lambda _line: None
    )
    assert channel.available() is False
    with pytest.raises(ConfirmationUnavailable):
        channel.confirm(approval_digest=DIGEST, summary=SUMMARY)
    monkeypatch.delenv("CTF_SOLVER_WORKER_TOKEN")
    monkeypatch.setenv("CTF_SOLVER_IPC_URL", "tcp://127.0.0.1:1234")
    assert channel.available() is False


def test_real_tty_detection_accepts_console(monkeypatch) -> None:
    class _TtyStdin:
        def isatty(self) -> bool:
            return True

    monkeypatch.setattr("sys.stdin", _TtyStdin())
    monkeypatch.delenv("CTF_SOLVER_WORKER_TOKEN", raising=False)
    monkeypatch.delenv("CTF_SOLVER_IPC_URL", raising=False)
    channel = ConsoleConfirmationChannel(
        FixedClock(),
        input_fn=lambda _prompt: f"CONFIRM {PREFIX}",
        output_fn=lambda _line: None,
    )
    assert channel.available() is True
    confirmation = channel.confirm(approval_digest=DIGEST, summary=SUMMARY)
    assert confirmation.approval_digest == DIGEST


def test_approve_requires_display_and_exact_phrase() -> None:
    clock = FixedClock()
    output: list[str] = []
    channel = scripted_channel(clock, [f"  CONFIRM {PREFIX}  "], output=output)
    confirmation = channel.confirm(approval_digest=DIGEST, summary=SUMMARY)
    assert isinstance(confirmation, HumanConfirmation)
    assert confirmation.channel == CHANNEL_LOCAL_CONSOLE
    assert confirmation.os_user == "human-owner"
    assert confirmation.approval_digest == DIGEST
    assert confirmation.confirmed_at == clock.now_ms()
    assert confirmation.note == ""
    uuid.UUID(confirmation.confirmation_id)  # a real UUID
    rendered = "\n".join(output)
    assert PREFIX in rendered
    assert "Action:" in rendered
    assert f"CONFIRM {PREFIX}" in rendered


def test_wrong_phrase_never_approves_and_attempts_are_bounded() -> None:
    clock = FixedClock()
    prompts: list[str] = []
    output: list[str] = []
    channel = scripted_channel(
        clock,
        ["yes", "approve", "CONFIRM deadbeef", "CONFIRM"],
        max_attempts=3,
        inputs_seen=prompts,
        output=output,
    )
    with pytest.raises(ConfirmationError) as excinfo:
        channel.confirm(approval_digest=DIGEST, summary=SUMMARY)
    assert excinfo.value.reason_code == "confirmation_error"
    assert len(prompts) == 3  # bounded: the 4th scripted answer is never read
    assert "NOT approved" in "\n".join(output)


def test_lowercase_phrase_is_not_accepted() -> None:
    channel = scripted_channel(FixedClock(), [f"confirm {PREFIX}"], max_attempts=1)
    with pytest.raises(ConfirmationError):
        channel.confirm(approval_digest=DIGEST, summary=SUMMARY)


def test_missing_phrase_and_eof_fail_closed() -> None:
    with pytest.raises(ConfirmationError):
        scripted_channel(FixedClock(), ["", "   "], max_attempts=2).confirm(
            approval_digest=DIGEST, summary=SUMMARY
        )
    with pytest.raises(ConfirmationError):
        scripted_channel(FixedClock(), [EOFError("no input")]).confirm(
            approval_digest=DIGEST, summary=SUMMARY
        )
    with pytest.raises(ConfirmationError):
        scripted_channel(FixedClock(), [KeyboardInterrupt()]).confirm(
            approval_digest=DIGEST, summary=SUMMARY
        )


def test_reject_happy_path_and_phrase_separation() -> None:
    clock = FixedClock()
    confirmation = scripted_channel(clock, ["REJECT"]).reject(
        approval_digest=DIGEST, summary=SUMMARY
    )
    assert confirmation.channel == CHANNEL_LOCAL_CONSOLE
    assert confirmation.os_user == "human-owner"
    assert confirmation.note == "explicit human rejection"

    # Approving phrase must not reject, and rejecting phrase must not approve.
    with pytest.raises(ConfirmationError):
        scripted_channel(clock, [f"CONFIRM {PREFIX}"], max_attempts=1).reject(
            approval_digest=DIGEST, summary=SUMMARY
        )
    with pytest.raises(ConfirmationError):
        scripted_channel(clock, ["REJECT"], max_attempts=1).confirm(
            approval_digest=DIGEST, summary=SUMMARY
        )


def test_os_user_comes_from_getpass_when_not_injected(monkeypatch) -> None:
    monkeypatch.setattr(
        "ctf_solver.security.confirmation.getpass.getuser", lambda: "console-user"
    )
    channel = scripted_channel(
        FixedClock(), [f"CONFIRM {PREFIX}"], os_user=None, is_tty=True
    )
    confirmation = channel.confirm(approval_digest=DIGEST, summary=SUMMARY)
    assert confirmation.os_user == "console-user"


def test_unknown_os_user_fails_closed(monkeypatch) -> None:
    def _boom() -> str:
        raise OSError("no user identity")

    monkeypatch.setattr("ctf_solver.security.confirmation.getpass.getuser", _boom)
    channel = scripted_channel(
        FixedClock(), [f"CONFIRM {PREFIX}"], os_user=None, is_tty=True
    )
    with pytest.raises(ConfirmationUnavailable):
        channel.confirm(approval_digest=DIGEST, summary=SUMMARY)


def test_caller_cannot_supply_an_approver_identity() -> None:
    confirm_params = inspect.signature(ConsoleConfirmationChannel.confirm).parameters
    assert "approver" not in confirm_params
    assert "approved" not in confirm_params
    reject_params = inspect.signature(ConsoleConfirmationChannel.reject).parameters
    assert "approver" not in reject_params
    assert "approver" not in {field.name for field in HumanConfirmation.__dataclass_fields__.values()}
    channel = scripted_channel(FixedClock(), [f"CONFIRM {PREFIX}"])
    with pytest.raises(TypeError):
        channel.confirm(  # type: ignore[call-arg]
            approval_digest=DIGEST, summary=SUMMARY, approver="model-says-approved"
        )
    with pytest.raises(TypeError):
        channel.confirm(  # type: ignore[call-arg]
            approval_digest=DIGEST, summary=SUMMARY, approved="true"
        )


def test_malformed_digest_and_empty_summary_fail_closed() -> None:
    channel = scripted_channel(FixedClock(), [f"CONFIRM {PREFIX}"])
    with pytest.raises(ConfirmationError):
        channel.confirm(approval_digest="", summary=SUMMARY)
    with pytest.raises(ConfirmationError):
        channel.confirm(approval_digest="not-a-digest", summary=SUMMARY)
    with pytest.raises(ConfirmationError):
        channel.confirm(approval_digest=DIGEST, summary="")
    with pytest.raises(ConfirmationError):
        channel.confirm(approval_digest=None, summary=SUMMARY)  # type: ignore[arg-type]


def test_channel_validation_for_attempts_and_unprintable_prompt() -> None:
    with pytest.raises(ConfirmationError):
        ConsoleConfirmationChannel(FixedClock(), max_attempts=0)
    with pytest.raises(ConfirmationError):
        ConsoleConfirmationChannel(FixedClock(), max_attempts="three")  # type: ignore[arg-type]

    def _broken_output(_line: str) -> None:
        raise OSError("console closed")

    channel = ConsoleConfirmationChannel(
        FixedClock(),
        input_fn=lambda _prompt: f"CONFIRM {PREFIX}",
        output_fn=_broken_output,
        is_tty=True,
        os_user="human-owner",
    )
    with pytest.raises(ConfirmationError):
        channel.confirm(approval_digest=DIGEST, summary=SUMMARY)
