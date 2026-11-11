"""Local-console human confirmation channel (Round 2 P0 security).

Threat model
------------
The Agent/model is an untrusted proposal source. It may ask the Manager to
*request* an approval, but it must never be able to decide one. The only
accepted decision path is a real human, sitting at the local interactive
console, typing an exact phrase bound to the digest of the proposed action.

Hard rules implemented here (docs/ROUND_2_INTERFACES.md 2.1):

- The channel is available only on a real TTY and only outside an
  agent/MCP-driven process context. Non-interactive callers fail closed with
  :class:`ConfirmationUnavailable`.
- The action summary and ``approval_digest[:8]`` are always displayed before
  input. The human must type exactly ``CONFIRM <digest[:8]>`` to approve or
  ``REJECT`` to reject; any other answer is refused and attempts are bounded.
- The recorded OS user comes from the local process identity
  (``getpass.getuser()``) or an explicit test injection; there is no
  parameter anywhere that lets a caller supply an approver name.
"""

from __future__ import annotations

import getpass
import os
import re
import sys
import uuid
from dataclasses import asdict, dataclass
from typing import Any, Callable

from ..core.errors import CtfSolverError
from ..core.protocols import Clock, SystemClock

CHANNEL_LOCAL_CONSOLE = "local_console"

#: A human confirmation binds one full SHA-256 action digest.
_DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")

#: Environment markers that only exist in agent/MCP-driven processes. A process
#: carrying one of these must never be able to pop a local human prompt, even
#: if stdin happened to be attached to a console.
_MCP_ENV_MARKERS: tuple[str, ...] = (
    "CTF_SOLVER_WORKER_TOKEN",
    "CTF_SOLVER_IPC_URL",
)


class ConfirmationError(CtfSolverError):
    """The human confirmation could not be obtained; nothing was approved."""

    reason_code = "confirmation_error"


class ConfirmationUnavailable(ConfirmationError):
    """No local interactive console is available for a human decision."""

    reason_code = "confirmation_unavailable"


@dataclass(frozen=True)
class HumanConfirmation:
    """One human decision recorded on a local console.

    ``approval_digest`` is the digest of the exact proposed action that was
    displayed to (and confirmed by) the human. The Manager refuses to bind a
    confirmation to an approval whose digest differs.
    """

    channel: str
    os_user: str
    confirmed_at: int
    confirmation_id: str
    approval_digest: str
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _default_input(prompt: str) -> str:
    return input(prompt)


def _default_output(text: str) -> None:
    print(text)


class ConsoleConfirmationChannel:
    """Interactive local-console confirmation (the only human decision channel)."""

    def __init__(
        self,
        clock: Clock | None = None,
        *,
        input_fn: Callable[[str], str] | None = None,
        output_fn: Callable[[str], Any] | None = None,
        is_tty: bool | None = None,
        os_user: str | None = None,
        max_attempts: int = 3,
    ) -> None:
        self.clock: Clock = clock or SystemClock()
        self._input_fn = input_fn or _default_input
        self._output_fn = output_fn or _default_output
        self._is_tty = is_tty
        injected_user = str(os_user or "").strip()
        self._os_user = injected_user or None
        try:
            attempts = int(max_attempts)
        except (TypeError, ValueError) as exc:
            raise ConfirmationError("max_attempts must be a positive integer") from exc
        if attempts < 1:
            raise ConfirmationError("max_attempts must be a positive integer")
        self.max_attempts = attempts

    # ------------------------------------------------------------------
    # Availability
    # ------------------------------------------------------------------

    def available(self) -> bool:
        """True only for a local interactive console TTY.

        Tests inject ``is_tty`` explicitly. The real check never trusts an
        agent/MCP process context: stdio-pipe MCP servers report no TTY and the
        worker/MCP environment markers force an unavailable channel.
        """

        if self._is_tty is not None:
            return bool(self._is_tty)
        for marker in _MCP_ENV_MARKERS:
            if str(os.environ.get(marker) or "").strip():
                return False
        try:
            stream = sys.stdin
            return bool(stream is not None and stream.isatty())
        except (AttributeError, OSError, ValueError):  # pragma: no cover - defensive
            return False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def confirm(self, *, approval_digest: str, summary: str) -> HumanConfirmation:
        """Ask the human to approve exactly one proposed action."""

        return self._interact(approval_digest=approval_digest, summary=summary, approve=True)

    def reject(self, *, approval_digest: str, summary: str) -> HumanConfirmation:
        """Ask the human to explicitly reject exactly one proposed action."""

        return self._interact(approval_digest=approval_digest, summary=summary, approve=False)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _require_digest(self, approval_digest: Any) -> str:
        digest = str(approval_digest or "").strip().lower()
        if not _DIGEST_PATTERN.match(digest):
            raise ConfirmationError(
                "the approval digest is malformed; refusing to ask for a human decision"
            )
        return digest

    def _require_summary(self, summary: Any) -> str:
        # Round 2 P0-2: a summary is displayed on a real terminal. It must be
        # exactly the canonical, digest-bound action description and may never
        # contain control/format characters, CR/LF injection, ANSI/OSC escapes
        # or bidi overrides. Unsafe summaries fail closed instead of being
        # "cleaned" while an unnormalized payload is approved.
        from .textsafe import UnsafeTextError, require_displayable

        try:
            return require_displayable(summary, field="confirmation summary")
        except UnsafeTextError as exc:
            raise ConfirmationError(
                f"{exc.message}; refusing to collect a human decision"
            ) from exc

    def _resolve_os_user(self) -> str:
        if self._os_user is not None:
            return self._os_user
        try:
            user = str(getpass.getuser() or "").strip()
        except Exception:  # noqa: BLE001 - identity failure must fail closed
            user = ""
        if not user:
            raise ConfirmationUnavailable(
                "cannot determine the local OS user; refusing to record a confirmation"
            )
        return user

    def _say(self, text: str) -> None:
        from .textsafe import terminal_safe

        # Every line written to the terminal passes through the terminal-safe
        # escaper; canonical summaries are validated before they reach here.
        try:
            self._output_fn(terminal_safe(text))
        except Exception as exc:  # noqa: BLE001 - undisplayed consent is invalid
            raise ConfirmationError(
                f"the confirmation prompt could not be displayed ({type(exc).__name__}); "
                "refusing to collect a human decision"
            ) from exc

    def _interact(self, *, approval_digest: Any, summary: Any, approve: bool) -> HumanConfirmation:
        digest = self._require_digest(approval_digest)
        summary_text = self._require_summary(summary)
        if not self.available():
            raise ConfirmationUnavailable(
                "human confirmation requires the local interactive console (TTY); "
                "non-interactive and agent/MCP contexts cannot approve or reject actions"
            )
        os_user = self._resolve_os_user()
        prefix = digest[:8]
        expected = f"CONFIRM {prefix}" if approve else "REJECT"

        self._say("=== CTF-Solver human confirmation ===")
        self._say(f"Action: {summary_text}")
        self._say(f"Digest: {prefix}")
        if approve:
            self._say(f"Type exactly '{expected}' to APPROVE this action.")
        else:
            self._say(f"Type exactly '{expected}' to REJECT this action.")
        self._say("Anything else refuses the action; this decision is not delegable.")

        for attempt in range(1, self.max_attempts + 1):
            try:
                answer = self._input_fn(f"confirmation [{attempt}/{self.max_attempts}]> ")
            except (EOFError, KeyboardInterrupt) as exc:
                raise ConfirmationError(
                    "confirmation input was aborted; the action was NOT approved"
                ) from exc
            if str(answer).strip() == expected:
                return HumanConfirmation(
                    channel=CHANNEL_LOCAL_CONSOLE,
                    os_user=os_user,
                    confirmed_at=int(self.clock.now_ms()),
                    confirmation_id=str(uuid.uuid4()),
                    approval_digest=digest,
                    note="" if approve else "explicit human rejection",
                )
            self._say("Invalid confirmation phrase; the action was NOT approved.")

        raise ConfirmationError(
            f"confirmation attempts exhausted after {self.max_attempts} attempt(s); "
            "the action was NOT approved",
            details={"max_attempts": self.max_attempts},
        )


__all__ = [
    "CHANNEL_LOCAL_CONSOLE",
    "ConfirmationError",
    "ConfirmationUnavailable",
    "ConsoleConfirmationChannel",
    "HumanConfirmation",
]
