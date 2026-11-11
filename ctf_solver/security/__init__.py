"""Round 2 human-confirmation security package.

The only way a sensitive action (remote target access, untrusted code,
software installation, privileged tool action) can be approved is an explicit
confirmation by the local OS user on the local interactive console. Model /
MCP callers can *request* approvals, but they can never decide one, and an
identity string supplied by a caller is never accepted as an approver.
"""

from __future__ import annotations

from .confirmation import (
    CHANNEL_LOCAL_CONSOLE,
    ConfirmationError,
    ConfirmationUnavailable,
    ConsoleConfirmationChannel,
    HumanConfirmation,
)

__all__ = [
    "CHANNEL_LOCAL_CONSOLE",
    "ConfirmationError",
    "ConfirmationUnavailable",
    "ConsoleConfirmationChannel",
    "HumanConfirmation",
]
