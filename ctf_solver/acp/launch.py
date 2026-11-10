"""Exact argv construction for the audited Harness ACP server (Round 2 section 3.3).

The only audited ACP entrypoint is ``dsh --profile acp`` (stdio ND-JSON
JSON-RPC 2.0). The Manager must spawn an argv array with ``shell=False``; this
module is the single place that knows the exact command shape:

* a native executable ``dsh.exe`` / ``dsh`` -> ``[exe, "--profile", "acp", *rest]``;
* a ``.cmd`` / ``.bat`` launcher (the shipped Windows CLI) -> wrapped by
  ``COMSPEC`` because ``CreateProcess`` cannot execute batch files directly:
  ``[COMSPEC, "/c", exe, "--profile", "acp", *rest]``.

A launcher string is never split by a shell here, and a shell command string is
never accepted: callers either get an argv list or :class:`ConfigError`.
"""

from __future__ import annotations

import os
from typing import Mapping

from ..core.config import discover_acp_command
from ..core.errors import ConfigError

#: ACP profile name in the audited Harness (`dsh --profile acp`).
ACP_PROFILE = "acp"

#: The two profile arguments every ACP launch command must contain.
ACP_PROFILE_ARGS: tuple[str, str] = ("--profile", ACP_PROFILE)

#: Launcher extensions that require the Windows command-processor wrapper.
_CALL_SCRIPT_EXTENSIONS = (".cmd", ".bat")


def _comspec(env: Mapping[str, str] | None = None) -> str:
    """Return the command processor used to wrap ``.cmd``/``.bat`` launchers."""

    source = os.environ if env is None else env
    value = str(source.get("COMSPEC", "") or "").strip()
    if value:
        return value
    fallback = str(os.environ.get("COMSPEC", "") or "").strip()
    return fallback or "cmd.exe"


def _validate_launcher(launcher: object) -> list[str]:
    if isinstance(launcher, (list, tuple)):
        entries = list(launcher)
    else:
        # A string would be a shell command line: never accepted.
        raise ConfigError("ACP launcher must be an argv array, not a shell string")
    if not entries:
        raise ConfigError("empty ACP launcher command")
    for entry in entries:
        if not isinstance(entry, str) or not entry:
            raise ConfigError("ACP launcher entries must be non-empty strings")
    return [str(entry) for entry in entries]


def _build(launcher: object, *, comspec: str) -> list[str]:
    entries = _validate_launcher(launcher)
    executable, rest = entries[0], entries[1:]
    if executable.lower().endswith(_CALL_SCRIPT_EXTENSIONS):
        return [comspec, "/c", executable, *ACP_PROFILE_ARGS, *rest]
    return [executable, *ACP_PROFILE_ARGS, *rest]


def build_acp_command(launcher: list[str]) -> list[str]:
    """Return the exact argv for the audited ACP server ``dsh --profile acp``.

    ``.cmd``/``.bat`` launchers are wrapped as
    ``[COMSPEC, "/c", exe, "--profile", "acp", *rest]``; every other executable
    as ``[exe, "--profile", "acp", *rest]``. Empty/invalid launchers raise
    :class:`~ctf_solver.core.errors.ConfigError`; a shell string is never built.
    """

    return _build(launcher, comspec=_comspec())


def build_default_acp_command(env: dict[str, str] | None = None) -> list[str] | None:
    """Discover the managed launcher and return the ACP launch argv.

    Returns ``None`` when no launcher can be discovered so callers report the
    missing platform dependency instead of guessing. ``env`` is used for both
    discovery (``CTF_SOLVER_ACP_COMMAND`` / ``LOCALAPPDATA``) and ``COMSPEC``.
    """

    environ = dict(os.environ if env is None else env)
    launcher = discover_acp_command(environ)
    if launcher is None:
        return None
    return _build(launcher, comspec=_comspec(environ))
