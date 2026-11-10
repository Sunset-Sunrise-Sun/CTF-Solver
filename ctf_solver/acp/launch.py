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
from pathlib import Path
from typing import Mapping

from ..core.config import discover_acp_command
from ..core.errors import ConfigError

#: ACP profile name in the audited Harness (`dsh --profile acp`).
ACP_PROFILE = "acp"

#: The two profile arguments every ACP launch command must contain.
ACP_PROFILE_ARGS: tuple[str, str] = ("--profile", ACP_PROFILE)

#: Project-level privacy patch argument (Round 2 P0-3).
ACP_PATCH_ARG = "--patch"

#: Launcher extensions that require the Windows command-processor wrapper.
_CALL_SCRIPT_EXTENSIONS = (".cmd", ".bat")


def build_privacy_patch_args(patch_path: str | os.PathLike[str]) -> list[str]:
    """Return the exact ``["--patch", <absolute-project-patch>]`` arguments.

    Round 2 P0-3 requires every Manager-managed ACP Worker session to compose
    the project privacy patch. The path must be absolute and the file must
    exist; otherwise the launch is refused (fail closed) rather than silently
    running an unprotected Harness profile.
    """

    if not isinstance(patch_path, (str, os.PathLike)):
        raise ConfigError("ACP privacy patch path must be a filesystem path")
    try:
        candidate = Path(os.fspath(patch_path)).expanduser()
    except (OSError, ValueError) as exc:
        raise ConfigError(f"invalid ACP privacy patch path: {patch_path!r}") from exc
    if not candidate.is_absolute():
        raise ConfigError(
            f"ACP privacy patch path must be absolute (got {candidate}); refusing to "
            "depend on the current working directory"
        )
    try:
        path = candidate.resolve(strict=False)
    except (OSError, ValueError) as exc:
        raise ConfigError(f"invalid ACP privacy patch path: {patch_path!r}") from exc
    if not path.is_file():
        raise ConfigError(
            f"ACP privacy patch is missing: {path}; refusing to launch an "
            "unprotected Harness ACP session"
        )
    return [ACP_PATCH_ARG, str(path)]


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


def _build(launcher: object, *, comspec: str, patch_args: list[str] | None = None) -> list[str]:
    entries = _validate_launcher(launcher)
    executable, rest = entries[0], entries[1:]
    extra = list(patch_args or [])
    # Protected arguments are appended after the launcher's own fixed arguments.
    # This keeps interpreter-style test launchers (``python -m fake_server``) valid
    # while still guaranteeing ``--profile acp --patch <abs>`` on every launch.
    if executable.lower().endswith(_CALL_SCRIPT_EXTENSIONS):
        return [comspec, "/c", executable, *rest, *ACP_PROFILE_ARGS, *extra]
    return [executable, *rest, *ACP_PROFILE_ARGS, *extra]


def build_acp_command(
    launcher: list[str], *, privacy_patch: str | os.PathLike[str] | None = None
) -> list[str]:
    """Return the exact argv for the audited ACP server ``dsh --profile acp``.

    ``.cmd``/``.bat`` launchers are wrapped as
    ``[COMSPEC, "/c", exe, "--profile", "acp", *rest]``; every other executable
    as ``[exe, "--profile", "acp", *rest]``. When ``privacy_patch`` is given,
    the absolute ``--patch <path>`` arguments are appended after the profile and
    the patch file must exist. Empty/invalid launchers raise
    :class:`~ctf_solver.core.errors.ConfigError`; a shell string is never built.
    """

    patch_args = build_privacy_patch_args(privacy_patch) if privacy_patch else None
    return _build(launcher, comspec=_comspec(), patch_args=patch_args)


def build_default_acp_command(
    env: dict[str, str] | None = None,
    *,
    privacy_patch: str | os.PathLike[str] | None = None,
) -> list[str] | None:
    """Discover the managed launcher and return the ACP launch argv.

    Returns ``None`` when no launcher can be discovered so callers report the
    missing platform dependency instead of guessing. ``env`` is used for both
    discovery (``CTF_SOLVER_ACP_COMMAND`` / ``LOCALAPPDATA``) and ``COMSPEC``.
    """

    environ = dict(os.environ if env is None else env)
    launcher = discover_acp_command(environ)
    if launcher is None:
        return None
    patch_args = build_privacy_patch_args(privacy_patch) if privacy_patch else None
    return _build(launcher, comspec=_comspec(environ), patch_args=patch_args)
