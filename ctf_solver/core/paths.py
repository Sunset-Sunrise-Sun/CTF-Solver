"""Filesystem containment helpers.

Broker path policy is part of the fail-closed security boundary: every cwd,
input and output path must resolve (after symlink/junction resolution) inside
an authorized root. Windows uses case-insensitive comparison.
"""

from __future__ import annotations

import os
from pathlib import Path


def resolve_path(path: str | os.PathLike[str]) -> Path:
    """Resolve to an absolute, symlink-free path without requiring existence."""

    raw = os.fspath(path)
    if not raw:
        raise ValueError("empty path")
    if "\x00" in raw:
        raise ValueError("path contains NUL byte")
    resolved = os.path.realpath(os.path.abspath(raw))
    return Path(resolved)


def _norm(path: str) -> str:
    return os.path.normcase(os.path.normpath(path))


def is_within(child: str | os.PathLike[str], root: str | os.PathLike[str]) -> bool:
    """True when ``child`` is ``root`` itself or a descendant of ``root``."""

    try:
        child_path = resolve_path(child)
        root_path = resolve_path(root)
    except (OSError, ValueError):
        return False
    child_n = _norm(str(child_path))
    root_n = _norm(str(root_path))
    if child_n == root_n:
        return True
    return child_n.startswith(root_n.rstrip("\\/") + os.sep)


def relative_inside(child: str | os.PathLike[str], root: str | os.PathLike[str]) -> str:
    """Return the POSIX-style relative path of ``child`` inside ``root``."""

    child_path = resolve_path(child)
    root_path = resolve_path(root)
    if not is_within(child_path, root_path):
        raise ValueError(f"path {child_path} is outside authorized root {root_path}")
    return Path(os.path.relpath(child_path, root_path)).as_posix()


def ensure_relative_safe(value: str) -> str:
    """Reject absolute paths and traversal in a caller-declared relative path."""

    if not isinstance(value, str) or not value.strip():
        raise ValueError("empty path")
    if "\x00" in value:
        raise ValueError("path contains NUL byte")
    normalized = value.replace("\\", "/")
    if normalized.startswith("/") or (len(normalized) > 1 and normalized[1] == ":"):
        raise ValueError(f"absolute paths are not allowed: {value!r}")
    parts = [part for part in normalized.split("/") if part not in ("", ".")]
    if any(part == ".." for part in parts):
        raise ValueError(f"path traversal is not allowed: {value!r}")
    if not parts:
        raise ValueError("empty path")
    return "/".join(parts)
