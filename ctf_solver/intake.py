"""Controlled challenge-file intake (Round 2 P1).

``IntakeService`` is the only path by which Worker/model-visible challenge files
enter a Task workspace. The *source* root is a project-owned intake directory
(``<project>/challenge-uploads/`` by default, exposed as
``SolverConfig.intake_root``); callers supply only **relative** file names inside
that root. The service resolves, validates, copies and hashes the bytes under
Manager control and never exposes an arbitrary host path to the model.

Security rules (docs/ROUND_2_INTERFACES.md §4.1):

- the intake root must exist, be a directory, and not be a symlink/reparse point;
- entries must be relative (POSIX or Windows separators); absolute paths,
  drive-qualified paths, ``..`` traversal, NUL/control characters, empty entries
  and Windows reserved device names are rejected;
- symlinks are rejected for the entry *and every ancestor component* (junctions
  are reparse points, detected through ``st_file_attributes``);
- non-regular files (directories, devices, pipes) are rejected;
- the resolved source must stay inside the intake root (``realpath`` checks);
- duplicate target ``rel_path`` values are rejected (case-insensitively, because
  the destination file system is case-insensitive on Windows);
- file-count and total-byte limits are enforced before anything is copied;
- copies go to ``<workspace>/inputs/<rel_path>`` with ``mkdir(parents=True)``.

The module performs no shell invocation and no network access.
"""

from __future__ import annotations

import mimetypes
import os
import stat
from pathlib import Path
from typing import Any

from .core.canonical import file_sha256
from .core.errors import CtfSolverError
from .core.protocols import Clock, SystemClock
from .core.types import ImportedInput

__all__ = [
    "DEFAULT_MAX_FILES",
    "DEFAULT_MAX_TOTAL_BYTES",
    "DEFAULT_MEDIA_TYPE",
    "IntakeError",
    "IntakeService",
]

DEFAULT_MAX_FILES = 100
DEFAULT_MAX_TOTAL_BYTES = 256 * 1024 * 1024
DEFAULT_MEDIA_TYPE = "application/octet-stream"

#: Maximum accepted length of one relative intake path (defensive bound).
MAX_REL_PATH_CHARS = 1024

#: Windows reserved device names (rejected so a copy can never target a device).
_WINDOWS_RESERVED_NAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL", "CLOCK$"}
    | {f"COM{i}" for i in range(1, 10)}
    | {f"LPT{i}" for i in range(1, 10)}
)

_REPARSE_ATTRIBUTE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x0400)


class IntakeError(CtfSolverError):
    """Raised when a challenge-file intake request violates the intake policy."""

    reason_code = "intake_error"


# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------


def _has_control_char(value: str) -> bool:
    return any(ord(char) < 32 or ord(char) == 127 for char in value)


def _is_reparse_point(path: Path) -> bool:
    """True for a symlink or any Windows reparse point (junction, etc.)."""

    try:
        info = os.lstat(path)
    except OSError:
        return False
    if stat.S_ISLNK(info.st_mode):
        return True
    attributes = getattr(info, "st_file_attributes", 0)
    return bool(attributes & _REPARSE_ATTRIBUTE)


def _normcase(value: str) -> str:
    return os.path.normcase(os.path.normpath(value))


def _is_within(child: Path, root: Path) -> bool:
    child_n = _normcase(str(child))
    root_n = _normcase(str(root))
    if child_n == root_n:
        return True
    return child_n.startswith(root_n.rstrip("\\/") + os.sep)


def _media_type(rel_path: str) -> str:
    guessed, _encoding = mimetypes.guess_type(rel_path)
    return guessed or DEFAULT_MEDIA_TYPE


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------


class IntakeService:
    """Copy validated challenge files from one intake root into Task workspaces."""

    def __init__(
        self,
        intake_root: str | os.PathLike[str],
        *,
        max_files: int = DEFAULT_MAX_FILES,
        max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
        clock: Clock | None = None,
    ) -> None:
        if intake_root is None or str(os.fspath(intake_root)).strip() == "":
            raise IntakeError("intake_root is required")
        root = Path(os.path.abspath(os.fspath(intake_root)))
        if not root.exists():
            raise IntakeError(
                f"intake root does not exist: {root}",
                details={"code": "intake_root_missing", "path": str(root)},
            )
        if _is_reparse_point(root):
            raise IntakeError(
                f"intake root must not be a symlink/reparse point: {root}",
                details={"code": "intake_root_symlink", "path": str(root)},
            )
        if not root.is_dir():
            raise IntakeError(
                f"intake root is not a directory: {root}",
                details={"code": "intake_root_not_directory", "path": str(root)},
            )
        if isinstance(max_files, bool) or not isinstance(max_files, int) or max_files <= 0:
            raise IntakeError("max_files must be a positive integer")
        if (
            isinstance(max_total_bytes, bool)
            or not isinstance(max_total_bytes, int)
            or max_total_bytes <= 0
        ):
            raise IntakeError("max_total_bytes must be a positive integer")
        self._root = root
        self._root_real = Path(os.path.realpath(root))
        self.max_files = int(max_files)
        self.max_total_bytes = int(max_total_bytes)
        self._clock: Clock = clock if clock is not None else SystemClock()

    @property
    def intake_root(self) -> Path:
        return self._root

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def import_files(
        self,
        *,
        task_id: str,
        workspace: str | os.PathLike[str],
        supplied_files: list[str],
    ) -> list[ImportedInput]:
        """Validate and copy ``supplied_files`` into ``<workspace>/inputs``."""

        if not isinstance(task_id, str) or not task_id.strip():
            raise IntakeError("task_id must be a non-empty string")
        if _has_control_char(task_id):
            raise IntakeError("task_id must not contain control characters")
        if workspace is None or str(os.fspath(workspace)).strip() == "":
            raise IntakeError("workspace is required")
        if not isinstance(supplied_files, list):
            raise IntakeError("supplied_files must be a list of relative paths")
        if len(supplied_files) > self.max_files:
            raise IntakeError(
                f"too many supplied files: {len(supplied_files)} > max_files={self.max_files}",
                details={"code": "limit_files", "count": len(supplied_files), "max_files": self.max_files},
            )
        if not supplied_files:
            return []

        workspace_path = Path(os.path.abspath(os.fspath(workspace)))
        inputs_dir = workspace_path / "inputs"

        # ---- phase 1: validate everything, nothing is copied on error --------
        plans: list[tuple[str, Path, int]] = []
        seen_rel_paths: set[str] = set()
        seen_sources: set[str] = set()
        total_bytes = 0
        for entry in supplied_files:
            rel_path = self._validate_entry(entry)
            key = rel_path.casefold()
            if key in seen_rel_paths:
                raise IntakeError(
                    f"duplicate supplied file target: {rel_path!r}",
                    details={"code": "duplicate", "entry": str(entry), "rel_path": rel_path},
                )
            source = self._resolve_source(rel_path, entry)
            source_key = _normcase(str(source))
            if source_key in seen_sources:
                raise IntakeError(
                    f"duplicate supplied source file: {rel_path!r}",
                    details={"code": "duplicate_source", "entry": str(entry), "rel_path": rel_path},
                )
            try:
                info = os.lstat(source)
            except OSError as exc:
                raise IntakeError(
                    f"cannot stat supplied file {rel_path!r}: {exc}",
                    details={"code": "stat_failed", "entry": str(entry)},
                ) from exc
            if not stat.S_ISREG(info.st_mode):
                raise IntakeError(
                    f"supplied entry is not a regular file: {rel_path!r}",
                    details={"code": "not_regular_file", "entry": str(entry)},
                )
            size = int(info.st_size)
            total_bytes += size
            if total_bytes > self.max_total_bytes:
                raise IntakeError(
                    f"supplied files exceed the total size limit "
                    f"({total_bytes} > max_total_bytes={self.max_total_bytes})",
                    details={
                        "code": "limit_bytes",
                        "total_bytes": total_bytes,
                        "max_total_bytes": self.max_total_bytes,
                    },
                )
            plans.append((rel_path, source, size))
            seen_rel_paths.add(key)
            seen_sources.add(source_key)

        # ---- phase 2: copy each file, hash exactly the copied bytes ----------
        if inputs_dir.exists() and _is_reparse_point(inputs_dir):
            raise IntakeError(
                f"workspace inputs directory must not be a symlink/reparse point: {inputs_dir}",
                details={"code": "workspace_symlink", "path": str(inputs_dir)},
            )
        now_ms = int(self._clock.now_ms())
        inputs: list[ImportedInput] = []
        created: list[Path] = []
        try:
            for rel_path, source, expected_size in plans:
                destination = inputs_dir / Path(rel_path)
                destination.parent.mkdir(parents=True, exist_ok=True)
                # A symlink/reparse destination is never followed, whether or not
                # it currently resolves to an existing file.
                if _is_reparse_point(destination):
                    raise IntakeError(
                        f"destination is a symlink/reparse point: {rel_path!r}",
                        details={"code": "destination_symlink", "rel_path": rel_path},
                    )
                if destination.is_dir():
                    raise IntakeError(
                        f"destination collides with a directory: {rel_path!r}",
                        details={"code": "destination_directory", "rel_path": rel_path},
                    )
                created.append(destination)
                copied = self._copy_file(source, destination, rel_path)
                if copied != expected_size:
                    raise IntakeError(
                        f"supplied file changed size while being imported: {rel_path!r}",
                        details={
                            "code": "source_changed",
                            "rel_path": rel_path,
                            "expected": expected_size,
                            "actual": copied,
                        },
                    )
                inputs.append(
                    ImportedInput(
                        rel_path=rel_path,
                        sha256=file_sha256(destination),
                        size=copied,
                        media_type=_media_type(rel_path),
                        source_rel_path=rel_path,
                        imported_at=now_ms,
                    )
                )
        except BaseException:
            # Never leave a half-copied intake behind (also removes overwritten
            # partial files from this call; earlier committed imports are intact).
            for path in created:
                try:
                    path.unlink(missing_ok=True)
                except OSError:
                    pass
            raise
        return inputs

    # ------------------------------------------------------------------
    # Validation internals
    # ------------------------------------------------------------------

    def _validate_entry(self, entry: Any) -> str:
        if not isinstance(entry, str):
            raise IntakeError(
                f"supplied file entry must be a string, got {type(entry).__name__}",
                details={"code": "entry_not_string"},
            )
        raw = entry
        if raw.strip() == "":
            raise IntakeError(
                "supplied file entry must not be empty",
                details={"code": "empty_entry", "entry": raw},
            )
        if raw != raw.strip():
            raise IntakeError(
                f"supplied file entry must not have leading/trailing whitespace: {raw!r}",
                details={"code": "whitespace_entry", "entry": raw},
            )
        if len(raw) > MAX_REL_PATH_CHARS:
            raise IntakeError(
                f"supplied file entry is too long ({len(raw)} > {MAX_REL_PATH_CHARS})",
                details={"code": "entry_too_long", "entry": raw[:64]},
            )
        if _has_control_char(raw):
            raise IntakeError(
                f"supplied file entry contains a NUL/control character: {raw!r}",
                details={"code": "control_char", "entry": raw},
            )
        normalized = raw.replace("\\", "/")
        if normalized.startswith("/"):
            raise IntakeError(
                f"absolute paths are not allowed in intake: {raw!r}",
                details={"code": "absolute_path", "entry": raw},
            )
        if len(normalized) >= 2 and normalized[1] == ":":
            raise IntakeError(
                f"drive-qualified paths are not allowed in intake: {raw!r}",
                details={"code": "drive_qualified", "entry": raw},
            )
        parts = normalized.split("/")
        if any(part in ("", ".") for part in parts):
            raise IntakeError(
                f"supplied file entry has an empty or '.' path component: {raw!r}",
                details={"code": "invalid_component", "entry": raw},
            )
        if any(part == ".." for part in parts):
            raise IntakeError(
                f"path traversal is not allowed in intake: {raw!r}",
                details={"code": "path_traversal", "entry": raw},
            )
        for part in parts:
            stem = part.split(".", 1)[0].upper()
            if stem in _WINDOWS_RESERVED_NAMES:
                raise IntakeError(
                    f"Windows reserved device name is not allowed in intake: {raw!r}",
                    details={"code": "reserved_name", "entry": raw},
                )
            if part.endswith(" ") or part.endswith("."):
                raise IntakeError(
                    f"supplied file entry has a trailing space/dot component: {raw!r}",
                    details={"code": "invalid_component", "entry": raw},
                )
        return "/".join(parts)

    def _resolve_source(self, rel_path: str, original: Any) -> Path:
        parts = rel_path.split("/")
        current = self._root_real
        for index, part in enumerate(parts):
            current = current / part
            if _is_reparse_point(current):
                raise IntakeError(
                    f"symlink/reparse point is not allowed in intake path: {rel_path!r}",
                    details={
                        "code": "symlink_rejected",
                        "entry": str(original),
                        "component": "/".join(parts[: index + 1]),
                    },
                )
        try:
            resolved = Path(os.path.realpath(current))
        except OSError as exc:  # pragma: no cover - platform edge
            raise IntakeError(
                f"cannot resolve supplied file {rel_path!r}: {exc}",
                details={"code": "resolve_failed", "entry": str(original)},
            ) from exc
        if not _is_within(resolved, self._root_real):
            raise IntakeError(
                f"supplied file resolves outside the intake root: {rel_path!r}",
                details={"code": "outside_root", "entry": str(original)},
            )
        if not resolved.exists():
            raise IntakeError(
                f"supplied file does not exist in the intake root: {rel_path!r}",
                details={"code": "missing", "entry": str(original)},
            )
        try:
            info = os.lstat(resolved)
        except OSError as exc:  # pragma: no cover - race
            raise IntakeError(
                f"cannot stat supplied file {rel_path!r}: {exc}",
                details={"code": "stat_failed", "entry": str(original)},
            ) from exc
        if not stat.S_ISREG(info.st_mode):
            raise IntakeError(
                f"supplied entry is not a regular file: {rel_path!r}",
                details={"code": "not_regular_file", "entry": str(original)},
            )
        return resolved

    def _copy_file(self, source: Path, destination: Path, rel_path: str) -> int:
        """Stream-copy ``source`` to ``destination``; return the copied byte count."""

        total = 0
        try:
            with open(source, "rb") as reader, open(destination, "wb") as writer:
                while True:
                    chunk = reader.read(1024 * 1024)
                    if not chunk:
                        break
                    writer.write(chunk)
                    total += len(chunk)
                    if total > self.max_total_bytes:
                        raise IntakeError(
                            f"supplied file exceeds the total size limit while copying: {rel_path!r}",
                            details={"code": "limit_bytes", "rel_path": rel_path},
                        )
        except OSError as exc:
            raise IntakeError(
                f"failed to copy supplied file {rel_path!r}: {exc}",
                details={"code": "copy_failed", "rel_path": rel_path},
            ) from exc
        return total
