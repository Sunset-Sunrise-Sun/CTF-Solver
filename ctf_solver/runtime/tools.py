"""Builtin trusted tools for the typed ``ctf-exec`` runtime.

Every tool here is deterministic, offline and safe against untrusted challenge
data:

- Tier 0 tools run in-process and only read file/archive metadata or bounded
  byte ranges. They never execute challenge-provided code and never extract
  archive contents.
- Tier 1 tools are fixed-argv subprocess probes (``git --version`` and
  ``python --version``); the argv schema accepts exactly ``["--version"]`` so a
  caller cannot turn them into an arbitrary command.
- ``tool.remote_probe`` exists only so the Broker can prove network/tier denial.

No tool uses a shell string and none may execute challenge-provided code.
Internal tool arguments that reference files are workspace-relative paths;
:func:`resolve_workspace_path` re-validates containment even when the executor
is called directly in tests (defence in depth on top of the Broker).
"""

from __future__ import annotations

import datetime
import os
import stat
import sys
import tarfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from ..core.canonical import canonical_json, file_sha256
from ..core.errors import ToolExecutionError
from ..core.paths import ensure_relative_safe, is_within, resolve_path
from ..core.types import (
    ApprovalAction,
    ExecutionStatus,
    ExecutionTier,
    ExecRequest,
    RuntimeOutcome,
)

__all__ = [
    "ToolInvocation",
    "ToolSpec",
    "resolve_workspace_path",
    "build_builtin_tools",
]

#: Hard cap for internally produced output previews/lists (defence in depth).

#: Bounded work limits for internal inspection tools.
MAX_HASH_BYTES = 256 * 1024 * 1024
MAX_METADATA_MAGIC_BYTES = 4096
MAX_ARCHIVE_ENTRIES = 2000
MAX_ARCHIVE_NAME_CHARS = 4096
MAX_SEARCH_FILES = 500
MAX_SEARCH_FILE_BYTES = 8 * 1024 * 1024
MAX_SEARCH_MATCHES = 1000
MAX_SEARCH_LINE_CHARS = 400
MAX_SEARCH_PATTERN_CHARS = 256
MAX_HEX_PREVIEW_BYTES = 4096
MAX_HEX_PREVIEW_DEFAULT = 256
MAX_STRINGS_SCAN_BYTES = 4 * 1024 * 1024
MAX_STRINGS_COUNT = 2000
MAX_STRING_CHARS = 200
MAX_STRING_MIN_LENGTH = 64



# ---------------------------------------------------------------------------
# Invocation / specification types
# ---------------------------------------------------------------------------


@dataclass
class ToolInvocation:
    """One validated tool invocation handed to the executor.

    The Broker has already validated containment; the executor only translates
    this typed value into an in-process call or a fixed-argv subprocess.
    """

    argv: list[str]
    cwd: str
    input_files: list[dict[str, Any]] = field(default_factory=list)
    output_paths: list[str] = field(default_factory=list)
    timeout_s: float = 30.0
    max_output_bytes: int | None = None
    request: ExecRequest | None = None

    @property
    def cwd_path(self) -> Path:
        return resolve_path(self.cwd)


@dataclass(frozen=True)
class ToolSpec:
    """Trusted tool definition owned by the Manager/Runtime catalogue.

    ``executable`` is an implementation detail extension of the frozen
    interface: Tier 1 probe tools need to name the executable they spawn. The
    executable itself is never caller-controlled (argv is validated).
    """

    name: str
    display_name: str
    description: str
    tier: ExecutionTier = ExecutionTier.TIER0_STATIC
    version: str = ""
    version_probe: list[str] | None = None
    executes_challenge_code: bool = False
    arg_validator: Callable[[list[str]], str | None] | None = None
    internal: Callable[[ToolInvocation], RuntimeOutcome] | None = None
    default_timeout_s: float = 30.0
    max_output_bytes: int = 4 * 1024 * 1024
    requires_approval: ApprovalAction | None = None
    network: bool = False
    executable: str | None = None


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _completed(stdout: bytes = b"", *, exit_code: int = 0) -> RuntimeOutcome:
    return RuntimeOutcome(
        status=ExecutionStatus.COMPLETED,
        exit_code=exit_code,
        stdout=stdout,
    )


def _failed(message: str) -> RuntimeOutcome:
    return RuntimeOutcome(status=ExecutionStatus.FAILED, exit_code=None, error=message)


def _json_bytes(value: Any) -> bytes:
    return (canonical_json(value) + "\n").encode("utf-8")


def resolve_workspace_path(cwd: str, raw: str, *, must_be_file: bool = False) -> Path:
    """Resolve a workspace-relative path and re-check containment.

    Absolute paths and traversal are rejected, matching the Broker policy, so
    calling a tool directly (for example from a unit test) cannot read outside
    the authorized workspace.
    """

    if not isinstance(raw, str) or not raw.strip():
        raise ToolExecutionError("tool path argument must be a non-empty string")
    try:
        relative = ensure_relative_safe(raw)
        root = resolve_path(cwd)
        candidate = resolve_path(os.path.join(str(root), relative))
    except (OSError, ValueError) as exc:
        raise ToolExecutionError(f"unsafe path argument {raw!r}: {exc}") from exc
    if not is_within(candidate, root):
        raise ToolExecutionError(f"path argument {raw!r} escapes the workspace")
    if must_be_file:
        if not candidate.is_file():
            raise ToolExecutionError(f"file not found in workspace: {relative}")
    return candidate


def _read_bounded(path: Path, limit: int) -> bytes:
    with open(path, "rb") as handle:
        return handle.read(limit)


def _zip_time_ms(date_time: tuple[int, int, int, int, int, int]) -> int:
    """Convert a zip DOS date tuple into epoch milliseconds (UTC)."""

    try:
        moment = datetime.datetime(
            date_time[0], date_time[1], date_time[2], date_time[3], date_time[4], date_time[5],
            tzinfo=datetime.timezone.utc,
        )
    except ValueError:  # pragma: no cover - malformed archive timestamps
        return 0
    return int(moment.timestamp() * 1000)


def _magic_type(path: Path) -> str:
    try:
        with open(path, "rb") as handle:
            head = handle.read(MAX_METADATA_MAGIC_BYTES)
    except OSError:
        raise
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if head.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if head.startswith(b"GIF87a") or head.startswith(b"GIF89a"):
        return "gif"
    if head.startswith(b"%PDF-"):
        return "pdf"
    if head.startswith(b"PK\x03\x04") or head.startswith(b"PK\x05\x06"):
        return "zip"
    if head.startswith(b"\x1f\x8b"):
        return "gzip"
    if head.startswith(b"BZh"):
        return "bzip2"
    if head.startswith(b"\xfd7zXZ\x00"):
        return "xz"
    if head.startswith(b"\x28\xb5\x2f\xfd"):
        return "zstd"
    if head.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7z"
    if head.startswith(b"Rar!\x1a\x07"):
        return "rar"
    if head.startswith(b"\x7fELF"):
        return "elf"
    if head.startswith(b"MZ"):
        return "pe"
    if head.startswith(b"BM"):
        return "bmp"
    if head.startswith(b"II*\x00") or head.startswith(b"MM\x00*"):
        return "tiff"
    if head.startswith(b"SQLite format 3\x00"):
        return "sqlite"
    if head.startswith(b"ustar\x00") or (len(head) >= 262 and head[257:262] == b"ustar"):
        return "tar"
    return "unknown"


def _arg_count(argv: list[str], minimum: int, maximum: int) -> str | None:
    if not minimum <= len(argv) <= maximum:
        if minimum == maximum:
            return f"expected exactly {minimum} argument(s), got {len(argv)}"
        return f"expected between {minimum} and {maximum} arguments, got {len(argv)}"
    return None


def _validate_single_path_arg(argv: list[str]) -> str | None:
    problem = _arg_count(argv, 1, 1)
    if problem:
        return problem
    try:
        ensure_relative_safe(argv[0])
    except ValueError as exc:
        return f"invalid path argument: {exc}"
    return None


def _validate_text_search_args(argv: list[str]) -> str | None:
    problem = _arg_count(argv, 1, 2)
    if problem:
        return problem
    pattern = argv[0]
    if not pattern:
        return "search pattern must not be empty"
    if len(pattern) > MAX_SEARCH_PATTERN_CHARS:
        return f"search pattern exceeds {MAX_SEARCH_PATTERN_CHARS} characters"
    if len(argv) == 2:
        try:
            ensure_relative_safe(argv[1])
        except ValueError as exc:
            return f"invalid search path: {exc}"
    return None


def _validate_hex_preview_args(argv: list[str]) -> str | None:
    problem = _arg_count(argv, 1, 3)
    if problem:
        return problem
    try:
        ensure_relative_safe(argv[0])
    except ValueError as exc:
        return f"invalid path argument: {exc}"
    numeric = argv[1:]
    for value in numeric:
        if not value.isdigit():
            return f"expected a non-negative integer, got {value!r}"
    if len(numeric) >= 1 and int(numeric[0]) > MAX_HASH_BYTES:
        return "offset is unreasonably large"
    if len(numeric) == 2:
        length = int(numeric[1])
        if length < 1 or length > MAX_HEX_PREVIEW_BYTES:
            return f"length must be within [1, {MAX_HEX_PREVIEW_BYTES}] bytes"
    return None


def _validate_strings_args(argv: list[str]) -> str | None:
    problem = _arg_count(argv, 1, 2)
    if problem:
        return problem
    try:
        ensure_relative_safe(argv[0])
    except ValueError as exc:
        return f"invalid path argument: {exc}"
    if len(argv) == 2:
        value = argv[1]
        if not value.isdigit():
            return f"expected an integer minimum string length, got {value!r}"
        minimum = int(value)
        if minimum < 1 or minimum > MAX_STRING_MIN_LENGTH:
            return f"minimum string length must be within [1, {MAX_STRING_MIN_LENGTH}]"
    return None


def _validate_fixed_version_argv(argv: list[str]) -> str | None:
    if list(argv) != ["--version"]:
        return "this probe accepts exactly the fixed argv ['--version']"
    return None


# ---------------------------------------------------------------------------
# Tier 0 internal tools
# ---------------------------------------------------------------------------


def _file_hash(invocation: ToolInvocation) -> RuntimeOutcome:
    path = resolve_workspace_path(invocation.cwd, invocation.argv[0], must_be_file=True)
    size = path.stat().st_size
    if size > MAX_HASH_BYTES:
        return _failed(f"file is too large to hash ({size} bytes > {MAX_HASH_BYTES})")
    digest = file_sha256(path)
    return _completed(
        _json_bytes({"path": invocation.argv[0], "sha256": digest, "size": size})
    )


def _file_metadata(invocation: ToolInvocation) -> RuntimeOutcome:
    path = resolve_workspace_path(invocation.cwd, invocation.argv[0])
    try:
        info = path.lstat()
    except OSError as exc:
        return _failed(f"cannot read file metadata: {exc}")
    is_link = stat.S_ISLNK(info.st_mode)
    is_dir = stat.S_ISDIR(info.st_mode)
    metadata = {
        "path": invocation.argv[0],
        "name": path.name,
        "extension": path.suffix.lower(),
        "size": int(info.st_size),
        "is_dir": bool(is_dir),
        "is_symlink": bool(is_link),
        "mode": int(info.st_mode),
        "modified_at_ms": int(info.st_mtime_ns // 1_000_000),
        "created_at_ms": int(info.st_ctime_ns // 1_000_000),
        "magic_type": "directory" if is_dir else _magic_type(path),
    }
    return _completed(_json_bytes(metadata))


def _archive_list(invocation: ToolInvocation) -> RuntimeOutcome:
    path = resolve_workspace_path(invocation.cwd, invocation.argv[0], must_be_file=True)
    magic = _magic_type(path)
    entries: list[dict[str, Any]] = []
    truncated = False
    if magic == "zip":
        try:
            with zipfile.ZipFile(path) as archive:
                for info in archive.infolist():
                    if len(entries) >= MAX_ARCHIVE_ENTRIES:
                        truncated = True
                        break
                    entries.append(
                        {
                            "name": info.filename[:MAX_ARCHIVE_NAME_CHARS],
                            "size": int(info.file_size),
                            "compressed_size": int(info.compress_size),
                            "is_dir": info.is_dir(),
                            "modified_at_ms": _zip_time_ms(info.date_time),
                        }
                    )
        except (zipfile.BadZipFile, OSError, ValueError) as exc:
            return _failed(f"cannot read zip archive metadata: {exc}")
        archive_format = "zip"
    elif magic in {"tar", "gzip", "bzip2", "xz"}:
        try:
            with tarfile.open(path, mode="r:*") as archive:
                for member in archive:
                    if len(entries) >= MAX_ARCHIVE_ENTRIES:
                        truncated = True
                        break
                    entries.append(
                        {
                            "name": member.name[:MAX_ARCHIVE_NAME_CHARS],
                            "size": int(member.size),
                            "is_dir": bool(member.isdir()),
                            "is_file": bool(member.isfile()),
                            "is_symlink": bool(member.issym() or member.islnk()),
                            "modified_at_ms": int(float(member.mtime) * 1000),
                        }
                    )
        except (tarfile.TarError, OSError, ValueError) as exc:
            return _failed(f"cannot read tar archive metadata: {exc}")
        archive_format = "tar"
    else:
        return _failed(
            f"unsupported archive format ({magic}); internal.archive_list supports zip and tar"
        )
    return _completed(
        _json_bytes(
            {
                "path": invocation.argv[0],
                "format": archive_format,
                "entry_count": len(entries),
                "truncated": truncated,
                "entries": entries,
            }
        )
    )


def _iter_candidate_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for current, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for name in sorted(filenames):
            candidate = Path(current) / name
            if len(files) >= MAX_SEARCH_FILES:
                return files
            try:
                if candidate.is_symlink() or not candidate.is_file():
                    continue
                if candidate.stat().st_size > MAX_SEARCH_FILE_BYTES:
                    continue
            except OSError:
                continue
            files.append(candidate)
    return files


def _text_search(invocation: ToolInvocation) -> RuntimeOutcome:
    pattern = invocation.argv[0]
    cwd = resolve_path(invocation.cwd)
    if len(invocation.argv) == 2:
        target = resolve_workspace_path(invocation.cwd, invocation.argv[1])
        if target.is_dir():
            candidates = _iter_candidate_files(target)
        elif target.is_file():
            candidates = [target]
        else:
            return _failed(f"search path not found: {invocation.argv[1]}")
    else:
        candidates = _iter_candidate_files(cwd)

    matches: list[dict[str, Any]] = []
    truncated = False
    searched = 0
    for candidate in candidates:
        try:
            raw = _read_bounded(candidate, MAX_SEARCH_FILE_BYTES)
        except OSError:
            continue
        if b"\x00" in raw[:8192]:
            continue  # skip binary files for a text tool
        searched += 1
        try:
            text = raw.decode("utf-8", errors="replace")
        except UnicodeError:  # pragma: no cover - errors="replace" is total
            continue
        relative = Path(os.path.relpath(candidate, cwd)).as_posix()
        for line_number, line in enumerate(text.splitlines(), start=1):
            column = line.find(pattern)
            if column < 0:
                continue
            if len(matches) >= MAX_SEARCH_MATCHES:
                truncated = True
                break
            matches.append(
                {
                    "path": relative,
                    "line": line_number,
                    "column": column + 1,
                    "text": line[:MAX_SEARCH_LINE_CHARS],
                }
            )
        if truncated:
            break
    return _completed(
        _json_bytes(
            {
                "pattern": pattern,
                "searched_files": searched,
                "match_count": len(matches),
                "truncated": truncated,
                "matches": matches,
            }
        )
    )


def _format_hex_preview(data: bytes, *, base_offset: int = 0) -> bytes:
    lines = []
    for index in range(0, len(data), 16):
        chunk = data[index : index + 16]
        hex_part = " ".join(f"{byte:02x}" for byte in chunk)
        hex_part = f"{hex_part:<47}"
        ascii_part = "".join(chr(byte) if 32 <= byte < 127 else "." for byte in chunk)
        lines.append(f"{base_offset + index:08x}  {hex_part}  |{ascii_part}|")
    return ("\n".join(lines) + ("\n" if lines else "")).encode("utf-8")


def _hex_preview(invocation: ToolInvocation) -> RuntimeOutcome:
    path = resolve_workspace_path(invocation.cwd, invocation.argv[0], must_be_file=True)
    offset = int(invocation.argv[1]) if len(invocation.argv) >= 2 else 0
    length = (
        int(invocation.argv[2]) if len(invocation.argv) >= 3 else MAX_HEX_PREVIEW_DEFAULT
    )
    try:
        with open(path, "rb") as handle:
            handle.seek(offset)
            data = handle.read(length)
    except OSError as exc:
        return _failed(f"cannot read file bytes: {exc}")
    if not data and offset > 0:
        return _failed(f"offset {offset} is past the end of the file")
    return _completed(_format_hex_preview(data, base_offset=offset))


def _strings_scan(invocation: ToolInvocation) -> RuntimeOutcome:
    path = resolve_workspace_path(invocation.cwd, invocation.argv[0], must_be_file=True)
    min_length = int(invocation.argv[1]) if len(invocation.argv) == 2 else 4
    data = _read_bounded(path, MAX_STRINGS_SCAN_BYTES)
    found: list[dict[str, Any]] = []
    truncated = False
    index = 0
    total = len(data)
    while index < total:
        if 32 <= data[index] < 127:
            start = index
            while index < total and 32 <= data[index] < 127:
                index += 1
            run = data[start:index]
            if len(run) >= min_length:
                if len(found) >= MAX_STRINGS_COUNT:
                    truncated = True
                    break
                found.append(
                    {
                        "offset": start,
                        "value": run[:MAX_STRING_CHARS].decode("ascii", errors="replace"),
                    }
                )
        else:
            index += 1
    if len(data) >= MAX_STRINGS_SCAN_BYTES:
        truncated = True
    return _completed(
        _json_bytes(
            {
                "path": invocation.argv[0],
                "min_length": min_length,
                "scanned_bytes": len(data),
                "string_count": len(found),
                "truncated": truncated,
                "strings": found,
            }
        )
    )


# ---------------------------------------------------------------------------
# Catalogue construction
# ---------------------------------------------------------------------------



def build_builtin_tools() -> list[ToolSpec]:
    """Return fresh builtin :class:`ToolSpec` instances in stable name order."""

    return [
        ToolSpec(
            name="internal.archive_list",
            display_name="Archive metadata listing",
            description=(
                "List zip/tar entry metadata without extracting or executing "
                "archive contents (bounded entry count)."
            ),
            tier=ExecutionTier.TIER0_STATIC,
            version="1",
            arg_validator=_validate_single_path_arg,
            internal=_archive_list,
            default_timeout_s=20.0,
            max_output_bytes=2 * 1024 * 1024,
        ),
        ToolSpec(
            name="internal.file_hash",
            display_name="File SHA-256 hash",
            description="Compute the SHA-256 digest and size of a workspace file (streaming).",
            tier=ExecutionTier.TIER0_STATIC,
            version="1",
            arg_validator=_validate_single_path_arg,
            internal=_file_hash,
            default_timeout_s=60.0,
            max_output_bytes=64 * 1024,
        ),
        ToolSpec(
            name="internal.file_metadata",
            display_name="File metadata",
            description="Read size, timestamps, mode and magic-byte type of a workspace path.",
            tier=ExecutionTier.TIER0_STATIC,
            version="1",
            arg_validator=_validate_single_path_arg,
            internal=_file_metadata,
            default_timeout_s=10.0,
            max_output_bytes=64 * 1024,
        ),
        ToolSpec(
            name="internal.hex_preview",
            display_name="Hex preview",
            description="Print a bounded hex/ASCII preview of a workspace file (offset/length).",
            tier=ExecutionTier.TIER0_STATIC,
            version="1",
            arg_validator=_validate_hex_preview_args,
            internal=_hex_preview,
            default_timeout_s=10.0,
            max_output_bytes=2 * 1024 * 1024,
        ),
        ToolSpec(
            name="internal.strings_scan",
            display_name="Strings scan",
            description="Extract bounded printable ASCII strings from a workspace file.",
            tier=ExecutionTier.TIER0_STATIC,
            version="1",
            arg_validator=_validate_strings_args,
            internal=_strings_scan,
            default_timeout_s=30.0,
            max_output_bytes=2 * 1024 * 1024,
        ),
        ToolSpec(
            name="internal.text_search",
            display_name="Bounded text search",
            description=(
                "Literal text search across bounded workspace files "
                "(no regex, no execution, bounded matches)."
            ),
            tier=ExecutionTier.TIER0_STATIC,
            version="1",
            arg_validator=_validate_text_search_args,
            internal=_text_search,
            default_timeout_s=30.0,
            max_output_bytes=2 * 1024 * 1024,
        ),
        ToolSpec(
            name="tool.git_version",
            display_name="Git version probe",
            description="Run the fixed argv ['--version'] against git (no other arguments accepted).",
            tier=ExecutionTier.TIER1_TRUSTED,
            version="",
            version_probe=["--version"],
            executable="git",
            arg_validator=_validate_fixed_version_argv,
            default_timeout_s=10.0,
            max_output_bytes=64 * 1024,
        ),
        ToolSpec(
            name="tool.python_version",
            display_name="Python version probe",
            description="Run the fixed argv ['--version'] against the current Python interpreter.",
            tier=ExecutionTier.TIER1_TRUSTED,
            version="",
            version_probe=["--version"],
            executable=sys.executable or "python",
            arg_validator=_validate_fixed_version_argv,
            default_timeout_s=10.0,
            max_output_bytes=64 * 1024,
        ),
        ToolSpec(
            name="tool.remote_probe",
            display_name="Remote probe (policy stub)",
            description=(
                "Declared intent-only network tool. It is never executable in Round 1: "
                "the Broker denies it for Tier 2 / network policy reasons."
            ),
            tier=ExecutionTier.TIER2_ISOLATED,
            version="0",
            version_probe=None,
            executes_challenge_code=False,
            arg_validator=_validate_fixed_version_argv,
            default_timeout_s=30.0,
            max_output_bytes=1024 * 1024,
            requires_approval=ApprovalAction.REMOTE_TARGET,
            network=True,
        ),
    ]
