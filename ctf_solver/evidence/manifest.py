"""SHA-256 manifest generation and independent verification.

The evidence ZIP / export carries a ``manifest.sha256`` listing every selected
file as ``<sha256>  <relpath>`` (two spaces, like ``sha256sum``) sorted by path
with LF line endings. Verification is *independent*: it re-hashes the files on
disk instead of trusting the manifest, and reports missing, mismatched and extra
entries separately.

The manifest is evidence bookkeeping, not a signature: a manifest that an
attacker can rewrite together with the files proves nothing by itself. It is
useful for detecting transport/export corruption and accidental modification.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Sequence

from ..core.canonical import file_sha256, hash_manifest, sha256_hex
from ..core.errors import StorageError, ValidationError
from ..core.types import ExportInfo

_MANIFEST_LINE_RE = re.compile(r"^([0-9a-f]{64})  (.+)$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

MANIFEST_NAME = "manifest.sha256"


@dataclass
class ManifestReport:
    """Outcome of independent manifest verification."""

    ok: bool
    entries: int
    missing: list[str] = field(default_factory=list)
    mismatched: list[str] = field(default_factory=list)
    extra: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    manifest_sha256: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "entries": self.entries,
            "missing": list(self.missing),
            "mismatched": list(self.mismatched),
            "extra": list(self.extra),
            "errors": list(self.errors),
            "manifest_sha256": self.manifest_sha256,
        }


def _validate_relpath(relpath: str) -> str:
    """Reject absolute paths, traversal and NUL bytes in manifest entries."""

    if not isinstance(relpath, str) or not relpath:
        raise ValidationError("manifest entry requires a non-empty relative path")
    if "\x00" in relpath:
        raise ValidationError("manifest entry path contains a NUL byte")
    normalized = relpath.replace("\\", "/")
    if normalized.startswith("/") or (len(normalized) > 1 and normalized[1] == ":"):
        raise ValidationError(f"manifest entry path must be relative: {relpath!r}")
    parts = [part for part in normalized.split("/") if part not in ("", ".")]
    if any(part == ".." for part in parts):
        raise ValidationError(f"manifest entry path must not traverse: {relpath!r}")
    if not parts:
        raise ValidationError(f"manifest entry path is empty: {relpath!r}")
    return "/".join(parts)


def _validate_entries(entries: Sequence[tuple[str, str]]) -> list[tuple[str, str]]:
    if not isinstance(entries, (list, tuple)):
        raise ValidationError("manifest entries must be a sequence of (relpath, sha256)")
    normalized: list[tuple[str, str]] = []
    seen: set[str] = set()
    for item in entries:
        if not isinstance(item, (tuple, list)) or len(item) != 2:
            raise ValidationError(
                "manifest entries must be (relpath, sha256) pairs, "
                f"got {item!r}"
            )
        relpath, digest = item[0], item[1]
        rel = _validate_relpath(relpath)
        if not isinstance(digest, str) or not _SHA256_RE.fullmatch(digest):
            raise ValidationError(f"invalid SHA-256 digest for manifest entry {rel!r}: {digest!r}")
        if rel in seen:
            raise ValidationError(f"duplicate manifest entry: {rel!r}")
        seen.add(rel)
        normalized.append((rel, digest))
    return normalized


def build_manifest_text(entries: Sequence[tuple[str, str]]) -> str:
    """Render the sorted ``<sha256>  <relpath>`` manifest text (LF endings)."""

    normalized = _validate_entries(entries)
    return hash_manifest(normalized)


def write_manifest(
    entries: Sequence[tuple[str, str]], out_path: str | os.PathLike[str]
) -> ExportInfo:
    """Write a sorted SHA-256 manifest and return its :class:`ExportInfo`."""

    text = build_manifest_text(entries)
    data = text.encode("utf-8")
    target = Path(os.path.abspath(os.fspath(out_path)))
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = target.parent / f".{target.name}.{os.getpid()}.tmp"
    try:
        with open(tmp_path, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, target)
    except OSError as exc:  # pragma: no cover - disk failure path
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise StorageError(f"failed to write manifest: {exc}") from exc
    return ExportInfo(
        kind="manifest",
        path=str(target),
        sha256=sha256_hex(data),
        size=len(data),
        entries=len(entries),
    )


def write_manifest_for_tree(
    root: str | os.PathLike[str], out_path: str | os.PathLike[str]
) -> ExportInfo:
    """Hash every file under ``root`` and write a manifest for it."""

    base = Path(os.path.abspath(os.fspath(root)))
    if not base.is_dir():
        raise ValidationError(f"manifest root is not a directory: {base}")
    entries: list[tuple[str, str]] = []
    for path in sorted(base.rglob("*")):
        if path.is_file():
            rel = path.relative_to(base).as_posix()
            entries.append((rel, file_sha256(path)))
    return write_manifest(entries, out_path)


def verify_manifest(
    manifest_path: str | os.PathLike[str], root: str | os.PathLike[str]
) -> ManifestReport:
    """Independently verify a manifest against the files under ``root``."""

    manifest = Path(os.path.abspath(os.fspath(manifest_path)))
    base = Path(os.path.abspath(os.fspath(root)))
    report = ManifestReport(ok=False, entries=0)
    if not manifest.is_file():
        report.errors.append(f"manifest not found: {manifest}")
        return report
    if not base.is_dir():
        report.errors.append(f"manifest root is not a directory: {base}")
        return report
    try:
        manifest_bytes = manifest.read_bytes()
    except OSError as exc:  # pragma: no cover - permission failure
        report.errors.append(f"cannot read manifest: {exc}")
        return report
    report.manifest_sha256 = sha256_hex(manifest_bytes)
    try:
        text = manifest_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        report.errors.append(f"manifest is not valid UTF-8: {exc}")
        return report

    expected: dict[str, str] = {}
    line_count = 0
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        line_count += 1
        match = _MANIFEST_LINE_RE.match(line)
        if match is None:
            report.errors.append(
                f"line {line_number}: malformed manifest line (expected '<sha256>  <relpath>')"
            )
            continue
        digest, relpath = match.group(1), match.group(2)
        try:
            rel = _validate_relpath(relpath)
        except ValidationError as exc:
            report.errors.append(f"line {line_number}: {exc}")
            continue
        if rel in expected:
            report.errors.append(f"line {line_number}: duplicate manifest entry {rel!r}")
            continue
        expected[rel] = digest
    report.entries = line_count

    manifest_rel: str | None = None
    try:
        inside = manifest.relative_to(base)
        manifest_rel = inside.as_posix()
    except ValueError:
        manifest_rel = None

    for rel, digest in sorted(expected.items()):
        candidate = base / rel
        if not candidate.is_file():
            report.missing.append(rel)
            continue
        try:
            actual = file_sha256(candidate)
        except OSError as exc:  # pragma: no cover - permission failure
            report.errors.append(f"cannot hash {rel!r}: {exc}")
            continue
        if actual != digest:
            report.mismatched.append(rel)

    for path in sorted(base.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(base).as_posix()
        if manifest_rel is not None and rel == manifest_rel:
            continue
        if rel not in expected:
            report.extra.append(rel)

    report.missing.sort()
    report.mismatched.sort()
    report.extra.sort()
    report.ok = not (
        report.errors or report.missing or report.mismatched or report.extra
    )
    return report


def manifest_entries_from_paths(
    root: str | os.PathLike[str], relpaths: Iterable[str]
) -> list[tuple[str, str]]:
    """Helper: hash selected files (relative to ``root``) into manifest entries."""

    base = Path(os.path.abspath(os.fspath(root)))
    entries: list[tuple[str, str]] = []
    for relpath in relpaths:
        rel = _validate_relpath(relpath)
        candidate = base / rel
        if not candidate.is_file():
            raise ValidationError(f"manifest source file not found: {candidate}")
        entries.append((rel, file_sha256(candidate)))
    return entries


__all__ = [
    "MANIFEST_NAME",
    "ManifestReport",
    "build_manifest_text",
    "manifest_entries_from_paths",
    "verify_manifest",
    "write_manifest",
    "write_manifest_for_tree",
]
