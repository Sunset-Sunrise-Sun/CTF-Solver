"""Deterministic tests for SHA-256 manifest generation and independent verification."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from ctf_solver.core.canonical import file_sha256
from ctf_solver.core.errors import ValidationError
from ctf_solver.evidence.manifest import (
    ManifestReport,
    build_manifest_text,
    manifest_entries_from_paths,
    verify_manifest,
    write_manifest,
    write_manifest_for_tree,
)


def _make_tree(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "alpha.txt").write_bytes(b"alpha evidence")
    (root / "beta.bin").write_bytes(b"beta\x00evidence")
    nested = root / "nested"
    nested.mkdir()
    (nested / "gamma.log").write_bytes(b"gamma evidence\n")


def _tree_entries(root: Path) -> list[tuple[str, str]]:
    entries = []
    for path in sorted(root.rglob("*")):
        if path.is_file():
            entries.append((path.relative_to(root).as_posix(), file_sha256(path)))
    return entries


def test_write_and_verify_clean_manifest(tmp_path: Path) -> None:
    root = tmp_path / "evidence"
    _make_tree(root)
    entries = _tree_entries(root)
    manifest_path = tmp_path / "out" / "manifest.sha256"
    info = write_manifest(entries, manifest_path)

    assert info.kind == "manifest"
    assert info.entries == len(entries)
    assert Path(info.path) == manifest_path
    content = manifest_path.read_bytes()
    assert info.sha256 == hashlib.sha256(content).hexdigest()
    assert info.size == len(content)
    text = content.decode("utf-8")
    assert text.endswith("\n")
    assert "\r" not in text
    lines = text.splitlines()
    assert len(lines) == 3
    for line in lines:
        digest, _, relpath = line.partition("  ")
        assert len(digest) == 64
        assert (root / relpath).is_file()
        assert file_sha256(root / relpath) == digest

    report = verify_manifest(manifest_path, root)
    assert isinstance(report, ManifestReport)
    assert report.ok is True
    assert report.entries == 3
    assert report.missing == []
    assert report.mismatched == []
    assert report.extra == []
    assert report.errors == []
    assert report.manifest_sha256 == info.sha256
    assert report.to_dict()["ok"] is True


def test_manifest_is_sorted_and_order_independent(tmp_path: Path) -> None:
    root = tmp_path / "evidence"
    _make_tree(root)
    entries = _tree_entries(root)
    first = build_manifest_text(entries)
    second = build_manifest_text(list(reversed(entries)))
    assert first == second
    relpaths = [line.split("  ", 1)[1] for line in first.splitlines()]
    assert relpaths == sorted(relpaths)


def test_verify_detects_missing_file(tmp_path: Path) -> None:
    root = tmp_path / "evidence"
    _make_tree(root)
    manifest = write_manifest(_tree_entries(root), tmp_path / "manifest.sha256")
    (root / "alpha.txt").unlink()
    report = verify_manifest(manifest.path, root)
    assert report.ok is False
    assert report.missing == ["alpha.txt"]
    assert report.mismatched == []


def test_verify_detects_mismatched_file(tmp_path: Path) -> None:
    root = tmp_path / "evidence"
    _make_tree(root)
    manifest = write_manifest(_tree_entries(root), tmp_path / "manifest.sha256")
    (root / "beta.bin").write_bytes(b"tampered bytes")
    report = verify_manifest(manifest.path, root)
    assert report.ok is False
    assert report.mismatched == ["beta.bin"]


def test_verify_detects_extra_file(tmp_path: Path) -> None:
    root = tmp_path / "evidence"
    _make_tree(root)
    manifest = write_manifest(_tree_entries(root), tmp_path / "manifest.sha256")
    (root / "smuggled.txt").write_bytes(b"unlisted")
    report = verify_manifest(manifest.path, root)
    assert report.ok is False
    assert report.extra == ["smuggled.txt"]


def test_manifest_written_inside_root_is_not_extra(tmp_path: Path) -> None:
    root = tmp_path / "evidence"
    _make_tree(root)
    # First write a manifest next to the files, then verify the tree.
    write_manifest(_tree_entries(root), root / "manifest.sha256")
    report = verify_manifest(root / "manifest.sha256", root)
    # The manifest lists only the three data files, and its own file is ignored.
    assert report.ok is True, report.to_dict()


def test_verify_detects_tampered_digest_line(tmp_path: Path) -> None:
    root = tmp_path / "evidence"
    _make_tree(root)
    manifest = write_manifest(_tree_entries(root), tmp_path / "manifest.sha256")
    lines = Path(manifest.path).read_text(encoding="utf-8").splitlines()
    digest, _, relpath = lines[0].partition("  ")
    forged = ("f" * 64) + "  " + relpath
    lines[0] = forged
    Path(manifest.path).write_text("\n".join(lines) + "\n", encoding="utf-8")
    report = verify_manifest(manifest.path, root)
    assert report.ok is False
    assert report.mismatched == [relpath]


def test_verify_malformed_manifest_lines(tmp_path: Path) -> None:
    root = tmp_path / "evidence"
    _make_tree(root)
    manifest_path = tmp_path / "manifest.sha256"
    manifest_path.write_bytes(
        b"this is not a manifest line\n"
        + (b"a" * 64)
        + b"  alpha.txt\n"
    )
    report = verify_manifest(manifest_path, root)
    assert report.ok is False
    assert any("malformed manifest line" in error for error in report.errors)


def test_verify_rejects_traversal_entries(tmp_path: Path) -> None:
    root = tmp_path / "evidence"
    _make_tree(root)
    manifest_path = tmp_path / "manifest.sha256"
    manifest_path.write_bytes(((b"a" * 64) + b"  ../outside.txt\n"))
    report = verify_manifest(manifest_path, root)
    assert report.ok is False
    assert any("traverse" in error for error in report.errors)


def test_verify_missing_manifest_and_root(tmp_path: Path) -> None:
    report = verify_manifest(tmp_path / "nope.sha256", tmp_path)
    assert report.ok is False
    assert report.errors
    root = tmp_path / "evidence"
    _make_tree(root)
    manifest = write_manifest(_tree_entries(root), tmp_path / "manifest.sha256")
    report = verify_manifest(manifest.path, tmp_path / "not-a-dir")
    assert report.ok is False
    assert report.errors


def test_write_manifest_validates_entries(tmp_path: Path) -> None:
    with pytest.raises(ValidationError):
        write_manifest([("ok.txt", "not-a-digest")], tmp_path / "manifest.sha256")
    with pytest.raises(ValidationError):
        write_manifest(
            [("a.txt", "a" * 64), ("a.txt", "b" * 64)], tmp_path / "manifest.sha256"
        )
    with pytest.raises(ValidationError):
        write_manifest([("../escape.txt", "a" * 64)], tmp_path / "manifest.sha256")
    with pytest.raises(ValidationError):
        write_manifest([("C:/absolute.txt", "a" * 64)], tmp_path / "manifest.sha256")
    with pytest.raises(ValidationError):
        write_manifest([("bad",)], tmp_path / "manifest.sha256")  # type: ignore[list-item]


def test_write_manifest_for_tree(tmp_path: Path) -> None:
    root = tmp_path / "evidence"
    _make_tree(root)
    info = write_manifest_for_tree(root, root / "manifest.sha256")
    assert info.entries == 3
    report = verify_manifest(root / "manifest.sha256", root)
    assert report.ok is True
    # The manifest itself is inside the root but not listed, so no "extra" entry.
    assert report.extra == []


def test_manifest_entries_from_paths(tmp_path: Path) -> None:
    root = tmp_path / "evidence"
    _make_tree(root)
    entries = manifest_entries_from_paths(root, ["alpha.txt", "nested/gamma.log"])
    assert [rel for rel, _digest in entries] == ["alpha.txt", "nested/gamma.log"]
    assert entries[0][1] == file_sha256(root / "alpha.txt")
    with pytest.raises(ValidationError):
        manifest_entries_from_paths(root, ["missing.txt"])
