"""Tests for the Round 2 controlled challenge-file intake (docs/ROUND_2_INTERFACES.md §4.1).

Negative-case heavy: traversal, absolute/drive paths, symlink/junction ancestors,
non-regular files, limits, duplicates, missing intake root and cross-Task
isolation. All fixtures live under pytest ``tmp_path``; no shell, no network.
"""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from ctf_solver.core.errors import CtfSolverError
from ctf_solver.core.types import ImportedInput
from ctf_solver.intake import DEFAULT_MEDIA_TYPE, IntakeError, IntakeService

FIXED_NOW_MS = 1_700_000_000_123


class FixedClock:
    def now_ms(self) -> int:
        return FIXED_NOW_MS


def make_intake(
    tmp_path: Path,
    *,
    name: str = "uploads",
    max_files: int = 100,
    max_total_bytes: int = 256 * 1024 * 1024,
) -> tuple[Path, IntakeService]:
    root = tmp_path / name
    root.mkdir()
    service = IntakeService(
        root, max_files=max_files, max_total_bytes=max_total_bytes, clock=FixedClock()
    )
    return root, service


def write_file(root: Path, relative: str, data: bytes) -> Path:
    target = root / Path(relative)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    return target


def make_workspace(tmp_path: Path, name: str = "task-1") -> Path:
    workspace = tmp_path / "tasks" / name / "work"
    workspace.mkdir(parents=True, exist_ok=True)
    return workspace


def _try_make_link(target: Path, link: Path, *, directory: bool) -> str | None:
    """Create a symlink (or directory junction fallback) or return None if impossible."""

    try:
        os.symlink(target, link, target_is_directory=directory)
        return "symlink"
    except (OSError, NotImplementedError):
        pass
    if directory and sys.platform == "win32":
        try:
            completed = subprocess.run(
                ["cmd.exe", "/c", "mklink", "/J", str(link), str(target)],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):  # pragma: no cover - platform edge
            return None
        if completed.returncode == 0 and link.exists():
            return "junction"
    return None


def _require_link(link_kind: str | None, *, what: str) -> None:
    if link_kind is None:
        pytest.skip(f"cannot create {what} on this Windows host without elevation")


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_import_multiple_files_nested_with_hashes_and_metadata(tmp_path: Path) -> None:
    root, service = make_intake(tmp_path)
    write_file(root, "readme.txt", b"hello intake\n")
    write_file(root, "nested/archive.zip", b"PK\x03\x04synthetic")
    write_file(root, "nested/deeper/data.bin", b"\x00\x01\x02")
    workspace = make_workspace(tmp_path)

    imported = service.import_files(
        task_id="t-1",
        workspace=workspace,
        supplied_files=["readme.txt", "nested/archive.zip", "nested/deeper/data.bin"],
    )

    assert [item.rel_path for item in imported] == [
        "readme.txt",
        "nested/archive.zip",
        "nested/deeper/data.bin",
    ]
    assert all(isinstance(item, ImportedInput) for item in imported)
    expected = {
        "readme.txt": b"hello intake\n",
        "nested/archive.zip": b"PK\x03\x04synthetic",
        "nested/deeper/data.bin": b"\x00\x01\x02",
    }
    for item in imported:
        payload = expected[item.rel_path]
        assert item.sha256 == hashlib.sha256(payload).hexdigest()
        assert item.size == len(payload)
        assert item.source_rel_path == item.rel_path
        assert item.imported_at == FIXED_NOW_MS
        assert item.media_type
        copied = workspace / "inputs" / Path(item.rel_path)
        assert copied.is_file()
        assert copied.read_bytes() == payload
        assert set(item.to_dict()) == {
            "rel_path",
            "sha256",
            "size",
            "media_type",
            "source_rel_path",
            "imported_at",
        }
    assert imported[0].media_type == "text/plain"
    assert imported[1].media_type in {"application/zip", "application/x-zip-compressed"}
    assert imported[2].media_type == DEFAULT_MEDIA_TYPE
    # Intake sources are never modified or moved.
    for relative, payload in expected.items():
        assert (root / Path(relative)).read_bytes() == payload


def test_windows_separator_entries_are_normalized_to_posix(tmp_path: Path) -> None:
    root, service = make_intake(tmp_path)
    write_file(root, "sub/b.bin", b"payload")
    workspace = make_workspace(tmp_path)
    imported = service.import_files(
        task_id="t-1", workspace=workspace, supplied_files=["sub\\b.bin"]
    )
    assert imported[0].rel_path == "sub/b.bin"
    assert (workspace / "inputs" / "sub" / "b.bin").is_file()


def test_media_type_guess_and_fallback(tmp_path: Path) -> None:
    root, service = make_intake(tmp_path)
    write_file(root, "a.json", b"{}")
    write_file(root, "b.xyzzy", b"unknown")
    workspace = make_workspace(tmp_path)
    imported = service.import_files(
        task_id="t-1", workspace=workspace, supplied_files=["a.json", "b.xyzzy"]
    )
    assert imported[0].media_type == "application/json"
    assert imported[1].media_type == DEFAULT_MEDIA_TYPE


def test_empty_supplied_list_returns_empty(tmp_path: Path) -> None:
    _root, service = make_intake(tmp_path)
    workspace = make_workspace(tmp_path)
    assert service.import_files(task_id="t-1", workspace=workspace, supplied_files=[]) == []
    assert not (workspace / "inputs").exists()


# ---------------------------------------------------------------------------
# Path rejection
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "entry",
    [
        "/etc/passwd",
        "\\\\server\\share\\file.txt",
        "//server/share/file.txt",
        "..",
        "../outside.txt",
        "sub/../../outside.txt",
        "..\\outside.txt",
        "sub\\..\\..\\outside.txt",
    ],
)
def test_absolute_and_traversal_entries_are_rejected(tmp_path: Path, entry: str) -> None:
    root, service = make_intake(tmp_path)
    write_file(root, "sub/inside.txt", b"inside")
    workspace = make_workspace(tmp_path)
    with pytest.raises(IntakeError):
        service.import_files(task_id="t-1", workspace=workspace, supplied_files=[entry])
    assert not (workspace / "inputs").exists()


def test_absolute_host_path_is_rejected_by_string_even_if_inside_root(tmp_path: Path) -> None:
    root, service = make_intake(tmp_path)
    write_file(root, "inside.txt", b"inside")
    workspace = make_workspace(tmp_path)
    with pytest.raises(IntakeError) as excinfo:
        service.import_files(
            task_id="t-1",
            workspace=workspace,
            supplied_files=[str((root / "inside.txt").resolve())],
        )
    assert "absolute" in str(excinfo.value).lower()


def test_drive_qualified_entries_are_rejected(tmp_path: Path) -> None:
    root, service = make_intake(tmp_path)
    write_file(root, "inside.txt", b"inside")
    workspace = make_workspace(tmp_path)
    for entry in ("C:inside.txt", "C:\\Windows\\win.ini", "Z:does-not-exist"):
        with pytest.raises(IntakeError) as excinfo:
            service.import_files(task_id="t-1", workspace=workspace, supplied_files=[entry])
        assert "drive" in str(excinfo.value).lower() or "absolute" in str(excinfo.value).lower()
    assert not (workspace / "inputs").exists()


@pytest.mark.parametrize("entry", ["", "   ", "\t", "a/", "/a", "a//b", "./a", "a/./b"])
def test_empty_or_ambiguous_entries_are_rejected(tmp_path: Path, entry: str) -> None:
    _root, service = make_intake(tmp_path)
    workspace = make_workspace(tmp_path)
    with pytest.raises(IntakeError):
        service.import_files(task_id="t-1", workspace=workspace, supplied_files=[entry])


@pytest.mark.parametrize("entry", ["a\x00b.txt", "a\x01b.txt", "a\x1fb.txt", "a\x7fb.txt"])
def test_control_characters_are_rejected(tmp_path: Path, entry: str) -> None:
    _root, service = make_intake(tmp_path)
    workspace = make_workspace(tmp_path)
    with pytest.raises(IntakeError) as excinfo:
        service.import_files(task_id="t-1", workspace=workspace, supplied_files=[entry])
    assert "control" in str(excinfo.value).lower() or "nul" in str(excinfo.value).lower()


@pytest.mark.skipif(sys.platform != "win32", reason="Windows reserved device names")
@pytest.mark.parametrize("entry", ["NUL", "con.txt", "LPT1", "COM9", "aux.cfg", "trail."])
def test_windows_reserved_or_ambiguous_names_are_rejected(tmp_path: Path, entry: str) -> None:
    root, _service = make_intake(tmp_path)
    service = IntakeService(root, clock=FixedClock())
    workspace = make_workspace(tmp_path)
    with pytest.raises(IntakeError):
        service.import_files(task_id="t-1", workspace=workspace, supplied_files=[entry])


def test_missing_file_is_rejected(tmp_path: Path) -> None:
    _root, service = make_intake(tmp_path)
    workspace = make_workspace(tmp_path)
    with pytest.raises(IntakeError) as excinfo:
        service.import_files(
            task_id="t-1", workspace=workspace, supplied_files=["does-not-exist.txt"]
        )
    assert "exist" in str(excinfo.value).lower()
    assert not (workspace / "inputs").exists()


def test_directory_entry_is_rejected(tmp_path: Path) -> None:
    root, service = make_intake(tmp_path)
    (root / "somedir").mkdir()
    workspace = make_workspace(tmp_path)
    with pytest.raises(IntakeError) as excinfo:
        service.import_files(task_id="t-1", workspace=workspace, supplied_files=["somedir"])
    assert "regular" in str(excinfo.value).lower()


# ---------------------------------------------------------------------------
# Symlink / junction rejection
# ---------------------------------------------------------------------------


def test_symlink_file_inside_intake_root_is_rejected(tmp_path: Path) -> None:
    root, service = make_intake(tmp_path)
    target = write_file(root, "real.txt", b"secret")
    link = root / "link.txt"
    _require_link(_try_make_link(target, link, directory=False), what="file symlink")
    workspace = make_workspace(tmp_path)
    with pytest.raises(IntakeError) as excinfo:
        service.import_files(task_id="t-1", workspace=workspace, supplied_files=["link.txt"])
    assert "symlink" in str(excinfo.value).lower() or "reparse" in str(excinfo.value).lower()


def test_symlink_ancestor_escaping_intake_root_is_rejected(tmp_path: Path) -> None:
    root, service = make_intake(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "leak.txt").write_bytes(b"leaked")
    link = root / "linkdir"
    _require_link(_try_make_link(outside, link, directory=True), what="directory symlink/junction")
    (root / "linkdir-nested").mkdir(exist_ok=True)
    workspace = make_workspace(tmp_path)
    with pytest.raises(IntakeError) as excinfo:
        service.import_files(
            task_id="t-1", workspace=workspace, supplied_files=["linkdir/leak.txt"]
        )
    message = str(excinfo.value).lower()
    assert "symlink" in message or "reparse" in message or "outside" in message


def test_symlinked_intake_root_is_rejected(tmp_path: Path) -> None:
    real_root = tmp_path / "real-uploads"
    real_root.mkdir()
    link_root = tmp_path / "uploads-link"
    _require_link(_try_make_link(real_root, link_root, directory=True), what="root symlink/junction")
    with pytest.raises(IntakeError) as excinfo:
        IntakeService(link_root, clock=FixedClock())
    assert "symlink" in str(excinfo.value).lower() or "reparse" in str(excinfo.value).lower()


def test_symlink_destination_in_workspace_is_rejected(tmp_path: Path) -> None:
    root, service = make_intake(tmp_path)
    write_file(root, "a.txt", b"new content")
    workspace = make_workspace(tmp_path)
    inputs = workspace / "inputs"
    inputs.mkdir()
    elsewhere = tmp_path / "elsewhere.txt"
    elsewhere.write_bytes(b"must not be overwritten")
    link = inputs / "a.txt"
    _require_link(_try_make_link(elsewhere, link, directory=False), what="destination symlink")
    with pytest.raises(IntakeError) as excinfo:
        service.import_files(task_id="t-1", workspace=workspace, supplied_files=["a.txt"])
    assert "symlink" in str(excinfo.value).lower() or "reparse" in str(excinfo.value).lower()
    assert elsewhere.read_bytes() == b"must not be overwritten"


# ---------------------------------------------------------------------------
# Intake root validation / limits / duplicates
# ---------------------------------------------------------------------------


def test_intake_root_must_exist_be_directory_and_not_symlink(tmp_path: Path) -> None:
    with pytest.raises(IntakeError):
        IntakeService(tmp_path / "missing", clock=FixedClock())
    regular_file = tmp_path / "uploads-file"
    regular_file.write_bytes(b"not a directory")
    with pytest.raises(IntakeError):
        IntakeService(regular_file, clock=FixedClock())
    with pytest.raises(IntakeError):
        IntakeService("", clock=FixedClock())  # type: ignore[arg-type]
    with pytest.raises(IntakeError):
        IntakeService(tmp_path / "uploads", max_files=0, clock=FixedClock())
    with pytest.raises(IntakeError):
        IntakeService(tmp_path / "uploads", max_total_bytes=0, clock=FixedClock())


def test_file_count_limit_is_enforced_before_copying(tmp_path: Path) -> None:
    root, service = make_intake(tmp_path, max_files=2)
    for index in range(3):
        write_file(root, f"file-{index}.txt", b"x")
    workspace = make_workspace(tmp_path)
    with pytest.raises(IntakeError) as excinfo:
        service.import_files(
            task_id="t-1",
            workspace=workspace,
            supplied_files=["file-0.txt", "file-1.txt", "file-2.txt"],
        )
    assert "max_files" in str(excinfo.value)
    assert not (workspace / "inputs").exists()


def test_total_size_limit_is_enforced_before_copying(tmp_path: Path) -> None:
    root, service = make_intake(tmp_path, max_total_bytes=5)
    write_file(root, "a.bin", b"1234")
    write_file(root, "b.bin", b"5678")
    workspace = make_workspace(tmp_path)
    with pytest.raises(IntakeError) as excinfo:
        service.import_files(
            task_id="t-1", workspace=workspace, supplied_files=["a.bin", "b.bin"]
        )
    assert "max_total_bytes" in str(excinfo.value)
    assert not (workspace / "inputs").exists()


def test_duplicate_targets_are_rejected(tmp_path: Path) -> None:
    root, service = make_intake(tmp_path)
    write_file(root, "a.txt", b"a")
    workspace = make_workspace(tmp_path)
    for entries in (["a.txt", "a.txt"], ["a.txt", "A.TXT"]):
        with pytest.raises(IntakeError) as excinfo:
            service.import_files(task_id="t-1", workspace=workspace, supplied_files=entries)
        assert "duplicate" in str(excinfo.value).lower()
    assert not (workspace / "inputs").exists()


def test_invalid_argument_types_are_rejected(tmp_path: Path) -> None:
    _root, service = make_intake(tmp_path)
    workspace = make_workspace(tmp_path)
    with pytest.raises(IntakeError):
        service.import_files(task_id="t-1", workspace=workspace, supplied_files="a.txt")  # type: ignore[arg-type]
    with pytest.raises(IntakeError):
        service.import_files(task_id="", workspace=workspace, supplied_files=[])
    with pytest.raises(IntakeError):
        service.import_files(task_id="t-1", workspace="", supplied_files=[])  # type: ignore[arg-type]
    with pytest.raises(IntakeError):
        service.import_files(task_id="t-1", workspace=workspace, supplied_files=[42])  # type: ignore[list-item]


# ---------------------------------------------------------------------------
# Isolation / re-import
# ---------------------------------------------------------------------------


def test_two_tasks_receive_separate_copies(tmp_path: Path) -> None:
    root, service = make_intake(tmp_path)
    write_file(root, "challenge.txt", b"shared challenge bytes")
    workspace_one = make_workspace(tmp_path, "task-1")
    workspace_two = make_workspace(tmp_path, "task-2")
    first = service.import_files(
        task_id="task-1", workspace=workspace_one, supplied_files=["challenge.txt"]
    )
    second = service.import_files(
        task_id="task-2", workspace=workspace_two, supplied_files=["challenge.txt"]
    )
    assert first[0].sha256 == second[0].sha256
    copy_one = workspace_one / "inputs" / "challenge.txt"
    copy_two = workspace_two / "inputs" / "challenge.txt"
    assert copy_one.is_file() and copy_two.is_file()
    assert copy_one != copy_two
    copy_one.write_bytes(b"task-1 local modification")
    assert copy_two.read_bytes() == b"shared challenge bytes"
    assert not (workspace_one / "inputs" / "task-2").exists()
    assert not (workspace_two / "inputs" / "task-1").exists()


def test_reimport_overwrites_within_the_same_workspace(tmp_path: Path) -> None:
    root, service = make_intake(tmp_path)
    write_file(root, "a.txt", b"first")
    workspace = make_workspace(tmp_path)
    first = service.import_files(task_id="t-1", workspace=workspace, supplied_files=["a.txt"])
    write_file(root, "a.txt", b"second")
    second = service.import_files(task_id="t-1", workspace=workspace, supplied_files=["a.txt"])
    assert first[0].sha256 != second[0].sha256
    assert (workspace / "inputs" / "a.txt").read_bytes() == b"second"
    assert len(service.import_files(task_id="t-1", workspace=workspace, supplied_files=[])) == 0


def test_solver_config_intake_root_is_the_project_intake_area(tmp_path: Path) -> None:
    """The service is wired to ``SolverConfig.intake_root`` (``<project>/challenge-uploads``)."""

    from ctf_solver.core.config import SolverConfig

    config = SolverConfig(root=tmp_path / "project")
    config.ensure_runtime_dirs()
    intake_root = config.intake_root
    assert intake_root == (tmp_path / "project" / "challenge-uploads").resolve()
    assert intake_root.is_dir()
    write_file(intake_root, "given/challenge.zip", b"PK\x03\x04")
    workspace = config.paths.task_workspace("t-intake")
    workspace.mkdir(parents=True)

    imported = IntakeService(intake_root, clock=FixedClock()).import_files(
        task_id="t-intake", workspace=workspace, supplied_files=["given/challenge.zip"]
    )
    assert imported[0].rel_path == "given/challenge.zip"
    assert imported[0].sha256 == hashlib.sha256(b"PK\x03\x04").hexdigest()
    assert (workspace / "inputs" / "given" / "challenge.zip").read_bytes() == b"PK\x03\x04"


# ---------------------------------------------------------------------------
# No shell / no network / error type contract
# ---------------------------------------------------------------------------


def test_intake_error_is_a_ctf_solver_error() -> None:
    assert issubclass(IntakeError, CtfSolverError)
    assert IntakeError.reason_code == "intake_error"


def test_intake_module_has_no_shell_or_network_or_host_read_escape() -> None:
    source = (Path(__file__).resolve().parents[1] / "ctf_solver" / "intake.py").read_text(
        encoding="utf-8"
    )
    for forbidden in (
        "subprocess",
        "os.system",
        "os.popen",
        "shell=True",
        "import socket",
        "import urllib",
        "import requests",
    ):
        assert forbidden not in source, f"intake.py must not use {forbidden!r}"
    assert "realpath" in source, "intake must resolve containment with realpath"
