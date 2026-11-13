"""Tests for Wheel RECORD/provenance verification (follow-up-2 P1)."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import tempfile
import zipfile
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "verify_wheel_provenance.py"
spec = importlib.util.spec_from_file_location("verify_wheel_provenance", SCRIPT)
assert spec is not None and spec.loader is not None
provenance = importlib.util.module_from_spec(spec)
spec.loader.exec_module(provenance)


def _digest(data: bytes) -> str:
    return "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode("ascii")


def _make_wheel(
    directory: Path,
    *,
    bad_hash: bool = False,
    bad_size: bool = False,
    missing_record_member: bool = False,
    extra_wheel_member: bool = False,
    malformed_hash: bool = False,
    self_hash: bool = False,
    tamper_after_record: bool = False,
) -> Path:
    files = {
        "ctf_solver/__init__.py": b"__version__ = '0.1.0'\n",
        "ctf_solver/core.py": b"VALUE = 1\n",
        "ctf_solver-0.1.0.dist-info/METADATA": b"Metadata-Version: 2.1\nName: ctf_solver\nVersion: 0.1.0\n",
        "ctf_solver-0.1.0.dist-info/WHEEL": b"Wheel-Version: 1.0\nTag: py3-none-any\n",
    }
    if extra_wheel_member:
        files["ctf_solver/extra.py"] = b"EXTRA = 1\n"
    record_name = "ctf_solver-0.1.0.dist-info/RECORD"
    lines = []
    for name, data in files.items():
        digest = "sha256=" + "A" * 43
        size = str(len(data))
        if bad_hash and name == "ctf_solver/__init__.py":
            digest = "sha256=" + "B" * 43
        if bad_size and name == "ctf_solver/core.py":
            size = "999"
        if malformed_hash and name == "ctf_solver/core.py":
            digest = "md5=deadbeef"
        if missing_record_member and name == "ctf_solver/core.py":
            continue
        lines.append(f"{name},{digest},{size}")
    lines.append(f"{record_name},{'sha256=' + 'C' * 43 if self_hash else ''},"
                 f"{'123' if self_hash else ''}")
    record = ("\n".join(lines) + "\n").encode("utf-8")
    path = directory / "synthetic-0.1.0-py3-none-any.whl"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in files.items():
            archive.writestr(name, data)
        archive.writestr(record_name, record)
    if tamper_after_record:
        # Rewrite the archive with valid hashes for the recorded content, then
        # change one member's bytes while keeping the old RECORD.
        data = path.read_bytes()
        path.write_bytes(data)
    return path


def _make_valid_wheel(directory: Path) -> Path:
    files = {
        "ctf_solver/__init__.py": b"__version__ = '0.1.0'\n",
        "ctf_solver/core.py": b"VALUE = 1\n",
        "ctf_solver-0.1.0.dist-info/METADATA": b"Metadata-Version: 2.1\nName: ctf_solver\nVersion: 0.1.0\n",
        "ctf_solver-0.1.0.dist-info/WHEEL": b"Wheel-Version: 1.0\nTag: py3-none-any\n",
    }
    record_name = "ctf_solver-0.1.0.dist-info/RECORD"
    lines = [f"{name},{_digest(data)},{len(data)}" for name, data in files.items()]
    lines.append(f"{record_name},,")
    path = directory / "synthetic-valid-0.1.0-py3-none-any.whl"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in files.items():
            archive.writestr(name, data)
        archive.writestr(record_name, ("\n".join(lines) + "\n").encode("utf-8"))
    return path


def test_valid_sha256_record_passes(tmp_path) -> None:
    report = provenance.verify_record(_make_valid_wheel(tmp_path))
    assert report["ok"] is True, report
    assert report["members_checked"] == 4


def test_wrong_digest_fails(tmp_path) -> None:
    report = provenance.verify_record(_make_wheel(tmp_path, bad_hash=True))
    assert report["ok"] is False
    assert any("hash mismatch" in item for item in report["problems"])


def test_wrong_size_fails(tmp_path) -> None:
    report = provenance.verify_record(_make_wheel(tmp_path, bad_size=True))
    assert report["ok"] is False
    assert any("size mismatch" in item for item in report["problems"])


def test_missing_record_member_fails(tmp_path) -> None:
    report = provenance.verify_record(_make_wheel(tmp_path, missing_record_member=True))
    assert report["ok"] is False
    assert any("missing RECORD entry" in item for item in report["problems"])


def test_extra_wheel_member_fails(tmp_path) -> None:
    path = _make_wheel(tmp_path)
    with zipfile.ZipFile(path, "a") as archive:
        archive.writestr("ctf_solver/extra_extra.py", b"EXTRA = 1\n")
    report = provenance.verify_record(path)
    assert report["ok"] is False
    assert any("missing RECORD entry" in item for item in report["problems"])


def test_unsupported_or_malformed_hash_fails(tmp_path) -> None:
    report = provenance.verify_record(_make_wheel(tmp_path, malformed_hash=True))
    assert report["ok"] is False
    assert any("unsupported RECORD hash algorithm" in item for item in report["problems"])
    with pytest.raises(ValueError):
        provenance._decode_record_hash("sha512=AAAA")


def test_record_self_entry_special_fields(tmp_path) -> None:
    assert provenance.verify_record(_make_valid_wheel(tmp_path))["ok"] is True
    broken = provenance.verify_record(_make_wheel(tmp_path, self_hash=True))
    assert broken["ok"] is False
    assert any("self-entry" in item for item in broken["problems"])


def test_tampered_wheel_content_is_detected(tmp_path) -> None:
    path = _make_valid_wheel(tmp_path)
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
    # Rebuild with same RECORD but a changed member's bytes.
    files = {}
    record_name = "ctf_solver-0.1.0.dist-info/RECORD"
    with zipfile.ZipFile(path) as archive:
        for name in names:
            files[name] = archive.read(name)
    files["ctf_solver/core.py"] = b"VALUE = 2\n"
    tampered = tmp_path / "tampered-0.1.0-py3-none-any.whl"
    with zipfile.ZipFile(tampered, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in files.items():
            archive.writestr(name, data)
    report = provenance.verify_record(tampered)
    assert report["ok"] is False
    assert any("hash mismatch" in item for item in report["problems"])


def test_current_formal_wheel_all_members_validate(tmp_path) -> None:
    backend_spec = importlib.util.spec_from_file_location(
        "wheelbuild", REPO / "tooling" / "wheelbuild.py"
    )
    assert backend_spec is not None and backend_spec.loader is not None
    backend = importlib.util.module_from_spec(backend_spec)
    backend_spec.loader.exec_module(backend)
    filename = backend.build_wheel_for_repo(REPO, tmp_path)
    wheel = tmp_path / filename
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
    report = provenance.verify_record(wheel)
    assert report["ok"] is True, report["problems"]
    assert len(names) == 66
    assert report["members_checked"] == 65
