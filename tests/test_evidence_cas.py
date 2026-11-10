"""Deterministic tests for the SHA-256 content-addressed store."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from ctf_solver.core.errors import NotFoundError, StorageError, ValidationError
from ctf_solver.evidence.cas import Cas
from tests.test_evidence_support import make_cas


def test_put_bytes_layout_and_roundtrip(tmp_path: Path) -> None:
    cas = make_cas(tmp_path)
    data = b"synthetic evidence bytes"
    ref = cas.put_bytes(data, media_type="application/octet-stream")
    assert ref.sha256 == hashlib.sha256(data).hexdigest()
    assert ref.size == len(data)
    assert ref.media_type == "application/octet-stream"
    expected_path = cas.root / ref.sha256[:2] / ref.sha256
    assert Path(ref.cas_path) == expected_path
    assert expected_path.is_file()
    assert cas.exists(ref.sha256) is True
    assert cas.get_bytes(ref.sha256) == data
    assert cas.verify(ref.sha256) is True


def test_empty_object_roundtrip(tmp_path: Path) -> None:
    cas = make_cas(tmp_path)
    ref = cas.put_bytes(b"")
    assert ref.sha256 == hashlib.sha256(b"").hexdigest()
    assert ref.size == 0
    assert cas.get_bytes(ref.sha256) == b""


def test_dedup_identical_bytes_single_object(tmp_path: Path) -> None:
    cas = make_cas(tmp_path)
    data = b"duplicate me"
    first = cas.put_bytes(data, media_type="text/plain")
    object_path = cas.path_for(first.sha256)
    mtime_before = object_path.stat().st_mtime_ns
    second = cas.put_bytes(data, media_type="application/json")
    assert second.sha256 == first.sha256
    assert second.media_type == "application/json"  # metadata from the caller
    assert cas.count_objects() == 1
    assert object_path.stat().st_mtime_ns == mtime_before  # never mutated
    assert cas.get_bytes(first.sha256) == data


def test_put_file_matches_put_bytes(tmp_path: Path) -> None:
    cas = make_cas(tmp_path)
    source = tmp_path / "artifact.bin"
    source.write_bytes(b"file based evidence")
    ref = cas.put_file(source, media_type="application/octet-stream")
    assert ref.sha256 == hashlib.sha256(b"file based evidence").hexdigest()
    assert cas.get_bytes(ref.sha256) == b"file based evidence"


def test_put_file_missing_raises_not_found(tmp_path: Path) -> None:
    cas = make_cas(tmp_path)
    with pytest.raises(NotFoundError):
        cas.put_file(tmp_path / "missing.bin")


def test_get_bytes_missing_raises_not_found(tmp_path: Path) -> None:
    cas = make_cas(tmp_path)
    digest = hashlib.sha256(b"never stored").hexdigest()
    assert cas.exists(digest) is False
    with pytest.raises(NotFoundError):
        cas.get_bytes(digest)


@pytest.mark.parametrize(
    "digest",
    [
        "",
        "not-a-digest",
        "../../etc/passwd",
        "A" * 64,
        "a" * 63,
        "a" * 65,
        None,
    ],
)
def test_path_for_rejects_invalid_digests(tmp_path: Path, digest: object) -> None:
    cas = make_cas(tmp_path)
    with pytest.raises(ValidationError):
        cas.path_for(digest)  # type: ignore[arg-type]


def test_verify_detects_corruption(tmp_path: Path) -> None:
    cas = make_cas(tmp_path)
    ref = cas.put_bytes(b"tamper target")
    cas.path_for(ref.sha256).write_bytes(b"tamper target corrupted")
    assert cas.verify(ref.sha256) is False
    assert cas.verify(hashlib.sha256(b"absent").hexdigest()) is False


def test_put_existing_corrupt_object_fails_closed(tmp_path: Path) -> None:
    cas = make_cas(tmp_path)
    data = b"original evidence"
    ref = cas.put_bytes(data)
    cas.path_for(ref.sha256).write_bytes(b"attacker replaced the bytes")
    with pytest.raises(StorageError):
        cas.put_bytes(data)


def test_iter_objects_sorted_and_sized(tmp_path: Path) -> None:
    cas = make_cas(tmp_path)
    payloads = [b"one", b"two-two", b"three-three-three"]
    refs = [cas.put_bytes(payload) for payload in payloads]
    objects = list(cas.iter_objects())
    assert len(objects) == 3
    assert [ref.sha256 for ref in objects] == sorted(ref.sha256 for ref in refs)
    assert {ref.size for ref in objects} == {len(payload) for payload in payloads}
    assert cas.count_objects() == 3


def test_iter_objects_empty_store(tmp_path: Path) -> None:
    cas = make_cas(tmp_path)
    assert list(cas.iter_objects()) == []


def test_verify_all_reports_per_object_status(tmp_path: Path) -> None:
    cas = make_cas(tmp_path)
    good = cas.put_bytes(b"good object")
    bad = cas.put_bytes(b"bad object")
    cas.path_for(bad.sha256).write_bytes(b"corrupted")
    report = cas.verify_all()
    assert report[good.sha256] is True
    assert report[bad.sha256] is False


def test_original_object_not_observable_before_atomic_write(tmp_path: Path) -> None:
    """No partially written object may be visible under a final digest path."""

    cas = make_cas(tmp_path)
    ref = cas.put_bytes(b"atomic write check")
    leftovers = list(cas.root.rglob("*.tmp"))
    assert leftovers == []
    assert cas.get_bytes(ref.sha256) == b"atomic write check"
