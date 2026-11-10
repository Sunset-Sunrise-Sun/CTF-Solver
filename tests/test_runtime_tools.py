"""Builtin internal tool behaviour tests (real, bounded, no extraction/exec)."""

from __future__ import annotations

import hashlib
import json
import tarfile
import zipfile
from pathlib import Path

import pytest

from ctf_solver.core.canonical import sha256_hex
from ctf_solver.core.types import ExecutionStatus
from ctf_solver.runtime.catalog import RuntimeCatalog
from ctf_solver.runtime.executor import RuntimeExecutor
from ctf_solver.runtime.tools import ToolInvocation

PNG_HEADER = b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\rIHDR"


def run_internal(
    name: str, argv: list[str], cwd: Path, **kwargs: object
):
    catalog = RuntimeCatalog.default()
    spec = catalog.get(name)
    assert spec is not None, f"tool {name} missing from catalogue"
    return RuntimeExecutor().execute(
        spec, ToolInvocation(argv=list(argv), cwd=str(cwd), **kwargs)  # type: ignore[arg-type]
    )


def json_payload(outcome, *, expected_status: ExecutionStatus = ExecutionStatus.COMPLETED):
    assert outcome.status is expected_status, outcome.error
    return json.loads(outcome.stdout.decode("utf-8"))


# ---------------------------------------------------------------------------
# internal.file_hash
# ---------------------------------------------------------------------------


def test_file_hash_real_behavior(tmp_path: Path) -> None:
    data = b"the quick brown fox\n"
    (tmp_path / "input.txt").write_bytes(data)
    outcome = run_internal("internal.file_hash", ["input.txt"], tmp_path)
    payload = json_payload(outcome)
    assert payload["path"] == "input.txt"
    assert payload["size"] == len(data)
    assert payload["sha256"] == hashlib.sha256(data).hexdigest()


def test_file_hash_deterministic(tmp_path: Path) -> None:
    (tmp_path / "a.bin").write_bytes(b"deterministic")
    first = run_internal("internal.file_hash", ["a.bin"], tmp_path)
    second = run_internal("internal.file_hash", ["a.bin"], tmp_path)
    assert first.stdout == second.stdout


def test_file_hash_missing_file_reports_failure(tmp_path: Path) -> None:
    outcome = run_internal("internal.file_hash", ["missing.txt"], tmp_path)
    assert outcome.status is ExecutionStatus.FAILED
    assert "not found" in outcome.error


@pytest.mark.parametrize(
    "name", ["internal.file_hash", "internal.file_metadata", "internal.archive_list"]
)
@pytest.mark.parametrize("argument", ["../outside.txt", "..\\outside.txt", "sub/../../outside.txt"])
def test_file_tools_reject_traversal_even_without_broker(
    tmp_path: Path, name: str, argument: str
) -> None:
    (tmp_path.parent / "outside.txt").write_bytes(b"secret")
    outcome = run_internal(name, [argument], tmp_path)
    assert outcome.status is ExecutionStatus.FAILED


@pytest.mark.parametrize("name", ["internal.file_hash", "internal.file_metadata"])
def test_file_tools_reject_absolute_paths(tmp_path: Path, name: str) -> None:
    target = tmp_path / "a.txt"
    target.write_bytes(b"x")
    outcome = run_internal(name, [str(target)], tmp_path)
    assert outcome.status is ExecutionStatus.FAILED


# ---------------------------------------------------------------------------
# internal.file_metadata
# ---------------------------------------------------------------------------


def test_file_metadata_detects_png_magic(tmp_path: Path) -> None:
    (tmp_path / "image.png").write_bytes(PNG_HEADER + b"rest")
    payload = json_payload(run_internal("internal.file_metadata", ["image.png"], tmp_path))
    assert payload["magic_type"] == "png"
    assert payload["extension"] == ".png"
    assert payload["size"] == len(PNG_HEADER) + 4
    assert payload["is_dir"] is False


def test_file_metadata_directory(tmp_path: Path) -> None:
    (tmp_path / "folder").mkdir()
    payload = json_payload(run_internal("internal.file_metadata", ["folder"], tmp_path))
    assert payload["is_dir"] is True
    assert payload["magic_type"] == "directory"


def test_file_metadata_missing_path_reports_failure(tmp_path: Path) -> None:
    outcome = run_internal("internal.file_metadata", ["nope.bin"], tmp_path)
    assert outcome.status is ExecutionStatus.FAILED


# ---------------------------------------------------------------------------
# internal.archive_list (metadata only)
# ---------------------------------------------------------------------------


def test_archive_list_zip_metadata_only(tmp_path: Path) -> None:
    archive = tmp_path / "challenge.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("readme.txt", "hello")
        handle.writestr("bin/blob.bin", b"\x00\x01\x02")
    before = sorted(path.name for path in tmp_path.iterdir())
    payload = json_payload(run_internal("internal.archive_list", ["challenge.zip"], tmp_path))
    after = sorted(path.name for path in tmp_path.iterdir())
    assert payload["format"] == "zip"
    assert payload["entry_count"] == 2
    assert {entry["name"] for entry in payload["entries"]} == {"readme.txt", "bin/blob.bin"}
    assert payload["truncated"] is False
    # metadata only: nothing was extracted
    assert before == after


def test_archive_list_tar_metadata_only(tmp_path: Path) -> None:
    archive = tmp_path / "challenge.tar"
    source = tmp_path / "payload.txt"
    source.write_bytes(b"payload")
    with tarfile.open(archive, "w") as handle:
        handle.add(source, arcname="payload.txt")
    payload = json_payload(run_internal("internal.archive_list", ["challenge.tar"], tmp_path))
    assert payload["format"] == "tar"
    assert [entry["name"] for entry in payload["entries"]] == ["payload.txt"]


def test_archive_list_rejects_non_archive(tmp_path: Path) -> None:
    (tmp_path / "plain.txt").write_text("not an archive", encoding="utf-8")
    outcome = run_internal("internal.archive_list", ["plain.txt"], tmp_path)
    assert outcome.status is ExecutionStatus.FAILED
    assert "unsupported archive format" in outcome.error


def test_archive_list_reports_corrupt_zip(tmp_path: Path) -> None:
    (tmp_path / "broken.zip").write_bytes(b"PK\x03\x04" + b"\x00" * 40)
    outcome = run_internal("internal.archive_list", ["broken.zip"], tmp_path)
    assert outcome.status is ExecutionStatus.FAILED
    assert "zip archive metadata" in outcome.error


# ---------------------------------------------------------------------------
# internal.text_search
# ---------------------------------------------------------------------------


def test_text_search_finds_literal_matches(tmp_path: Path) -> None:
    (tmp_path / "a.txt").write_text("line one needle\nplain\n", encoding="utf-8")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "b.txt").write_text("needle again\n", encoding="utf-8")
    payload = json_payload(run_internal("internal.text_search", ["needle"], tmp_path))
    assert payload["match_count"] == 2
    paths = [match["path"] for match in payload["matches"]]
    assert paths == sorted(paths) or set(paths) == {"a.txt", "sub/b.txt"}
    assert {match["path"] for match in payload["matches"]} == {"a.txt", "sub/b.txt"}
    assert payload["truncated"] is False


def test_text_search_is_literal_not_regex(tmp_path: Path) -> None:
    (tmp_path / "code.txt").write_text("a.b and axb\n", encoding="utf-8")
    payload = json_payload(run_internal("internal.text_search", ["a.b"], tmp_path))
    assert payload["match_count"] == 1
    assert payload["matches"][0]["column"] == 1


def test_text_search_skips_binary_files(tmp_path: Path) -> None:
    (tmp_path / "bin.dat").write_bytes(b"\x00needle\x00")
    (tmp_path / "text.txt").write_text("needle\n", encoding="utf-8")
    payload = json_payload(run_internal("internal.text_search", ["needle"], tmp_path))
    assert {match["path"] for match in payload["matches"]} == {"text.txt"}
    assert payload["searched_files"] == 1


def test_text_search_is_bounded(tmp_path: Path) -> None:
    (tmp_path / "many.txt").write_text("needle\n" * 1100, encoding="utf-8")
    payload = json_payload(run_internal("internal.text_search", ["needle"], tmp_path))
    assert payload["match_count"] == 1000
    assert payload["truncated"] is True


def test_text_search_restricted_to_subpath(tmp_path: Path) -> None:
    (tmp_path / "root.txt").write_text("needle\n", encoding="utf-8")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "only.txt").write_text("needle\n", encoding="utf-8")
    payload = json_payload(
        run_internal("internal.text_search", ["needle", "sub"], tmp_path)
    )
    assert [match["path"] for match in payload["matches"]] == ["sub/only.txt"]


def test_text_search_missing_path_reports_failure(tmp_path: Path) -> None:
    outcome = run_internal("internal.text_search", ["needle", "missing"], tmp_path)
    assert outcome.status is ExecutionStatus.FAILED


def test_text_search_no_matches(tmp_path: Path) -> None:
    (tmp_path / "a.txt").write_text("nothing here\n", encoding="utf-8")
    payload = json_payload(run_internal("internal.text_search", ["absent"], tmp_path))
    assert payload["match_count"] == 0
    assert payload["matches"] == []


# ---------------------------------------------------------------------------
# internal.hex_preview
# ---------------------------------------------------------------------------


def test_hex_preview_real_behavior(tmp_path: Path) -> None:
    (tmp_path / "data.bin").write_bytes(bytes(range(32)))
    outcome = run_internal("internal.hex_preview", ["data.bin", "4", "8"], tmp_path)
    assert outcome.status is ExecutionStatus.COMPLETED
    text = outcome.stdout.decode("ascii")
    assert text.startswith("00000004  04 05 06 07 08 09 0a 0b")
    assert "|" in text


def test_hex_preview_default_length_is_bounded(tmp_path: Path) -> None:
    (tmp_path / "data.bin").write_bytes(b"A" * 5000)
    outcome = run_internal("internal.hex_preview", ["data.bin"], tmp_path)
    assert outcome.status is ExecutionStatus.COMPLETED
    assert outcome.stdout.count(b"\n") == 16  # 256 bytes / 16 per row


def test_hex_preview_offset_past_end_reports_failure(tmp_path: Path) -> None:
    (tmp_path / "small.bin").write_bytes(b"abc")
    outcome = run_internal("internal.hex_preview", ["small.bin", "100", "16"], tmp_path)
    assert outcome.status is ExecutionStatus.FAILED
    assert "past the end" in outcome.error


# ---------------------------------------------------------------------------
# internal.strings_scan
# ---------------------------------------------------------------------------


def test_strings_scan_finds_printable_strings(tmp_path: Path) -> None:
    (tmp_path / "binary.dat").write_bytes(
        b"\x00HELLO_WORLD\x00short\x00ANOTHER_STRING_123\x00"
    )
    payload = json_payload(run_internal("internal.strings_scan", ["binary.dat"], tmp_path))
    values = [entry["value"] for entry in payload["strings"]]
    assert "HELLO_WORLD" in values
    assert "ANOTHER_STRING_123" in values
    assert "short" in values  # >= default min length 4
    assert payload["string_count"] == len(values)


def test_strings_scan_min_length_filter(tmp_path: Path) -> None:
    (tmp_path / "binary.dat").write_bytes(b"\x00AB\x00LONG_ENOUGH_STRING\x00")
    payload = json_payload(
        run_internal("internal.strings_scan", ["binary.dat", "8"], tmp_path)
    )
    values = [entry["value"] for entry in payload["strings"]]
    assert values == ["LONG_ENOUGH_STRING"]


def test_strings_scan_is_bounded(tmp_path: Path) -> None:
    blob = b"".join(b"ABCD\x00" for _ in range(2100))
    (tmp_path / "many.bin").write_bytes(blob)
    payload = json_payload(run_internal("internal.strings_scan", ["many.bin"], tmp_path))
    assert payload["string_count"] == 2000
    assert payload["truncated"] is True


# ---------------------------------------------------------------------------
# Trust properties of the builtin catalogue
# ---------------------------------------------------------------------------


def test_no_builtin_tool_executes_challenge_code() -> None:
    catalog = RuntimeCatalog.default()
    for spec in catalog.list_tools():
        assert spec.executes_challenge_code is False, spec.name


def test_internal_tools_never_use_a_subprocess_executable() -> None:
    catalog = RuntimeCatalog.default()
    for spec in catalog.list_tools():
        if spec.name.startswith("internal."):
            assert spec.internal is not None
            assert spec.version_probe is None
            assert spec.executable is None


def test_probe_tools_accept_only_fixed_argv() -> None:
    catalog = RuntimeCatalog.default()
    for name in ("tool.git_version", "tool.python_version"):
        spec = catalog.get(name)
        assert spec is not None
        assert spec.arg_validator is not None
        assert spec.arg_validator(["--version"]) is None
        assert spec.arg_validator(["--version", "extra"]) is not None
        assert spec.arg_validator(["--exec", "malicious"]) is not None


def test_text_search_rejects_regex_bomb_length(tmp_path: Path) -> None:
    catalog = RuntimeCatalog.default()
    spec = catalog.get("internal.text_search")
    assert spec is not None and spec.arg_validator is not None
    assert spec.arg_validator(["x" * 300]) is not None
