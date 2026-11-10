"""Tests for the read-only preflight/doctor."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from ctf_solver.preflight.doctor import EXPECTED_SKILLS, render_text, run_preflight
from tests.support.proc import PROJECT_ROOT


def _tree_state(root: Path) -> set[tuple[str, int, int]]:
    state: set[tuple[str, int, int]] = set()
    for path in sorted(root.rglob("*")):
        if path.is_file():
            stat = path.stat()
            state.add((path.relative_to(root).as_posix(), stat.st_size, stat.st_mtime_ns))
    return state


def _copy_skills(root: Path) -> None:
    source = PROJECT_ROOT / ".dsh" / "skills"
    target = root / ".dsh" / "skills"
    shutil.copytree(source, target)


def test_preflight_reports_project_skills_and_is_read_only(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    _copy_skills(root)
    (root / "config" / "acp").mkdir(parents=True)
    shutil.copy(PROJECT_ROOT / "config" / "acp" / "cordis.patch.yml", root / "config" / "acp" / "cordis.patch.yml")
    before = _tree_state(root)

    report = run_preflight(root)

    after = _tree_state(root)
    assert before == after, "preflight must not create, modify or delete files"
    assert report["read_only"] is True
    assert report["mutations"] == []
    assert report["skills"]["ok"] is True
    assert set(report["skills"]["found"]) == set(EXPECTED_SKILLS)
    for name in EXPECTED_SKILLS:
        info = report["skills"]["found"][name]
        assert info["utf8"] is True
        assert info["bom"] is False
        assert info["frontmatter"] is True
        assert info["description"] is True
        assert info["name"] == name
    assert report["privacy_gate"]["project_patch_present"] is True
    assert report["privacy_gate"]["project_patch_disables_delivery"] is True
    assert report["privacy_gate"]["negative_outbound_delivery_test"].startswith("NOT VERIFIED")
    assert report["isolation"]["docker_daemon_state"].startswith("not_verified")
    assert report["isolation"]["wsl_distribution_state"].startswith("not_verified")
    assert report["summary"]["no_environment_mutation"] is True
    # Preflight must not create runtime data directories.
    assert not (root / ".ctf-solver-data").exists()


def test_preflight_reports_missing_skills(tmp_path: Path) -> None:
    report = run_preflight(tmp_path)
    assert report["skills"]["ok"] is False
    assert set(report["skills"]["missing"]) == set(EXPECTED_SKILLS)


def test_preflight_detects_utf8_bom(tmp_path: Path) -> None:
    _copy_skills(tmp_path)
    target = tmp_path / ".dsh" / "skills" / "ctf-web" / "SKILL.md"
    original = target.read_bytes()
    target.write_bytes(b"\xef\xbb\xbf" + original)
    report = run_preflight(tmp_path)
    assert report["skills"]["ok"] is False
    assert any("BOM" in problem for problem in report["skills"]["problems"])
    assert report["skills"]["found"]["ctf-web"]["bom"] is True


def test_preflight_reports_missing_description(tmp_path: Path) -> None:
    _copy_skills(tmp_path)
    target = tmp_path / ".dsh" / "skills" / "ctf-pwn" / "SKILL.md"
    text = target.read_text(encoding="utf-8")
    lines = [line for line in text.splitlines() if not line.strip().startswith("description:")]
    target.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    report = run_preflight(tmp_path)
    assert report["skills"]["ok"] is False
    assert any("description" in problem for problem in report["skills"]["problems"])


def test_preflight_human_report(tmp_path: Path) -> None:
    _copy_skills(tmp_path)
    report = run_preflight(tmp_path)
    text = render_text(report)
    assert "CTF-Solver preflight (read-only)" in text
    assert "Skills:" in text
    assert "Session-log privacy gate (P0):" in text
    assert "No environment mutation performed." in text
    json.dumps(report)  # machine-readable and JSON serializable


def test_preflight_toolchain_reports_missing_separately_from_unverified(tmp_path: Path) -> None:
    report = run_preflight(tmp_path)
    tools = report["toolchain"]
    assert "git" in tools
    assert tools["git"]["status"] in {"available", "missing", "unknown"}
    for info in tools.values():
        assert info["status"] in {"available", "missing", "unknown"}
    assert "not verified" in report["isolation"]["tier2_os_isolation"].lower()
