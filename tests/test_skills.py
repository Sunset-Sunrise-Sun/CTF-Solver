"""Tests for the six project-local Skills (format and content requirements)."""

from __future__ import annotations

from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SKILLS_ROOT = PROJECT_ROOT / ".dsh" / "skills"
EXPECTED = ("ctf-solver", "ctf-web", "ctf-misc", "ctf-crypto", "ctf-reverse", "ctf-pwn")


def _skill_text(name: str) -> str:
    path = SKILLS_ROOT / name / "SKILL.md"
    return path.read_text(encoding="utf-8")


def test_exactly_six_skill_directories() -> None:
    directories = sorted(path.name for path in SKILLS_ROOT.iterdir() if path.is_dir())
    assert directories == sorted(EXPECTED)
    for name in EXPECTED:
        assert (SKILLS_ROOT / name / "SKILL.md").is_file()


@pytest.mark.parametrize("name", EXPECTED)
def test_skill_is_utf8_without_bom_and_has_frontmatter(name: str) -> None:
    path = SKILLS_ROOT / name / "SKILL.md"
    raw = path.read_bytes()
    assert not raw.startswith(b"\xef\xbb\xbf"), f"{name} must be UTF-8 without BOM"
    text = raw.decode("utf-8")
    assert text.startswith("---\n")
    end = text.find("\n---", 3)
    assert end != -1, f"{name} missing closing frontmatter"
    header = text[3:end]
    fields: dict[str, str] = {}
    for line in header.splitlines():
        if ":" in line and not line.startswith(" "):
            key, value = line.split(":", 1)
            fields[key.strip()] = value.strip()
    assert fields.get("name") == name
    assert fields.get("description")
    assert len(fields["description"]) >= 40
    assert len(text) > 800, f"{name} Skill body looks like a stub"


@pytest.mark.parametrize("name", EXPECTED)
def test_skill_bodies_are_real_instructions_not_stubs(name: str) -> None:
    text = _skill_text(name)
    lowered = text.lower()
    assert "todo" not in lowered
    assert "tbd" not in lowered
    assert "placeholder" not in lowered
    headings = [line for line in text.splitlines() if line.startswith("#")]
    assert len(headings) >= 3, f"{name} needs structured sections"


def test_core_skill_requirements() -> None:
    text = _skill_text("ctf-solver")
    for phrase in (
        "/ctf-solver",
        "persistent",
        "ctf_task_create",
        "ctf_task_continue",
        "ctf_approval_request",
        "approval confirm",
        "ctf_flag_candidate",
        "ctf-writeup" if False else "ctf_writeup_build",
        "ctf_evidence_zip",
        "Tier 2",
        "never fabricate" if False else "Never fabricate",
    ):
        assert phrase in text, phrase
    for category in ("ctf-web", "ctf-misc", "ctf-crypto", "ctf-reverse", "ctf-pwn"):
        assert category in text
    # Intake fields from ROUND_1_IMPLEMENTATION_TASK.md section B.
    for intake in ("title", "category", "screenshot", "ZIP", "target address", "rules"):
        assert intake.lower() in text.lower(), intake


def test_specialist_skills_cover_category_specific_rules() -> None:
    assert "grant" in _skill_text("ctf-web").lower()
    assert "attempt budget" in _skill_text("ctf-misc").lower()
    assert "mathematical" in _skill_text("ctf-crypto").lower()
    assert "static analysis" in _skill_text("ctf-reverse").lower()
    assert "static" in _skill_text("ctf-pwn").lower()
    for name in ("ctf-web", "ctf-misc", "ctf-crypto", "ctf-reverse", "ctf-pwn"):
        text = _skill_text(name).lower()
        assert "candidate" in text
        assert "submit" in text
