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


MANAGER_TOOLS = (
    "ctf_task_create",
    "ctf_task_list",
    "ctf_task_status",
    "ctf_task_continue",
    "ctf_task_pause",
    "ctf_task_cancel",
    "ctf_task_complete",
    "ctf_approval_request",
    "ctf_approval_list",
    "ctf_grant_list",
    "ctf_grant_revoke",
    "ctf_flag_candidate",
    "ctf_screenshot_capture",
    "ctf_session_ingest",
    "ctf_events_export",
    "ctf_writeup_build",
    "ctf_evidence_zip",
    "ctf_runtime_status",
)

EVIDENCE_HEADING = "## Evidence recording (native tools)"


def test_core_skill_requires_native_category_skill_load_before_analysis() -> None:
    text = _skill_text("ctf-solver")
    normalized = " ".join(text.lower().split())
    assert "before reading or analysing any challenge material" in normalized
    assert "harness native `skill` tool" in normalized
    for category, skill in (
        ("web", "ctf-web"),
        ("misc", "ctf-misc"),
        ("crypto", "ctf-crypto"),
        ("reverse", "ctf-reverse"),
        ("pwn", "ctf-pwn"),
    ):
        assert f"`{category}`" in text, category
        assert f'skill({{"name": "{skill}"}})' in text, skill
    # The load is mandatory and a discovery listing cannot replace it.
    assert "mandatory" in normalized
    assert "stop the analysis" in normalized
    assert "not a substitute" in normalized
    assert "python -m ctf_solver skills" in text


def test_core_skill_lists_all_eighteen_manager_tools() -> None:
    text = _skill_text("ctf-solver")
    assert len(MANAGER_TOOLS) == 18
    for tool in MANAGER_TOOLS:
        assert tool in text, tool


def test_core_skill_makes_lead_native_tools_the_executor() -> None:
    text = _skill_text("ctf-solver")
    lowered = text.lower()
    assert "lead" in lowered
    assert "native harness tools" in lowered
    assert "$env:DSH_SESSION_ID" in text
    assert "lead_session_id" in text
    assert "ctf_session_ingest" in text
    assert "session log" in lowered
    # ctf-exec / Worker MCP is described only as the legacy path.
    assert "legacy worker path" in lowered
    # Category routing is a hard step, and unrecorded steps are never facts.
    assert "hard step" in lowered
    assert "未执行" in text
    assert "未记录" in text
    assert "never fabricate" in lowered


@pytest.mark.parametrize("name", EXPECTED[1:])
def test_category_skills_carry_the_unified_evidence_paragraph(name: str) -> None:
    text = _skill_text(name)
    assert EVIDENCE_HEADING in text, name
    block = text.split(EVIDENCE_HEADING, 1)[1].strip()
    non_empty = [line for line in block.splitlines() if line.strip()]
    assert 1 <= len(non_empty) <= 5, f"{name} evidence paragraph must be <=5 lines"
    assert "turn{N}-step{S}" in block
    for state in ("未执行", "执行失败", "未记录"):
        assert state in block, state
    assert "never hand-write" in block


def test_category_evidence_paragraphs_are_identical() -> None:
    blocks = set()
    for name in EXPECTED[1:]:
        text = _skill_text(name)
        blocks.add(text.split(EVIDENCE_HEADING, 1)[1].strip())
    assert len(blocks) == 1
