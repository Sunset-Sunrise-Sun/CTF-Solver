"""Delivery evidence: every committed JUnit XML must be well-formed.

The privacy redaction once inserted an unescaped ``<USER_HOME>`` placeholder into
a JUnit XML file, making it unparseable. This regression test parses every
tracked ``*junit*.xml`` with the standard library XML parser and also checks the
redaction placeholder is escaped and no personal home path remains.
"""

from __future__ import annotations

import re
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def _junit_files() -> list[Path]:
    files = subprocess.run(
        ["git", "-C", str(REPO), "ls-files"], capture_output=True, text=True, encoding="utf-8"
    ).stdout.splitlines()
    return sorted(REPO / rel for rel in files if "junit" in rel and rel.endswith(".xml"))


def test_all_committed_junit_xml_files_parse_and_counts_are_consistent() -> None:
    files = _junit_files()
    assert files, "no JUnit XML evidence files found"
    for path in files:
        text = path.read_text(encoding="utf-8", errors="replace")
        assert "<USER_HOME>" not in text, f"unescaped redaction placeholder in {path}"
        assert "<USER_ID>" not in text, f"unescaped redaction placeholder in {path}"
        assert not re.search(r"C:[\\/]+Users[\\/]+28746", text), f"personal path in {path}"
        root = ET.parse(path).getroot()  # raises ParseError if malformed
        suites = [root] if root.tag == "testsuite" else list(root.iter("testsuite"))
        assert suites, f"no testsuite element in {path}"
        totals = {key: 0 for key in ("tests", "failures", "errors", "skipped")}
        for suite in suites:
            for key in totals:
                totals[key] += int(suite.get(key, "0") or 0)
        assert totals["tests"] > 0, path
        assert totals["failures"] == 0, (path, totals)
        assert totals["errors"] == 0, (path, totals)
        assert totals["skipped"] >= 0
        derived_passed = totals["tests"] - totals["failures"] - totals["errors"] - totals["skipped"]
        assert derived_passed > 0, (path, totals)


def test_redacted_junit_text_restores_placeholder_after_xml_parse() -> None:
    """The escaped placeholder must be literal text, not an element."""

    path = REPO / "round2-evidence/raw/hardening-final-clone-junit.xml"
    root = ET.parse(path).getroot()
    text = "".join(root.itertext())
    assert "<USER_HOME>" in text or "<USER_ID>" in text
    assert root.tag not in {"USER_HOME", "USER_ID"}
    for element in root.iter():
        assert element.tag not in {"USER_HOME", "USER_ID"}
