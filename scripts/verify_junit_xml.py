"""Verify that committed JUnit XML evidence is well-formed and matches pytest logs.

This is a delivery-audit helper: it parses every tracked ``*junit*.xml`` file with
the standard library XML parser, aggregates tests/failures/errors/skipped, checks
that no unescaped redaction placeholder leaked into XML markup, and compares the
totals with the corresponding raw pytest console log summary.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]

# XML -> corresponding raw pytest console log
LOG_MAP = {
    "round1-evidence/raw/junit-final.xml": "round1-evidence/raw/final-full-suite.txt",
    "round1-evidence/raw/junit-final-with-real-acp.xml": "round1-evidence/raw/final-full-suite-with-real-acp.txt",
    "round1-evidence/raw/junit-post-commit.xml": "round1-evidence/raw/final-post-commit-suite.txt",
    "round2-evidence/raw/junit-round2-default.xml": "round2-evidence/raw/round2-full-suite-default.txt",
    "round2-evidence/raw/junit-round2-with-real-acp.xml": "round2-evidence/raw/round2-full-suite-with-real-acp.txt",
    "round2-evidence/raw/junit-remediation-default.xml": "round2-evidence/raw/remediation-full-default.txt",
    "round2-evidence/raw/junit-remediation-with-real-acp.xml": "round2-evidence/raw/remediation-full-with-real-acp.txt",
    "round2-evidence/raw/junit-hardening-default.xml": "round2-evidence/raw/hardening-full-default.txt",
    "round2-evidence/raw/junit-hardening-with-real-acp.xml": "round2-evidence/raw/hardening-full-with-real-acp.txt",
    "round2-evidence/raw/junit-followup-default.xml": "round2-evidence/raw/hardening-followup-full-default.txt",
    "round2-evidence/raw/junit-followup-with-real-acp.xml": "round2-evidence/raw/hardening-followup-full-with-real-acp.txt",
    "round2-evidence/raw/junit-followup2-default.xml": "round2-evidence/raw/hardening-followup2-full-default.txt",
    "round2-evidence/raw/junit-followup2-with-real-acp.xml": "round2-evidence/raw/hardening-followup2-full-with-real-acp.txt",
    "round2-evidence/raw/junit-finalpatch-default.xml": "round2-evidence/raw/finalpatch-full-default.txt",
    "round2-evidence/raw/junit-finalpatch-with-real-acp.xml": "round2-evidence/raw/finalpatch-full-with-real-acp.txt",
    "round2-evidence/raw/junit-v011-default.xml": "round2-evidence/raw/v011-full-default.txt",
    "round2-evidence/raw/junit-v011-with-real-acp.xml": "round2-evidence/raw/v011-full-with-real-acp.txt",
    "round2-evidence/raw/junit-v011-venv-default.xml": "round2-evidence/raw/v011-venv-default.txt",
    "round2-evidence/raw/junit-v011-venv-with-real-acp.xml": "round2-evidence/raw/v011-venv-with-real-acp.txt",
    "round2-evidence/raw/v011-final-clean-clone-junit.xml": "round2-evidence/raw/v011-final-clean-clone-tests.txt",
    "round2-evidence/raw/final-clean-clone-junit.xml": "round2-evidence/raw/final-clean-clone-tests.txt",
    "round2-evidence/raw/hardening-followup2-clean-clone-junit.xml": "round2-evidence/raw/hardening-followup2-clean-clone-tests.txt",
    "round2-evidence/raw/hardening-final-clone-junit.xml": "round2-evidence/raw/hardening-final-clone-tests.txt",
    "round2-evidence/raw/hardening-followup-clean-clone-junit.xml": "round2-evidence/raw/hardening-followup-clean-clone-tests.txt",
}

_SUMMARY = re.compile(
    r"(\d+) passed(?:, (\d+) skipped)?(?:, (\d+) failed)?(?:, (\d+) errors?)?"
    r"(?:, (\d+) xfailed)?(?:, (\d+) xpassed)?"
)


def tracked_xml() -> list[str]:
    files = subprocess.run(
        ["git", "-C", str(REPO), "ls-files"], capture_output=True, text=True, encoding="utf-8"
    ).stdout.splitlines()
    return sorted(f for f in files if "junit" in f and f.endswith(".xml"))


def parse_xml(path: Path) -> dict[str, object]:
    root = ET.parse(path).getroot()
    suites = [root] if root.tag == "testsuite" else list(root.iter("testsuite"))
    totals = {key: 0 for key in ("tests", "failures", "errors", "skipped")}
    for suite in suites:
        for key in totals:
            totals[key] += int(suite.get(key, "0") or 0)
    raw_text = path.read_text(encoding="utf-8", errors="replace")
    return {
        "totals": totals,
        "contains_raw_placeholder_markup": "<USER_HOME>" in raw_text or "<USER_ID>" in raw_text,
        "personal_home_remaining": bool(re.search(r"C:[\\/]+Users[\\/]+28746", raw_text)),
    }


def log_summary(path: Path) -> dict[str, object] | None:
    if not path.is_file():
        return None
    lines = [line.strip() for line in path.read_text(encoding="utf-8", errors="replace").splitlines()]
    for line in reversed(lines):
        match = _SUMMARY.search(line)
        if match:
            return {
                "passed": int(match.group(1)),
                "skipped": int(match.group(2) or 0),
                "failed": int(match.group(3) or 0),
                "errors": int(match.group(4) or 0),
                "xfailed": int(match.group(5) or 0),
                "xpassed": int(match.group(6) or 0),
                "summary_line": line,
            }
    return None


def main() -> int:
    report: dict[str, object] = {"xml_files": {}, "problems": []}
    for rel in tracked_xml():
        path = REPO / rel
        parsed = parse_xml(path)
        log_rel = LOG_MAP.get(rel)
        summary = log_summary(REPO / log_rel) if log_rel else None
        totals = parsed["totals"]
        assert isinstance(totals, dict)
        derived_passed = (
            totals["tests"] - totals["failures"] - totals["errors"] - totals["skipped"]
        )
        entry = {
            **parsed,
            "log": log_rel,
            "log_summary": summary,
            "derived_passed": derived_passed,
        }
        if summary is not None:
            expected_passed = int(summary["passed"]) + int(summary["xpassed"])
            expected_skipped = int(summary["skipped"])
            if derived_passed != expected_passed:
                report["problems"].append(f"passed mismatch: {rel}: {derived_passed} vs {expected_passed}")
            if totals["skipped"] != expected_skipped:
                report["problems"].append(f"skipped mismatch: {rel}: {totals['skipped']} vs {expected_skipped}")
            if totals["failures"] != int(summary["failed"]):
                report["problems"].append(f"failures mismatch: {rel}")
        if parsed["contains_raw_placeholder_markup"]:
            report["problems"].append(f"unescaped redaction placeholder: {rel}")
        if parsed["personal_home_remaining"]:
            report["problems"].append(f"personal home path remains: {rel}")
        report["xml_files"][rel] = entry
    report["ok"] = not report["problems"]
    out = REPO / "round2-evidence/raw/junit-xml-verification.json"
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"ok": report["ok"], "problems": report["problems"]}, ensure_ascii=False, indent=2))
    for rel, entry in report["xml_files"].items():  # type: ignore[union-attr]
        print(rel, entry["totals"], "log=", entry["log"])
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
