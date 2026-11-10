"""Read-only first-run preflight / doctor.

The preflight never installs, configures or starts anything, and never launches
WSL/Docker or the Harness application. It reports facts separately from
"not verified": a tool that is absent is reported ``missing``; a runtime whose
state cannot be inspected without side effects is reported ``not_verified``.
"""

from __future__ import annotations

import importlib.util
import json
import os
import platform
import shutil
import subprocess
import sys
import sysconfig
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "1.0"
EXPECTED_SKILLS = ("ctf-solver", "ctf-web", "ctf-misc", "ctf-crypto", "ctf-reverse", "ctf-pwn")

_TOOLCHAIN = {
    "git": ["git"],
    "python": [sys.executable],
    "node": ["node"],
    "java": ["java"],
    "javac": ["javac"],
    "ghidra": ["ghidraRun", "ghidra"],
    "gdb": ["gdb"],
    "java_jdk": ["javac"],
    "wireshark": ["wireshark"],
    "tshark": ["tshark"],
    "radare2": ["radare2"],
    "rizin": ["rizin"],
    "7z": ["7z", "7za"],
    "nmap": ["nmap"],
    "sqlmap": ["sqlmap"],
    "hashcat": ["hashcat"],
    "john": ["john"],
    "binwalk": ["binwalk"],
    "sage": ["sage"],
}

_PYTHON_MODULES = (
    "sqlite3",
    "zlib",
    "tkinter",
    "compression.zstd",
    "zstandard",
    "PIL",
    "pwn",
    "z3",
    "Crypto",
    "capstone",
    "unicorn",
    "angr",
    "elftools",
    "scapy",
)


def _which_any(candidates: list[str]) -> str | None:
    for candidate in candidates:
        if candidate == sys.executable:
            return candidate
        found = shutil.which(candidate)
        if found:
            return found
    return None


def _probe_version(argv: list[str], *, timeout_s: float = 5.0) -> dict[str, Any]:
    try:
        completed = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_s,
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"available": False, "version": None, "error": str(exc)}
    text = (completed.stdout or completed.stderr or "").strip().splitlines()
    first = text[0].strip() if text else ""
    return {"available": completed.returncode == 0, "version": first, "exit_code": completed.returncode}


def _module_status(name: str) -> dict[str, Any]:
    try:
        spec = importlib.util.find_spec(name)
    except (ImportError, ValueError, ModuleNotFoundError):
        spec = None
    available = spec is not None
    version = None
    if available:
        try:
            module = __import__(name, fromlist=["__version__"])
            version = getattr(module, "__version__", None)
        except Exception:  # noqa: BLE001 - probing must never fail the report
            version = None
    return {"available": available, "version": str(version) if version else None}


def _skill_report(root: Path) -> dict[str, Any]:
    skills_root = root / ".dsh" / "skills"
    found: dict[str, Any] = {}
    problems: list[str] = []
    if not skills_root.is_dir():
        problems.append(f"skills root missing: {skills_root}")
    else:
        for entry in sorted(skills_root.iterdir()):
            if not entry.is_dir():
                continue
            skill_file = entry / "SKILL.md"
            if not skill_file.is_file():
                continue
            raw = skill_file.read_bytes()
            entry_report: dict[str, Any] = {
                "path": str(skill_file),
                "size": len(raw),
                "utf8": True,
                "bom": raw.startswith(b"\xef\xbb\xbf"),
                "frontmatter": False,
                "name": None,
                "description": False,
            }
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError:
                entry_report["utf8"] = False
                problems.append(f"{skill_file}: invalid UTF-8")
                found[entry.name] = entry_report
                continue
            if entry_report["bom"]:
                problems.append(f"{skill_file}: UTF-8 BOM present (Harness silently ignores such Skills)")
            if text.startswith("---"):
                end = text.find("\n---", 3)
                if end != -1:
                    header = text[3:end]
                    entry_report["frontmatter"] = True
                    for line in header.splitlines():
                        if line.strip().startswith("name:"):
                            entry_report["name"] = line.split(":", 1)[1].strip().strip('"').strip("'")
                        if line.strip().startswith("description:"):
                            entry_report["description"] = True
            if not entry_report["frontmatter"]:
                problems.append(f"{skill_file}: missing YAML frontmatter")
            elif not entry_report["description"]:
                problems.append(f"{skill_file}: frontmatter missing description")
            if entry_report["name"] and entry_report["name"] != entry.name:
                problems.append(
                    f"{skill_file}: frontmatter name {entry_report['name']!r} does not match directory {entry.name!r}"
                )
            found[entry.name] = entry_report
    missing = [name for name in EXPECTED_SKILLS if name not in found]
    if missing:
        problems.append("missing Skills: " + ", ".join(missing))
    return {
        "root": str(skills_root),
        "found": found,
        "missing": missing,
        "problems": problems,
        "ok": not problems,
    }


def _privacy_gate_report(root: Path) -> dict[str, Any]:
    patch = root / "config" / "acp" / "cordis.patch.yml"
    documented = patch.is_file()
    configured = False
    if documented:
        text = patch.read_text(encoding="utf-8", errors="replace")
        configured = "session-log-deepseek" in text and "enabled: false" in text.replace("\t", " ")
    return {
        "mechanism": "disable the session-log-deepseek plugin in a dedicated profile via cordis.patch.yml",
        "project_patch_file": str(patch),
        "project_patch_present": documented,
        "project_patch_disables_delivery": configured,
        "isolated_temp_home_verification": "not run by preflight; see docs/ROUND_1_ARCHITECTURE_NOTES.md",
        "global_harness_state": "not inspected (no global configuration is read or modified by preflight)",
        "negative_outbound_delivery_test": "NOT VERIFIED (requires a model request; blocked in Round 1)",
        "status": "BLOCKED_FOR_REAL_CTF_DATA" if not configured else "MECHANISM_CONFIGURED_DELIVERY_UNVERIFIED",
    }


def _toolchain_report() -> dict[str, Any]:
    tools: dict[str, Any] = {}
    for name, candidates in _TOOLCHAIN.items():
        path = _which_any(candidates)
        if path is None:
            tools[name] = {"status": "missing", "path": None, "version": None}
            continue
        probe = _probe_version([path, "--version"])
        if not probe.get("version"):
            probe = _probe_version([path, "-version"])
        tools[name] = {
            "status": "available" if probe.get("available") else "unknown",
            "path": path,
            "version": probe.get("version"),
        }
    return tools


def _isolation_report() -> dict[str, Any]:
    docker_cli = shutil.which("docker")
    wsl_cli = shutil.which("wsl")
    return {
        "tier2_os_isolation": "NOT AVAILABLE / NOT VERIFIED in this run (no install, no WSL/Docker start)",
        "docker_cli_present": docker_cli is not None,
        "docker_daemon_state": "not_verified (preflight does not start or connect to Docker)",
        "wsl_cli_present": wsl_cli is not None,
        "wsl_distribution_state": "not_verified (preflight does not start WSL)",
        "untrusted_challenge_code_execution": "BLOCKED until a Tier 2 isolation environment is installed and accepted",
        "gvisor_present": shutil.which("runsc") is not None,
    }


def _storage_report(root: Path) -> dict[str, Any]:
    db_path = root / ".ctf-solver-data" / "manager.sqlite"
    cas_root = root / ".ctf-solver-data" / "cas" / "sha256"
    report: dict[str, Any] = {
        "db_path": str(db_path),
        "db_present": db_path.is_file(),
        "db_schema_version": None,
        "cas_root": str(cas_root),
        "cas_present": cas_root.is_dir(),
        "tasks_dir_present": (root / "tasks").is_dir(),
    }
    if db_path.is_file():
        import sqlite3

        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
            try:
                row = conn.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
                report["db_schema_version"] = row[0] if row else None
            finally:
                conn.close()
        except sqlite3.Error as exc:
            report["db_schema_version"] = f"error: {exc}"
    return report


def _acp_report() -> dict[str, Any]:
    from ..core.config import discover_acp_command

    command = discover_acp_command()
    return {
        "launcher": command,
        "found": command is not None,
        "version": "not_verified (preflight does not execute the launcher)",
        "mode": "dsh --profile acp (ACP Server over stdio ND-JSON/JSON-RPC 2.0)",
        "manager_role": "Manager implements the ACP Client; no model call is made in Round 1",
    }


def run_preflight(root: str | os.PathLike[str] = ".") -> dict[str, Any]:
    """Return a machine-readable, read-only environment report."""

    base = Path(os.path.abspath(os.fspath(root)))
    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "generated_at_ms": int(__import__("time").time() * 1000),
        "root": str(base),
        "read_only": True,
        "mutations": [],
        "environment": {
            "os": platform.platform(),
            "machine": platform.machine(),
            "python_version": platform.python_version(),
            "python_executable": sys.executable,
            "python_implementation": platform.python_implementation(),
            "platform_dir": sysconfig.get_platform(),
            "cwd": os.getcwd(),
            "node_version": _module_version_node(),
        },
        "python_modules": {name: _module_status(name) for name in _PYTHON_MODULES},
        "toolchain": _toolchain_report(),
        "acp": _acp_report(),
        "isolation": _isolation_report(),
        "skills": _skill_report(base),
        "privacy_gate": _privacy_gate_report(base),
        "storage": _storage_report(base),
    }
    report["summary"] = _summary(report)
    return report


def _module_version_node() -> dict[str, Any]:
    node = shutil.which("node")
    if not node:
        return {"status": "missing", "version": None}
    probe = _probe_version([node, "--version"])
    return {"status": "available" if probe.get("available") else "unknown", "version": probe.get("version")}


def _summary(report: dict[str, Any]) -> dict[str, Any]:
    tools = report["toolchain"]
    available = sorted(name for name, value in tools.items() if value["status"] == "available")
    missing = sorted(name for name, value in tools.items() if value["status"] == "missing")
    modules = report["python_modules"]
    modules_available = sorted(name for name, value in modules.items() if value["available"])
    modules_missing = sorted(name for name, value in modules.items() if not value["available"])
    return {
        "tools_available": available,
        "tools_missing": missing,
        "python_modules_available": modules_available,
        "python_modules_missing": modules_missing,
        "skills_ok": report["skills"]["ok"],
        "acp_launcher_found": report["acp"]["found"],
        "session_log_privacy_gate": report["privacy_gate"]["status"],
        "tier2_isolation": report["isolation"]["tier2_os_isolation"],
        "no_environment_mutation": True,
    }


def render_text(report: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append("CTF-Solver preflight (read-only)")
    lines.append("=" * 40)
    lines.append(f"root:      {report['root']}")
    env = report["environment"]
    lines.append(f"os:        {env['os']}")
    lines.append(f"python:    {env['python_version']} ({env['python_executable']})")
    node = env.get("node_version") or {}
    lines.append(f"node:      {node.get('version') or 'missing'}")
    lines.append("")
    lines.append("ACP launcher:")
    acp = report["acp"]
    lines.append(f"  found:   {acp['found']}")
    if acp["launcher"]:
        lines.append(f"  command: {' '.join(acp['launcher'])}")
    lines.append(f"  version: {acp['version']}")
    lines.append("")
    lines.append("Skills:")
    skills = report["skills"]
    for name, info in sorted(skills["found"].items()):
        lines.append(
            f"  {name}: utf8={info['utf8']} bom={info['bom']} frontmatter={info['frontmatter']} "
            f"name={info['name']}"
        )
    if skills["problems"]:
        for problem in skills["problems"]:
            lines.append(f"  PROBLEM: {problem}")
    lines.append("")
    lines.append("Toolchain (available/missing; versions are probes, not installs):")
    for name, info in sorted(report["toolchain"].items()):
        version = f" — {info['version']}" if info.get("version") else ""
        lines.append(f"  {name:12s} {info['status']}{version}")
    lines.append("")
    lines.append("Python modules:")
    for name, info in sorted(report["python_modules"].items()):
        suffix = f" ({info['version']})" if info.get("version") else ""
        lines.append(f"  {name:20s} {'available' if info['available'] else 'missing'}{suffix}")
    lines.append("")
    gate = report["privacy_gate"]
    lines.append("Session-log privacy gate (P0):")
    lines.append(f"  project patch: {gate['project_patch_file']} present={gate['project_patch_present']} disables_delivery={gate['project_patch_disables_delivery']}")
    lines.append(f"  status:        {gate['status']}")
    lines.append(f"  outbound test: {gate['negative_outbound_delivery_test']}")
    lines.append("")
    lines.append("Isolation:")
    for key, value in report["isolation"].items():
        lines.append(f"  {key}: {value}")
    lines.append("")
    lines.append(f"No environment mutation performed. Summary: {json.dumps(report['summary'], ensure_ascii=False)}")
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="CTF-Solver read-only preflight")
    parser.add_argument("--root", default=".")
    parser.add_argument("--json", dest="json_path", default=None, help="Optional JSON report output path")
    parser.add_argument("--text", dest="text_path", default=None, help="Optional human-readable output path")
    parser.add_argument("--quiet", action="store_true", help="Do not print the human-readable report to stdout")
    args = parser.parse_args(argv)
    report = run_preflight(args.root)
    text = render_text(report)
    if args.json_path:
        Path(args.json_path).write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
    if args.text_path:
        Path(args.text_path).write_text(text, encoding="utf-8")
    if not args.quiet:
        sys.stdout.write(text)
    return 0 if report["skills"]["ok"] else 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main(sys.argv[1:]))
