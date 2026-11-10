"""Verify a built wheel against an exact Git commit (delivery provenance audit).

Checks:
- HEAD in the build checkout equals the expected implementation commit;
- every ``ctf_solver/**.py`` file in the wheel is byte-identical to the Git blob
  at that commit, and every tracked Python source file is present in the wheel;
- RECORD hashes/sizes match the wheel members;
- the wheel imports and ``python -m ctf_solver version`` succeeds.

The caller provides the commit and build metadata; this script never guesses a
commit and never accepts a wheel built from an unlisted working tree.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path


def _git(repo: Path, *args: str, binary: bool = False):
    completed = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"git {' '.join(args)} failed: {completed.stderr.decode('utf-8', 'replace')}"
        )
    return completed.stdout if binary else completed.stdout.decode("utf-8").strip()


def _record_hash(data: bytes) -> str:
    digest = hashlib.sha256(data).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel", required=True)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--branch", default="")
    parser.add_argument("--build-command", default="python scripts/build_wheel.py")
    parser.add_argument("--json-out", required=True)
    args = parser.parse_args(argv)

    repo = Path(args.repo).resolve()
    wheel = Path(args.wheel).resolve()
    expected = args.commit.strip().lower()
    head = _git(repo, "rev-parse", "HEAD").lower()
    problems: list[str] = []
    if head != expected:
        problems.append(f"build checkout HEAD {head} != expected commit {expected}")
    if _git(repo, "status", "--porcelain", "--untracked-files=all"):
        problems.append("build checkout working tree is not clean")

    tracked = [
        rel
        for rel in _git(repo, "ls-tree", "-r", "--name-only", head).splitlines()
        if rel.startswith("ctf_solver/") and rel.endswith(".py")
    ]
    tracked_set = set(tracked)
    wheel_data = wheel.read_bytes()
    wheel_sha = hashlib.sha256(wheel_data).hexdigest()

    source_checks = 0
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
        wheel_py = {name for name in names if name.startswith("ctf_solver/") and name.endswith(".py")}
        missing_in_wheel = sorted(tracked_set - wheel_py)
        extra_in_wheel = sorted(wheel_py - tracked_set)
        if missing_in_wheel:
            problems.append(f"tracked sources missing from wheel: {missing_in_wheel[:10]}")
        if extra_in_wheel:
            problems.append(f"unexpected sources in wheel: {extra_in_wheel[:10]}")
        for rel in tracked:
            if rel not in wheel_py:
                continue
            wheel_bytes = archive.read(rel)
            git_bytes = _git(repo, "show", f"{head}:{rel}", binary=True)
            if wheel_bytes != git_bytes:
                problems.append(f"source bytes differ from Git: {rel}")
            source_checks += 1

        record_names = [name for name in names if name.endswith(".dist-info/RECORD")]
        if len(record_names) != 1:
            problems.append(f"expected one RECORD, found {record_names}")
            record_ok = False
        else:
            record_ok = True
            record_lines = archive.read(record_names[0]).decode("utf-8").splitlines()
            recorded = {}
            for line in record_lines:
                if not line:
                    continue
                parts = line.split(",")
                if len(parts) != 3:
                    problems.append(f"malformed RECORD line: {line[:100]}")
                    record_ok = False
                    continue
                recorded[parts[0]] = (parts[1], parts[2])
            for name in names:
                if name.endswith("/RECORD"):
                    continue
                entry = recorded.get(name)
                if entry is None:
                    problems.append(f"missing RECORD entry: {name}")
                    record_ok = False
                    continue
                digest, size = entry
                data = archive.read(name)
                if size and int(size) != len(data):
                    problems.append(f"RECORD size mismatch: {name}")
                    record_ok = False
                if digest and digest != _record_hash(data):
                    problems.append(f"RECORD hash mismatch: {name}")
                    record_ok = False
            if set(recorded) != set(names):
                problems.append("RECORD entries do not exactly cover wheel members")
                record_ok = False

    python_version = sys.version
    extract_dir = Path(tempfile.mkdtemp(prefix="ctf-solver-wheel-provenance-"))
    import_ok = False
    version_ok = False
    version_stdout = ""
    try:
        with zipfile.ZipFile(wheel) as archive:
            archive.extractall(extract_dir)
        env = dict(os.environ)
        env["PYTHONPATH"] = str(extract_dir)
        env["PYTHONUTF8"] = "1"
        import_check = subprocess.run(
            [sys.executable, "-c", "import ctf_solver, ctf_solver.evidence.store, ctf_solver.manager.service, ctf_solver.intake; print(ctf_solver.__version__)"],
            capture_output=True,
            text=True,
            env=env,
            timeout=120,
        )
        import_ok = import_check.returncode == 0
        if not import_ok:
            problems.append("wheel import check failed: " + import_check.stderr[-300:])
        version_check = subprocess.run(
            [sys.executable, "-m", "ctf_solver", "version"],
            capture_output=True,
            text=True,
            env=env,
            timeout=120,
        )
        version_ok = version_check.returncode == 0
        version_stdout = version_check.stdout.strip()
        if not version_ok:
            problems.append("wheel CLI version check failed")
    finally:
        import shutil

        shutil.rmtree(extract_dir, ignore_errors=True)

    report = {
        "wheel": {
            "filename": wheel.name,
            "path": str(wheel),
            "size": len(wheel_data),
            "sha256": wheel_sha,
        },
        "build": {
            "repo": str(repo),
            "head": head,
            "expected_commit": expected,
            "branch": args.branch or _git(repo, "branch", "--show-current"),
            "python_version": python_version,
            "build_command": args.build_command,
            "clean_checkout": head == expected
            and not _git(repo, "status", "--porcelain", "--untracked-files=all"),
        },
        "source": {
            "tracked_python_sources": len(tracked),
            "wheel_python_sources": len(wheel_py),
            "sources_byte_identical": source_checks == len(tracked) and not missing_in_wheel and not extra_in_wheel,
        },
        "record": {"ok": record_ok},
        "imports": {"ok": import_ok},
        "version": {"ok": version_ok, "stdout": version_stdout},
        "commit_reachable_from_final_bundle": None,  # caller/audit fills after bundle creation
        "problems": problems,
        "ok": not problems,
    }
    Path(args.json_out).write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"ok": report["ok"], "problems": problems}, ensure_ascii=False, indent=2))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
