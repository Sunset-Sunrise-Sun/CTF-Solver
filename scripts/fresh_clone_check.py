"""Fresh-clone verification: clone the branch, run the suite, build the wheel.

Round 2 Task §4.2 requires an independent check that a *clean clone* of the
current branch can run the full test suite and build/import the project wheel
with only the already-installed interpreter/pip. This script:

1. resolves the branch (default: the source checkout's current branch);
2. ``git clone --no-hardlinks --branch <branch> <repo> <temp>`` (the source is
   only read, never written);
3. optionally overlays the source working tree onto the clone (``--overlay-
   working-tree``) so an uncommitted candidate can be checked before the Lead
   commits; tracked modifications/deletions and untracked files are copied, and
   runtime/evidence directories are skipped;
4. runs ``python -m pytest tests -q -p no:cacheprovider`` inside the clone;
5. runs the clone's ``scripts/build_wheel.py`` (pip wheel with in-tree backend
   fallback) and records its JSON evidence;
6. writes ``round2-evidence/raw/fresh-clone-<utc>.json`` plus raw command logs
   and exits non-zero if pytest or the wheel build fails.

No network, no installation, no shell strings. Runtime data stays in the temp
clone and evidence goes to ``round2-evidence/raw/``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_EVIDENCE_DIR = REPO_ROOT / "round2-evidence" / "raw"
DEFAULT_TIMEOUT_S = 1800.0
MAX_CAPTURED_CHARS = 200_000

#: Paths never overlaid from the source working tree into the fresh clone.
SKIP_OVERLAY_PREFIXES = (
    ".git/",
    ".pytest_cache/",
    "__pycache__/",
    "dist/",
    "round1-evidence/",
    "round2-evidence/",
    "challenge-uploads/",
    "challenge-files/",
    "tasks/",
    "captures/",
    "exports/",
    ".ctf-solver-data/",
    "scratch/",
)


class FreshCloneError(RuntimeError):
    """Raised when the clone/test/build pipeline cannot continue."""

    def __init__(self, message: str, report: dict[str, Any]) -> None:
        super().__init__(message)
        self.report = report


def _utc_stamp() -> str:
    return time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())


def _tail(text: str) -> str:
    if len(text) <= MAX_CAPTURED_CHARS:
        return text
    return "…[truncated]…\n" + text[-MAX_CAPTURED_CHARS:]


def _run(
    command: list[str],
    *,
    cwd: Path,
    timeout: float,
    env: dict[str, str] | None = None,
) -> dict[str, Any]:
    started = time.time()
    try:
        completed = subprocess.run(
            command,
            cwd=str(cwd),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
            env=env,
        )
        returncode = int(completed.returncode)
        stdout = completed.stdout or ""
        stderr = completed.stderr or ""
    except (OSError, subprocess.SubprocessError) as exc:
        returncode = -1
        stdout = ""
        stderr = f"{type(exc).__name__}: {exc}"
    return {
        "command": [str(part) for part in command],
        "returncode": returncode,
        "seconds": round(time.time() - started, 3),
        "stdout": _tail(stdout),
        "stderr": _tail(stderr),
    }


def _git_text(repo: Path, *args: str) -> str | None:
    try:
        completed = subprocess.run(
            ["git", "-C", str(repo), *args],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):  # pragma: no cover - git absent
        return None
    if completed.returncode != 0:
        return None
    return completed.stdout.strip()


def current_branch(repo: Path) -> str:
    branch = _git_text(repo, "rev-parse", "--abbrev-ref", "HEAD")
    if not branch or branch == "HEAD":
        raise FreshCloneError(
            "cannot determine the current branch (detached HEAD?)", {"errors": ["no branch"]}
        )
    return branch


def _should_skip_overlay(relative: str) -> bool:
    normalized = relative.replace("\\", "/")
    return any(
        normalized == prefix.rstrip("/") or normalized.startswith(prefix)
        for prefix in SKIP_OVERLAY_PREFIXES
    )


def _copy_source_file(source_root: Path, clone_root: Path, relative: str) -> bool:
    source = source_root / Path(relative)
    destination = clone_root / Path(relative)
    if not source.is_file():
        return False
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    return True


def overlay_working_tree(source: Path, clone: Path) -> dict[str, Any]:
    """Overlay the source checkout's uncommitted state onto the clone."""

    overlay: dict[str, Any] = {
        "tracked_changed": 0,
        "tracked_deleted": 0,
        "untracked_copied": 0,
        "skipped": [],
        "errors": [],
    }
    status = _run(
        ["git", "-C", str(source), "status", "--porcelain=v1", "-z"],
        cwd=source,
        timeout=120,
    )
    if status["returncode"] != 0:
        overlay["errors"].append("git status failed: " + status["stderr"])
        return overlay
    raw = subprocess.run(
        ["git", "-C", str(source), "status", "--porcelain=v1", "-z"],
        capture_output=True,
        check=False,
    ).stdout
    tokens = raw.split(b"\0")
    index = 0
    while index < len(tokens):
        entry = tokens[index]
        index += 1
        if not entry:
            continue
        text = entry.decode("utf-8", "replace")
        code = text[:2]
        relative = text[3:] if len(text) > 3 else ""
        if not relative:
            continue
        if code[0] in ("R", "C") or code[1] in ("R", "C"):
            # rename/copy: binary -z format stores the old path in the next token
            if index < len(tokens):
                index += 1
        if _should_skip_overlay(relative):
            overlay["skipped"].append(relative)
            continue
        if code == "??":
            # untracked directory entries end with '/': copy the tree recursively
            if relative.endswith("/"):
                source_dir = source / Path(relative.rstrip("/"))
                copied = 0
                for candidate in sorted(source_dir.rglob("*")):
                    if not candidate.is_file():
                        continue
                    rel_candidate = candidate.relative_to(source).as_posix()
                    if _should_skip_overlay(rel_candidate):
                        continue
                    _copy_source_file(source, clone, rel_candidate)
                    copied += 1
                overlay["untracked_copied"] += copied
            else:
                if _copy_source_file(source, clone, relative):
                    overlay["untracked_copied"] += 1
            continue
        if "D" in code:
            target = clone / Path(relative)
            try:
                target.unlink()
                overlay["tracked_deleted"] += 1
            except FileNotFoundError:
                pass
            except OSError as exc:  # pragma: no cover - platform edge
                overlay["errors"].append(f"cannot delete {relative}: {exc}")
            continue
        if _copy_source_file(source, clone, relative):
            overlay["tracked_changed"] += 1
    return overlay


def _write_evidence(
    evidence_dir: Path,
    stamp: str,
    report: dict[str, Any],
    logs: list[tuple[str, str]],
) -> dict[str, str]:
    evidence_dir.mkdir(parents=True, exist_ok=True)
    artifact_paths: dict[str, str] = {}
    log_path = evidence_dir / f"fresh-clone-{stamp}.log"
    log_path.write_text("\n".join(text for _name, text in logs) + "\n", encoding="utf-8")
    artifact_paths["log"] = str(log_path)
    json_path = evidence_dir / f"fresh-clone-{stamp}.json"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    artifact_paths["json"] = str(json_path)
    return artifact_paths


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Fresh-clone test and wheel-build check")
    parser.add_argument("--repo", default=str(REPO_ROOT), help="source repository (read-only)")
    parser.add_argument("--branch", default=None, help="branch to clone (default: current)")
    parser.add_argument(
        "--evidence-dir", default=str(DEFAULT_EVIDENCE_DIR), help="evidence output directory"
    )
    parser.add_argument(
        "--overlay-working-tree",
        action="store_true",
        help=(
            "overlay the source uncommitted changes onto the clone so a candidate can be "
            "verified before the Lead commits (default: clone committed HEAD only)"
        ),
    )
    parser.add_argument("--keep-temp", action="store_true", help="keep the temporary clone")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_S)
    args = parser.parse_args(argv)

    repo = Path(args.repo).resolve()
    evidence_dir = Path(args.evidence_dir).resolve()
    branch = args.branch or current_branch(repo)
    stamp = _utc_stamp()
    temp_root = Path(tempfile.mkdtemp(prefix="ctf-solver-fresh-clone-"))
    clone = temp_root / "clone"
    logs: list[tuple[str, str]] = []
    report: dict[str, Any] = {
        "ok": False,
        "generated_at_utc": stamp,
        "repo": str(repo),
        "branch": branch,
        "overlay_working_tree": bool(args.overlay_working_tree),
        "source_head": _git_text(repo, "rev-parse", "HEAD"),
        "source_status_sha256": hashlib.sha256(
            (
                subprocess.run(
                    ["git", "-C", str(repo), "status", "--porcelain"],
                    capture_output=True,
                    check=False,
                ).stdout
                or b""
            )
        ).hexdigest(),
        "clone_dir": str(clone),
        "steps": [],
        "errors": [],
        "logs": [],
    }

    def log(name: str, text: str) -> None:
        logs.append((name, f"===== {name} =====\n{text}"))
        print(f"\n===== {name} =====\n{text}")

    try:
        clone_step = _run(
            [
                "git",
                "clone",
                "--no-hardlinks",
                "--branch",
                branch,
                str(repo),
                str(clone),
            ],
            cwd=temp_root,
            timeout=600,
        )
        report["steps"].append({k: clone_step[k] for k in ("command", "returncode", "seconds")})
        log("git clone", f"{' '.join(clone_step['command'])}\n{clone_step['stdout']}{clone_step['stderr']}")
        if clone_step["returncode"] != 0:
            raise FreshCloneError("git clone failed: " + clone_step["stderr"], report)
        report["clone_head"] = _git_text(clone, "rev-parse", "HEAD")
        report["clone_branch"] = _git_text(clone, "rev-parse", "--abbrev-ref", "HEAD")
        report["source_core_autocrlf"] = _git_text(repo, "config", "core.autocrlf")
        report["clone_core_autocrlf"] = _git_text(clone, "config", "core.autocrlf")

        if args.overlay_working_tree:
            overlay = overlay_working_tree(repo, clone)
            report["overlay"] = overlay
            log("working-tree overlay", json.dumps(overlay, indent=2))
            if overlay["errors"]:
                raise FreshCloneError(
                    "working-tree overlay failed: " + "; ".join(overlay["errors"]), report
                )

        env = dict(os.environ)
        env.pop("PYTHONPATH", None)
        env["PYTHONUTF8"] = "1"
        env["PYTHONDONTWRITEBYTECODE"] = "1"

        pytest_step = _run(
            [sys.executable, "-m", "pytest", "tests", "-q", "-p", "no:cacheprovider"],
            cwd=clone,
            timeout=args.timeout,
            env=env,
        )
        report["pytest"] = {
            "returncode": pytest_step["returncode"],
            "seconds": pytest_step["seconds"],
        }
        if pytest_step["returncode"] != 0:
            report["errors"].append(
                f"clone pytest failed with exit code {pytest_step['returncode']}"
            )
        report["steps"].append(
            {k: pytest_step[k] for k in ("command", "returncode", "seconds")}
        )
        log(
            "clone pytest",
            f"{' '.join(pytest_step['command'])} (cwd={clone})\n"
            f"exit={pytest_step['returncode']}\n"
            f"{pytest_step['stdout']}{pytest_step['stderr']}",
        )

        build_script = clone / "scripts" / "build_wheel.py"
        wheel_build_json = evidence_dir / f"fresh-clone-wheel-build-{stamp}.json"
        if not build_script.is_file():
            raise FreshCloneError(
                f"clone has no scripts/build_wheel.py (branch HEAD does not contain the "
                f"Round 2 packaging work; run with --overlay-working-tree or commit first): "
                f"{build_script}",
                report,
            )
        build_step = _run(
            [
                sys.executable,
                str(build_script),
                "--repo",
                str(clone),
                "--out",
                str(clone / "dist"),
                "--evidence-json",
                str(wheel_build_json),
            ],
            cwd=clone,
            timeout=args.timeout,
            env=env,
        )
        report["wheel_build"] = {
            "returncode": build_step["returncode"],
            "seconds": build_step["seconds"],
            "evidence_json": str(wheel_build_json),
        }
        if build_step["returncode"] != 0:
            report["errors"].append(
                f"clone wheel build failed with exit code {build_step['returncode']}"
            )
        report["steps"].append(
            {k: build_step[k] for k in ("command", "returncode", "seconds")}
        )
        log(
            "clone wheel build",
            f"{' '.join(build_step['command'])} (cwd={clone})\n"
            f"exit={build_step['returncode']}\n"
            f"{build_step['stdout']}{build_step['stderr']}",
        )

        report["ok"] = pytest_step["returncode"] == 0 and build_step["returncode"] == 0
    except FreshCloneError as exc:
        report = exc.report
        report["ok"] = False
        report["errors"].append(str(exc))
        log("ERROR", str(exc))
    finally:
        report["temp_clone_kept"] = bool(args.keep_temp)
        if not args.keep_temp:
            shutil.rmtree(temp_root, ignore_errors=True)
        artifacts = _write_evidence(evidence_dir, stamp, report, logs)
        report["logs"].append(artifacts["log"])
        report["evidence_json"] = artifacts["json"]
        # Write the final JSON once more so the artifact paths are inside it.
        Path(artifacts["json"]).write_text(
            json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )

    print("\n===== SUMMARY =====")
    print(json.dumps(
        {
            "ok": report["ok"],
            "branch": report["branch"],
            "clone_head": report.get("clone_head"),
            "overlay_working_tree": report["overlay_working_tree"],
            "source_core_autocrlf": report.get("source_core_autocrlf"),
            "clone_core_autocrlf": report.get("clone_core_autocrlf"),
            "pytest": report.get("pytest"),
            "wheel_build": report.get("wheel_build"),
            "errors": report["errors"],
            "evidence_json": report["evidence_json"],
            "log": report["logs"][0] if report["logs"] else None,
        },
        indent=2,
    ))
    return 0 if report["ok"] else 1


if __name__ == "__main__":  # pragma: no cover - script entry point
    sys.exit(main())
