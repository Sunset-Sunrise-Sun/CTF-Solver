"""Build and verify the in-tree wheel without installing packaging tools.

Round 2 Task §4.2:

1. build via ``python -m pip wheel . --no-deps --no-build-isolation -w dist``
   (pip is present; setuptools/wheel are not, so the project now uses the
   in-tree PEP 517 backend in ``tooling/wheelbuild.py``);
2. fall back to driving that backend directly if pip refuses the project;
3. verify the wheel structure (names, dist-info, RECORD hashes/sizes, package
   discovery, metadata/entry points);
4. extract the wheel, import ``ctf_solver.evidence.store``,
   ``ctf_solver.manager.service`` and ``ctf_solver.intake`` with
   ``PYTHONPATH=<extract>`` and run ``python -m ctf_solver version``;
5. write ``dist/wheel-build.json`` and exit non-zero on failure.

Only standard-library modules are used; no network, no installation.
"""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUT_DIR = REPO_ROOT / "dist"
DEFAULT_EVIDENCE_JSON = REPO_ROOT / "dist" / "wheel-build.json"

#: Packages that must be present in every wheel regardless of later additions.
BASELINE_PACKAGES = (
    "ctf_solver",
    "ctf_solver.core",
    "ctf_solver.storage",
    "ctf_solver.acp",
    "ctf_solver.evidence",
    "ctf_solver.policy",
    "ctf_solver.runtime",
    "ctf_solver.mcp",
    "ctf_solver.manager",
    "ctf_solver.delivery",
    "ctf_solver.preflight",
)

#: Modules the extracted wheel must import successfully (Round 2 Task §4.2).
REQUIRED_IMPORTS = (
    "ctf_solver.evidence.store",
    "ctf_solver.manager.service",
    "ctf_solver.intake",
)

MAX_CAPTURED_CHARS = 20000


class WheelVerificationError(RuntimeError):
    """Raised when a built wheel does not satisfy the packaging contract."""


class BuildStepFailed(RuntimeError):
    """Carries the partial JSON report when a build step fails."""

    def __init__(self, message: str, report: dict[str, Any]) -> None:
        super().__init__(message)
        self.report = report


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _tail(text: str, limit: int = MAX_CAPTURED_CHARS) -> str:
    if len(text) <= limit:
        return text
    return "…[truncated]…\n" + text[-limit:]


def _run(
    command: list[str],
    *,
    cwd: Path,
    timeout: float = 900.0,
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
        "stdout_tail": _tail(stdout),
        "stderr_tail": _tail(stderr),
    }


def _git_value(repo_root: Path, *args: str) -> str | None:
    try:
        completed = subprocess.run(
            ["git", "-C", str(repo_root), *args],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):  # pragma: no cover - git absent
        return None
    if completed.returncode != 0:
        return None
    return completed.stdout.strip()


def load_backend(repo_root: Path) -> Any:
    """Import ``<repo>/tooling/wheelbuild.py`` as a throw-away module."""

    backend_path = repo_root / "tooling" / "wheelbuild.py"
    if not backend_path.is_file():
        raise WheelVerificationError(f"in-tree build backend not found: {backend_path}")
    spec = importlib.util.spec_from_file_location(
        "ctf_solver_wheelbuild_for_build_script", backend_path
    )
    if spec is None or spec.loader is None:  # pragma: no cover - defensive
        raise WheelVerificationError(f"cannot load build backend: {backend_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def discover_packages(repo_root: Path) -> list[str]:
    """Return every dotted package name under ``ctf_solver/`` (sorted)."""

    root_package = repo_root / "ctf_solver"
    if not root_package.is_dir():
        raise WheelVerificationError(f"package directory not found: {root_package}")
    packages: list[str] = []
    for init_file in sorted(root_package.rglob("__init__.py")):
        if any(part == "__pycache__" for part in init_file.parts):
            continue
        relative = init_file.parent.relative_to(repo_root)
        packages.append(".".join(relative.parts))
    if "ctf_solver" not in packages:
        raise WheelVerificationError("ctf_solver/__init__.py not found")
    return packages


def expected_packages(repo_root: Path) -> list[str]:
    discovered = discover_packages(repo_root)
    missing = [name for name in BASELINE_PACKAGES if name not in discovered]
    if missing:
        raise WheelVerificationError(f"required packages missing from source tree: {missing}")
    return discovered


def _record_digest(data: bytes) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode("ascii")


def verify_wheel(wheel_path: Path, *, repo_root: Path) -> dict[str, Any]:
    """Validate wheel structure, metadata, package coverage and RECORD integrity."""

    if not wheel_path.is_file():
        raise WheelVerificationError(f"wheel not found: {wheel_path}")
    backend = load_backend(repo_root)
    root, _data = backend._load_project(repo_root)
    project = _data["project"]
    expected_filename = backend.wheel_filename(project)
    dist_info = backend._dist_info_name(project)
    if wheel_path.name != expected_filename:
        raise WheelVerificationError(
            f"unexpected wheel file name {wheel_path.name!r}; expected {expected_filename!r}"
        )
    problems: list[str] = []
    with zipfile.ZipFile(wheel_path, "r") as archive:
        names = archive.namelist()
        if len(names) != len(set(names)):
            problems.append("duplicate archive members")
        for name in names:
            if name.startswith("/") or "\\" in name:
                problems.append(f"unsafe archive member: {name!r}")
            parts = name.split("/")
            if ".." in parts:
                problems.append(f"path traversal archive member: {name!r}")
            if "__pycache__" in parts or name.endswith((".pyc", ".pyo")):
                problems.append(f"compiled/cache artifact in wheel: {name!r}")
        required_members = [
            f"{dist_info}/METADATA",
            f"{dist_info}/WHEEL",
            f"{dist_info}/RECORD",
            f"{dist_info}/entry_points.txt",
        ]
        for member in required_members:
            if member not in names:
                problems.append(f"missing dist-info member: {member}")
        for package in expected_packages(repo_root):
            init_member = package.replace(".", "/") + "/__init__.py"
            if init_member not in names:
                problems.append(f"package missing from wheel: {package}")
        for module in ("ctf_solver/intake.py", "ctf_solver/wiring.py", "ctf_solver/cli.py"):
            if module not in names:
                problems.append(f"module missing from wheel: {module}")

        metadata_text = archive.read(f"{dist_info}/METADATA").decode("utf-8")
        metadata_headers: dict[str, str] = {}
        for line in metadata_text.splitlines():
            if not line.strip():
                break
            if ":" in line:
                key, value = line.split(":", 1)
                metadata_headers[key.strip().lower()] = value.strip()
        if metadata_headers.get("name") != project["name"]:
            problems.append(f"METADATA Name mismatch: {metadata_headers.get('name')!r}")
        if metadata_headers.get("version") != project["version"]:
            problems.append(f"METADATA Version mismatch: {metadata_headers.get('version')!r}")
        if project.get("requires-python") and (
            metadata_headers.get("requires-python") != project["requires-python"]
        ):
            problems.append("METADATA Requires-Python mismatch")

        wheel_meta = archive.read(f"{dist_info}/WHEEL").decode("utf-8")
        for expected_line in ("Wheel-Version: 1.0", "Root-Is-Purelib: true", "Tag: py3-none-any"):
            if expected_line not in wheel_meta:
                problems.append(f"WHEEL missing {expected_line!r}")
        entry_points = archive.read(f"{dist_info}/entry_points.txt").decode("utf-8")
        for name, target in (project.get("scripts") or {}).items():
            if f"{name} = {target}" not in entry_points:
                problems.append(f"entry point missing: {name} = {target}")

        record_text = archive.read(f"{dist_info}/RECORD").decode("utf-8")
        rows = list(csv.reader(io.StringIO(record_text)))
        record_paths: set[str] = set()
        record_ok = True
        for row in rows:
            if len(row) != 3:
                problems.append(f"malformed RECORD row: {row!r}")
                record_ok = False
                continue
            record_path, digest, size = row
            record_paths.add(record_path)
            if record_path == f"{dist_info}/RECORD":
                if digest or size:
                    problems.append("RECORD row for RECORD itself must be unhashed")
                    record_ok = False
                continue
            if record_path not in names:
                problems.append(f"RECORD lists missing member: {record_path}")
                record_ok = False
                continue
            payload = archive.read(record_path)
            expected_digest = _record_digest(payload)
            if digest != f"sha256={expected_digest}":
                problems.append(f"RECORD digest mismatch for {record_path}")
                record_ok = False
            if size != str(len(payload)):
                problems.append(f"RECORD size mismatch for {record_path}")
                record_ok = False
        for name in names:
            if name == f"{dist_info}/RECORD":
                continue
            if name not in record_paths:
                problems.append(f"archive member not covered by RECORD: {name}")
                record_ok = False
    if problems:
        raise WheelVerificationError("; ".join(problems))
    return {
        "ok": True,
        "wheel_filename": wheel_path.name,
        "dist_info": dist_info,
        "members": len(names),
        "packages": expected_packages(repo_root),
        "record_entries": len(rows),
        "record_ok": record_ok,
        "metadata": {
            "name": metadata_headers.get("name"),
            "version": metadata_headers.get("version"),
            "requires_python": metadata_headers.get("requires-python"),
        },
    }


def verify_imports(wheel_path: Path, *, expected_version: str) -> dict[str, Any]:
    """Extract the wheel and import key modules with ``PYTHONPATH=<extract>``."""

    temp_root = Path(tempfile.mkdtemp(prefix="ctf-solver-wheel-verify-"))
    extract_dir = temp_root / "site"
    work_dir = temp_root / "outside-repo"
    extract_dir.mkdir(parents=True)
    work_dir.mkdir()
    try:
        with zipfile.ZipFile(wheel_path, "r") as archive:
            archive.extractall(extract_dir)
        env = dict(os.environ)
        env["PYTHONPATH"] = str(extract_dir)
        env["PYTHONUTF8"] = "1"
        env.pop("PYTHONHOME", None)
        import_code = (
            "import ctf_solver.evidence.store, ctf_solver.manager.service, ctf_solver.intake; "
            "from ctf_solver import __version__; print(__version__)"
        )
        import_run = _run(
            [sys.executable, "-c", import_code], cwd=work_dir, timeout=180.0, env=env
        )
        version_run = _run(
            [sys.executable, "-m", "ctf_solver", "version"],
            cwd=work_dir,
            timeout=120.0,
            env=env,
        )
        if import_run["returncode"] != 0:
            raise WheelVerificationError(
                "extracted wheel import failed: " + import_run["stderr_tail"]
            )
        if expected_version not in import_run["stdout_tail"]:
            raise WheelVerificationError(
                f"extracted wheel reports unexpected version: {import_run['stdout_tail']!r}"
            )
        if version_run["returncode"] != 0:
            raise WheelVerificationError(
                "`python -m ctf_solver version` failed: " + version_run["stderr_tail"]
            )
        if f"ctf-solver {expected_version}" not in version_run["stdout_tail"]:
            raise WheelVerificationError(
                f"unexpected `ctf_solver version` output: {version_run['stdout_tail']!r}"
            )
        imported_modules = import_run["stdout_tail"].strip().splitlines()
        return {
            "ok": True,
            "import_command": import_run,
            "version_command": version_run,
            "imported_version": imported_modules[0] if imported_modules else "",
            "required_imports": list(REQUIRED_IMPORTS),
        }
    finally:
        shutil.rmtree(temp_root, ignore_errors=True)


# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------


def _clean_output(out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    for candidate in out_dir.glob("*.whl"):
        try:
            candidate.unlink()
        except OSError:  # pragma: no cover - best effort
            pass


def _build_with_pip(repo_root: Path, out_dir: Path, timeout: float) -> dict[str, Any]:
    command = [
        sys.executable,
        "-m",
        "pip",
        "wheel",
        str(repo_root),
        "--no-deps",
        "--no-build-isolation",
        "--disable-pip-version-check",
        "--no-input",
        "--no-cache-dir",
        "-w",
        str(out_dir),
    ]
    result = _run(command, cwd=repo_root, timeout=timeout)
    result["builder"] = "pip"
    wheels = sorted(out_dir.glob("*.whl"))
    result["produced_wheel"] = str(wheels[-1]) if wheels else None
    return result


def _build_with_backend(repo_root: Path, out_dir: Path) -> dict[str, Any]:
    started = time.time()
    backend = load_backend(repo_root)
    filename = backend.build_wheel_for_repo(repo_root, out_dir)
    return {
        "command": ["<in-tree backend build_wheel_for_repo>", str(repo_root)],
        "builder": "backend",
        "returncode": 0,
        "seconds": round(time.time() - started, 3),
        "stdout_tail": filename,
        "stderr_tail": "",
        "produced_wheel": str(Path(out_dir) / filename),
    }


def build_and_verify(
    repo_root: Path,
    out_dir: Path,
    *,
    builder: str = "auto",
    timeout: float = 900.0,
) -> dict[str, Any]:
    """Build the wheel and return a JSON-friendly report (raises on failure)."""

    repo_root = Path(repo_root).resolve()
    out_dir = Path(out_dir).resolve()
    started = time.time()
    report: dict[str, Any] = {
        "ok": False,
        "generated_at_utc": _utc_now(),
        "repo_root": str(repo_root),
        "branch": _git_value(repo_root, "rev-parse", "--abbrev-ref", "HEAD"),
        "head": _git_value(repo_root, "rev-parse", "HEAD"),
        "python": sys.version,
        "python_executable": sys.executable,
        "pip_version": _pip_version(),
        "out_dir": str(out_dir),
        "commands": [],
        "errors": [],
    }
    try:
        _clean_output(out_dir)
        build_result: dict[str, Any] | None = None
        if builder in ("auto", "pip"):
            build_result = _build_with_pip(repo_root, out_dir, timeout)
            report["commands"].append(build_result)
            pip_ok = (
                build_result["returncode"] == 0
                and build_result.get("produced_wheel")
                and Path(build_result["produced_wheel"]).is_file()
            )
            if not pip_ok:
                if builder == "pip":
                    raise WheelVerificationError(
                        "pip wheel build failed: " + str(build_result.get("stderr_tail"))
                    )
                report["errors"].append(
                    "pip wheel build failed; falling back to the in-tree backend directly"
                )
                build_result = None
        if build_result is None:
            build_result = _build_with_backend(repo_root, out_dir)
            report["commands"].append(build_result)
        wheel_path = Path(str(build_result["produced_wheel"]))
        if not wheel_path.is_file():
            raise WheelVerificationError(f"build produced no wheel in {out_dir}")
        report["builder"] = build_result["builder"]
        payload = wheel_path.read_bytes()
        report["wheel"] = {
            "filename": wheel_path.name,
            "path": str(wheel_path),
            "size": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
        }
        structure = verify_wheel(wheel_path, repo_root=repo_root)
        report["verification"] = {"structure": structure}
        backend = load_backend(repo_root)
        _root, data = backend._load_project(repo_root)
        imports = verify_imports(wheel_path, expected_version=data["project"]["version"])
        report["verification"]["imports"] = imports
        report["verification"]["ok"] = True
        report["ok"] = True
    except BaseException as exc:  # noqa: BLE001 - report every failure as JSON
        report["errors"].append(f"{type(exc).__name__}: {exc}")
        report["duration_s"] = round(time.time() - started, 3)
        raise BuildStepFailed(str(exc), report) from exc
    report["duration_s"] = round(time.time() - started, 3)
    return report


def _pip_version() -> str | None:
    try:
        completed = subprocess.run(
            [sys.executable, "-m", "pip", "--version"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):  # pragma: no cover - pip absent
        return None
    return completed.stdout.strip() if completed.returncode == 0 else None


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build and verify the CTF-Solver wheel")
    parser.add_argument("--repo", default=str(REPO_ROOT), help="project root to build")
    parser.add_argument("--out", default=None, help="wheel output directory (default: <repo>/dist)")
    parser.add_argument(
        "--evidence-json",
        default=None,
        help="machine-readable report path (default: <repo>/round2-evidence/raw/wheel-build.json)",
    )
    parser.add_argument(
        "--builder",
        choices=["auto", "pip", "backend"],
        default="auto",
        help="auto = pip wheel with in-tree backend fallback",
    )
    parser.add_argument("--timeout", type=float, default=900.0)
    args = parser.parse_args(argv)

    repo_root = Path(args.repo).resolve()
    out_dir = Path(args.out).resolve() if args.out else repo_root / "dist"
    evidence_json = (
        Path(args.evidence_json).resolve()
        if args.evidence_json
        else repo_root / "round2-evidence" / "raw" / "wheel-build.json"
    )
    report: dict[str, Any] = {
        "ok": False,
        "generated_at_utc": _utc_now(),
        "repo_root": str(repo_root),
        "errors": [],
    }
    try:
        report = build_and_verify(
            repo_root, out_dir, builder=args.builder, timeout=args.timeout
        )
        returncode = 0
    except BuildStepFailed as exc:  # noqa: BLE001 - write evidence even on failure
        report = exc.report
        report["ok"] = False
        returncode = 1
        print(f"WHEEL BUILD FAILED: {exc}", file=sys.stderr)
    _write_json(evidence_json, report)
    print(json.dumps(report, indent=2, ensure_ascii=False))
    print(f"\nEVIDENCE_JSON={evidence_json}", file=sys.stderr if returncode else sys.stdout)
    return returncode


if __name__ == "__main__":  # pragma: no cover - script entry point
    sys.exit(main())
