"""Tests for the Round 2 in-tree wheel build and packaging scripts.

Covers docs/ROUND_2_INTERFACES.md §4.2 without installing anything:

- pyproject uses the in-tree PEP 517 backend (``wheelbuild``, no build requires);
- the backend builds a valid, deterministic ``ctf_solver-0.1.0-py3-none-any.whl``
  with every ``ctf_solver/**`` package, dist-info metadata and a correct RECORD;
- metadata/wheel/entry-point contents match authoritative ``[project]`` data;
- the wheel extracts and imports ``ctf_solver.evidence.store``,
  ``ctf_solver.manager.service`` and ``ctf_solver.intake``, and
  ``python -m ctf_solver version`` works with ``PYTHONPATH=<extract>``;
- ``scripts/build_wheel.py`` builds+verifies end-to-end (pip, with backend
  fallback) and fails non-zero on an unbuildable tree;
- ``scripts/fresh_clone_check.py`` helpers behave (branch + working-tree overlay).

All wheel builds target pytest ``tmp_path``; the repository is only read.
"""

from __future__ import annotations

import ast
import base64
import csv
import hashlib
import importlib.util
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tomllib
import zipfile
from pathlib import Path
from types import ModuleType

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
TOOLING_MODULE = REPO_ROOT / "tooling" / "wheelbuild.py"
BUILD_SCRIPT = REPO_ROOT / "scripts" / "build_wheel.py"
FRESH_CLONE_SCRIPT = REPO_ROOT / "scripts" / "fresh_clone_check.py"

PYPROJECT = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
PROJECT = PYPROJECT["project"]
DIST_NAME = PROJECT["name"].replace("-", "_")
WHEEL_FILENAME = f"{DIST_NAME}-{PROJECT['version']}-py3-none-any.whl"
DIST_INFO = f"{DIST_NAME}-{PROJECT['version']}.dist-info"

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


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def load_module(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None, path
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="session")
def backend() -> ModuleType:
    assert TOOLING_MODULE.is_file(), f"missing in-tree backend: {TOOLING_MODULE}"
    return load_module(TOOLING_MODULE, "verifier_round2_wheelbuild")


@pytest.fixture(scope="session")
def build_script() -> ModuleType:
    assert BUILD_SCRIPT.is_file(), f"missing build script: {BUILD_SCRIPT}"
    return load_module(BUILD_SCRIPT, "verifier_round2_build_wheel")


@pytest.fixture(scope="session")
def fresh_clone_script() -> ModuleType:
    assert FRESH_CLONE_SCRIPT.is_file(), f"missing fresh-clone script: {FRESH_CLONE_SCRIPT}"
    return load_module(FRESH_CLONE_SCRIPT, "verifier_round2_fresh_clone")


def frozen_project(tmp_path: Path) -> Path:
    """Copy the build inputs to a stable snapshot so concurrent author edits can't race."""

    destination = tmp_path / "frozen-project"
    destination.mkdir()
    shutil.copy2(REPO_ROOT / "pyproject.toml", destination / "pyproject.toml")
    readme = REPO_ROOT / "README.md"
    if readme.is_file():
        shutil.copy2(readme, destination / "README.md")
    shutil.copytree(
        REPO_ROOT / "ctf_solver",
        destination / "ctf_solver",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
    )
    tooling = destination / "tooling"
    tooling.mkdir()
    shutil.copy2(TOOLING_MODULE, tooling / "wheelbuild.py")
    return destination


def wheel_entries(wheel_path: Path) -> dict[str, bytes]:
    with zipfile.ZipFile(wheel_path) as archive:
        return {name: archive.read(name) for name in archive.namelist()}


def parse_record(record_text: str) -> list[list[str]]:
    return list(csv.reader(io.StringIO(record_text)))


def build_frozen(backend: ModuleType, frozen: Path, out: Path) -> Path:
    out.mkdir(parents=True, exist_ok=True)
    filename = backend.build_wheel_for_repo(frozen, out)
    return out / filename


def rewrite_zip(source: Path, destination: Path, replacements: dict[str, bytes]) -> None:
    with zipfile.ZipFile(source) as archive, zipfile.ZipFile(destination, "w") as target:
        for name in archive.namelist():
            payload = replacements.get(name, archive.read(name))
            target.writestr(name, payload)


def _source_package_files(root: Path) -> list[str]:
    package_root = root / "ctf_solver"
    files: list[str] = []
    for path in sorted(package_root.rglob("*")):
        if not path.is_file():
            continue
        if "__pycache__" in path.parts or path.suffix in (".pyc", ".pyo"):
            continue
        files.append(path.relative_to(root).as_posix())
    return files


# ---------------------------------------------------------------------------
# pyproject + backend contract
# ---------------------------------------------------------------------------


def test_pyproject_uses_in_tree_pep517_backend(backend: ModuleType) -> None:
    build_system = PYPROJECT.get("build-system")
    assert isinstance(build_system, dict)
    assert build_system.get("requires") == [], "no build requirements may be installed"
    assert build_system.get("build-backend") == "wheelbuild"
    assert build_system.get("backend-path") == ["tooling"]
    assert (REPO_ROOT / "tooling" / "wheelbuild.py").is_file()
    # [project] stays authoritative and dependency-free.
    assert PROJECT["name"] == "ctf-solver"
    assert PROJECT["version"] == "0.1.0"
    assert PROJECT["dependencies"] == []
    assert PROJECT["scripts"] == {"ctf-solver": "ctf_solver.cli:main"}
    assert backend.BACKEND_NAME == "wheelbuild"
    assert backend.repo_root_for_backend() == REPO_ROOT.resolve()
    assert backend.get_requires_for_build_wheel() == []
    assert backend.get_requires_for_build_sdist() == []


def test_backend_builds_named_deterministic_wheel(backend: ModuleType, tmp_path: Path) -> None:
    frozen = frozen_project(tmp_path)
    first = build_frozen(backend, frozen, tmp_path / "out-one")
    second = build_frozen(backend, frozen, tmp_path / "out-two")
    assert first.name == WHEEL_FILENAME
    assert second.name == WHEEL_FILENAME
    first_bytes = first.read_bytes()
    second_bytes = second.read_bytes()
    assert first_bytes == second_bytes, "wheel build must be deterministic"
    assert hashlib.sha256(first_bytes).hexdigest() == hashlib.sha256(second_bytes).hexdigest()
    # Rebuilding over an existing directory yields the same bytes too.
    again = build_frozen(backend, frozen, tmp_path / "out-one")
    assert again.read_bytes() == first_bytes


def test_prepare_metadata_hook_writes_dist_info(backend: ModuleType, tmp_path: Path) -> None:
    frozen = frozen_project(tmp_path)
    metadata_dir = tmp_path / "metadata"
    dist_info = backend.prepare_metadata_for_repo(frozen, metadata_dir)
    assert dist_info == DIST_INFO
    target = metadata_dir / dist_info
    for name in ("METADATA", "WHEEL", "entry_points.txt"):
        assert (target / name).is_file(), name
    wheel = build_frozen(backend, frozen, tmp_path / "out")
    entries = wheel_entries(wheel)
    assert entries[f"{DIST_INFO}/METADATA"] == (target / "METADATA").read_bytes()
    assert entries[f"{DIST_INFO}/WHEEL"] == (target / "WHEEL").read_bytes()


def test_wheel_contains_every_package_file_and_valid_record(
    backend: ModuleType, tmp_path: Path
) -> None:
    frozen = frozen_project(tmp_path)
    wheel = build_frozen(backend, frozen, tmp_path / "out")
    entries = wheel_entries(wheel)
    names = set(entries)
    assert len(names) == len(entries) == len(wheel_entries(wheel)), "duplicate archive members"

    for relative in _source_package_files(frozen):
        assert relative in names, f"source file missing from wheel: {relative}"
    for package in BASELINE_PACKAGES:
        assert f"{package.replace('.', '/')}/__init__.py" in names, package
    assert "ctf_solver/intake.py" in names

    for required in ("METADATA", "WHEEL", "RECORD", "entry_points.txt"):
        assert f"{DIST_INFO}/{required}" in names, required

    record_rows = parse_record(entries[f"{DIST_INFO}/RECORD"].decode("utf-8"))
    record_paths = {row[0] for row in record_rows}
    assert record_paths == names, "RECORD must cover exactly the archive members"
    for row in record_rows:
        assert len(row) == 3, row
        path, digest, size = row
        if path == f"{DIST_INFO}/RECORD":
            assert digest == "" and size == "", "RECORD row itself must be unhashed"
            continue
        payload = entries[path]
        expected = base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).rstrip(b"=").decode()
        assert digest == f"sha256={expected}", f"bad digest for {path}"
        assert "=" not in digest.split("=", 1)[1], "base64url hashes must not be padded"
        assert size == str(len(payload)), f"bad size for {path}"

    assert not any("__pycache__" in name or name.endswith((".pyc", ".pyo")) for name in names)
    with zipfile.ZipFile(wheel) as archive:
        for info in archive.infolist():
            assert info.date_time == (1980, 1, 1, 0, 0, 0), info.filename
            assert (info.external_attr >> 16) & 0o777 == 0o644, info.filename


def test_metadata_wheel_and_entry_points_content(backend: ModuleType, tmp_path: Path) -> None:
    frozen = frozen_project(tmp_path)
    wheel = build_frozen(backend, frozen, tmp_path / "out")
    entries = wheel_entries(wheel)

    metadata_text = entries[f"{DIST_INFO}/METADATA"].decode("utf-8")
    headers: dict[str, str] = {}
    for line in metadata_text.splitlines():
        if not line.strip():
            break
        key, value = line.split(":", 1)
        headers[key.strip().lower()] = value.strip()
    assert headers["metadata-version"] == "2.1"
    assert headers["name"] == "ctf-solver"
    assert headers["version"] == "0.1.0"
    assert headers["requires-python"] == ">=3.11"
    assert headers["summary"] == PROJECT["description"]
    assert headers["provides-extra"] == "dev"
    assert 'pytest>=8; extra == "dev"' in metadata_text
    assert headers["description-content-type"] == "text/markdown"
    assert "# CTF-Solver" in metadata_text, "README long description missing"

    wheel_meta = entries[f"{DIST_INFO}/WHEEL"].decode("utf-8")
    assert "Wheel-Version: 1.0" in wheel_meta
    assert "Root-Is-Purelib: true" in wheel_meta
    assert "Tag: py3-none-any" in wheel_meta

    entry_points = entries[f"{DIST_INFO}/entry_points.txt"].decode("utf-8")
    assert entry_points.startswith("[console_scripts]")
    assert "ctf-solver = ctf_solver.cli:main" in entry_points


def test_extracted_wheel_imports_and_version_cli(
    backend: ModuleType, build_script: ModuleType, tmp_path: Path
) -> None:
    frozen = frozen_project(tmp_path)
    wheel = build_frozen(backend, frozen, tmp_path / "out")

    report = build_script.verify_imports(wheel, expected_version=PROJECT["version"])
    assert report["ok"] is True
    assert report["imported_version"] == PROJECT["version"]
    assert report["version_command"]["returncode"] == 0
    assert "ctf-solver 0.1.0" in report["version_command"]["stdout_tail"]

    # Independent re-extraction, away from the repository, with only PYTHONPATH.
    extract_dir = tmp_path / "extract"
    extract_dir.mkdir()
    with zipfile.ZipFile(wheel) as archive:
        archive.extractall(extract_dir)
    outside = tmp_path / "outside"
    outside.mkdir()
    env = dict(os.environ)
    env["PYTHONPATH"] = str(extract_dir)
    env.pop("PYTHONHOME", None)
    import_run = subprocess.run(
        [
            sys.executable,
            "-c",
            "import ctf_solver.evidence.store, ctf_solver.manager.service, ctf_solver.intake;"
            "from ctf_solver import __version__; print(__version__)",
        ],
        cwd=outside,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert import_run.returncode == 0, import_run.stderr
    assert import_run.stdout.strip() == PROJECT["version"]
    version_run = subprocess.run(
        [sys.executable, "-m", "ctf_solver", "version"],
        cwd=outside,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert version_run.returncode == 0, version_run.stderr
    assert version_run.stdout.strip() == f"ctf-solver {PROJECT['version']}"


def test_verify_wheel_detects_tampered_record(
    backend: ModuleType, build_script: ModuleType, tmp_path: Path
) -> None:
    frozen = frozen_project(tmp_path)
    wheel = build_frozen(backend, frozen, tmp_path / "out")
    entries = wheel_entries(wheel)
    record_name = f"{DIST_INFO}/RECORD"
    rows = parse_record(entries[record_name].decode("utf-8"))
    # Tamper with the digest of one real member.
    target_row = next(row for row in rows if row[0] == "ctf_solver/__init__.py")
    tampered_rows = [
        [row[0], "sha256=AAAA", row[2]] if row is target_row else row for row in rows
    ]
    tampered_record = "\n".join(",".join(row) for row in tampered_rows) + "\n"
    tampered_wheel = tmp_path / wheel.name
    rewrite_zip(wheel, tampered_wheel, {record_name: tampered_record.encode()})
    with pytest.raises(build_script.WheelVerificationError):
        build_script.verify_wheel(tampered_wheel, repo_root=frozen)

    # A RECORD that forgets a member must also fail.
    missing_row = [row for row in rows if row[0] != "ctf_solver/__init__.py"]
    missing_record = "\n".join(",".join(row) for row in missing_row) + "\n"
    missing_dir = tmp_path / "missing"
    missing_dir.mkdir()
    missing_wheel = missing_dir / wheel.name
    rewrite_zip(wheel, missing_wheel, {record_name: missing_record.encode()})
    with pytest.raises(build_script.WheelVerificationError):
        build_script.verify_wheel(missing_wheel, repo_root=frozen)


def test_backend_direct_build_and_verify_path(
    build_script: ModuleType, tmp_path: Path
) -> None:
    frozen = frozen_project(tmp_path)
    report = build_script.build_and_verify(
        frozen, tmp_path / "dist", builder="backend"
    )
    assert report["ok"] is True
    assert report["builder"] == "backend"
    wheel = Path(report["wheel"]["path"])
    assert wheel.is_file()
    assert report["wheel"]["sha256"] == hashlib.sha256(wheel.read_bytes()).hexdigest()
    assert report["verification"]["structure"]["record_ok"] is True
    assert report["verification"]["imports"]["ok"] is True
    assert set(BASELINE_PACKAGES) <= set(report["verification"]["structure"]["packages"])


# ---------------------------------------------------------------------------
# scripts/build_wheel.py end-to-end
# ---------------------------------------------------------------------------


def test_build_script_end_to_end_on_repository(tmp_path: Path) -> None:
    out_dir = tmp_path / "dist"
    evidence_json = tmp_path / "wheel-build.json"
    completed = subprocess.run(
        [
            sys.executable,
            str(BUILD_SCRIPT),
            "--repo",
            str(REPO_ROOT),
            "--out",
            str(out_dir),
            "--evidence-json",
            str(evidence_json),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=900,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + "\n" + completed.stderr
    report = json.loads(evidence_json.read_text(encoding="utf-8"))
    assert report["ok"] is True
    assert report["builder"] in {"pip", "backend"}
    assert report["wheel"]["filename"] == WHEEL_FILENAME
    wheel_path = Path(report["wheel"]["path"])
    assert wheel_path.is_file()
    assert report["wheel"]["size"] == wheel_path.stat().st_size
    assert report["wheel"]["sha256"] == hashlib.sha256(wheel_path.read_bytes()).hexdigest()
    assert report["verification"]["structure"]["ok"] is True
    assert report["verification"]["structure"]["record_ok"] is True
    assert report["verification"]["imports"]["ok"] is True
    assert set(BASELINE_PACKAGES) <= set(report["verification"]["structure"]["packages"])
    assert sorted(out_dir.glob("*.whl")) == [wheel_path]


def test_build_script_fails_nonzero_on_unbuildable_repo(tmp_path: Path) -> None:
    empty_repo = tmp_path / "empty-repo"
    empty_repo.mkdir()
    evidence_json = tmp_path / "failure.json"
    completed = subprocess.run(
        [
            sys.executable,
            str(BUILD_SCRIPT),
            "--repo",
            str(empty_repo),
            "--out",
            str(tmp_path / "dist"),
            "--evidence-json",
            str(evidence_json),
        ],
        cwd=empty_repo,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    assert completed.returncode != 0
    assert evidence_json.is_file()
    report = json.loads(evidence_json.read_text(encoding="utf-8"))
    assert report["ok"] is False
    assert report["errors"]


# ---------------------------------------------------------------------------
# Package discovery against the live tree
# ---------------------------------------------------------------------------


def test_package_discovery_covers_current_tree(backend: ModuleType, tmp_path: Path) -> None:
    build_script = load_module(BUILD_SCRIPT, "verifier_round2_build_wheel_discovery")
    discovered = build_script.discover_packages(REPO_ROOT)
    assert set(BASELINE_PACKAGES) <= set(discovered)
    assert "ctf_solver.intake" not in discovered  # intake is a module, not a package
    filename = backend.build_wheel_for_repo(REPO_ROOT, tmp_path)
    wheel = tmp_path / filename
    entries = set(wheel_entries(wheel))
    for package in discovered:
        assert f"{package.replace('.', '/')}/__init__.py" in entries, package
    assert "ctf_solver/intake.py" in entries


def test_sdist_hook_is_deterministic_and_contains_sources(
    backend: ModuleType, tmp_path: Path
) -> None:
    import tarfile

    frozen = frozen_project(tmp_path)
    out_one = tmp_path / "sdist-one"
    out_two = tmp_path / "sdist-two"
    first_name = backend.build_sdist_for_repo(frozen, out_one)
    second_name = backend.build_sdist_for_repo(frozen, out_two)
    assert first_name == second_name == "ctf_solver-0.1.0.tar.gz"
    assert (out_one / first_name).read_bytes() == (out_two / second_name).read_bytes()
    with tarfile.open(out_one / first_name, "r:gz") as archive:
        names = archive.getnames()
    assert any(name.endswith("pyproject.toml") for name in names)
    assert any(name.endswith("ctf_solver/__init__.py") for name in names)
    assert any(name.endswith("tooling/wheelbuild.py") for name in names)


# ---------------------------------------------------------------------------
# No installation / no network / stdlib-only checks
# ---------------------------------------------------------------------------


def test_build_surfaces_are_stdlib_only_and_do_not_install() -> None:
    backend_source = TOOLING_MODULE.read_text(encoding="utf-8")
    build_source = BUILD_SCRIPT.read_text(encoding="utf-8")
    fresh_source = FRESH_CLONE_SCRIPT.read_text(encoding="utf-8")

    tree = ast.parse(backend_source)
    imported_roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            imported_roots.add(node.module.split(".")[0])
    non_stdlib = sorted(
        name for name in imported_roots if name not in sys.stdlib_module_names
    )
    assert non_stdlib == [], f"backend imports non-stdlib modules: {non_stdlib}"

    for source, label in ((build_source, "build_wheel.py"), (fresh_source, "fresh_clone_check.py")):
        assert not re.search(r"pip\s+install", source, re.IGNORECASE), label
        for forbidden in ("http://", "https://", "urllib.request", "socket.create_connection", "import requests"):
            assert forbidden not in source, f"{label} must not use {forbidden!r}"
    assert "--no-build-isolation" in build_source
    assert "--no-deps" in build_source
    assert "--no-cache-dir" in build_source
    assert "--no-hardlinks" in fresh_source


# ---------------------------------------------------------------------------
# scripts/fresh_clone_check.py helpers
# ---------------------------------------------------------------------------


def test_fresh_clone_helpers_and_overlay(tmp_path: Path, fresh_clone_script: ModuleType) -> None:
    git_env = dict(os.environ)
    git_env["GIT_AUTHOR_NAME"] = "verifier"
    git_env["GIT_AUTHOR_EMAIL"] = "verifier@example.invalid"
    git_env["GIT_COMMITTER_NAME"] = "verifier"
    git_env["GIT_COMMITTER_EMAIL"] = "verifier@example.invalid"
    source = tmp_path / "source-repo"
    source.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=source, check=True, env=git_env)
    (source / "tracked.txt").write_text("original\n", encoding="utf-8")
    subprocess.run(["git", "add", "tracked.txt"], cwd=source, check=True, env=git_env)
    subprocess.run(
        ["git", "commit", "-q", "-m", "initial"], cwd=source, check=True, env=git_env
    )
    assert fresh_clone_script.current_branch(source) not in (None, "HEAD")
    # Simulate a candidate: modify a tracked file, add an untracked file.
    (source / "tracked.txt").write_text("modified\n", encoding="utf-8")
    (source / "new_module.py").write_text("X = 1\n", encoding="utf-8")

    clone = tmp_path / "clone"
    clone.mkdir()
    shutil.copy2(source / "tracked.txt", clone / "tracked.txt")  # stale committed content
    overlay = fresh_clone_script.overlay_working_tree(source, clone)
    assert overlay["errors"] == []
    assert (clone / "tracked.txt").read_text(encoding="utf-8") == "modified\n"
    assert (clone / "new_module.py").read_text(encoding="utf-8") == "X = 1\n"
    assert overlay["untracked_copied"] >= 1
    # Runtime/evidence directories are never overlaid.
    assert fresh_clone_script._should_skip_overlay("round2-evidence/raw/x.json") is True
    assert fresh_clone_script._should_skip_overlay("ctf_solver/intake.py") is False
