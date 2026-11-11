"""In-tree PEP 517 wheel backend (no setuptools/wheel installation required).

Round 2 Task §4.2 requires the project to be buildable in an environment that
has **no** packaging tools installed and where installing anything is forbidden.
This module is therefore a self-contained PEP 517 backend that:

- reads authoritative metadata from ``[project]`` in ``pyproject.toml``;
- discovers every package/module file under ``ctf_solver/`` from the source tree;
- writes a valid ``ctf_solver-<version>-py3-none-any.whl`` containing
  ``<dist>-<version>.dist-info/{METADATA,WHEEL,entry_points.txt,RECORD}`` and all
  ``ctf_solver/**`` files;
- produces a deterministic archive (fixed 1980-01-01 timestamps, sorted entries,
  fixed permissions, fixed deflate level) so identical inputs give identical
  wheel bytes;
- writes a PEP 427 ``RECORD`` with ``sha256`` urlsafe-base64 (no padding) and
  size entries, leaving only the ``RECORD`` row itself unhashed;
- exposes ``prepare_metadata_for_build_wheel`` and an optional deterministic
  ``build_sdist``.

The module uses only the Python standard library (``tomllib`` is available on
the project's Python >= 3.11 requirement). It never invokes a shell, never
installs anything and never touches the network.
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import io
import os
import re
import tarfile
import tomllib
import zipfile
from pathlib import Path
from typing import Any

__all__ = [
    "BACKEND_NAME",
    "BACKEND_VERSION",
    "WheelBuildError",
    "build_sdist",
    "build_wheel",
    "build_wheel_for_repo",
    "build_sdist_for_repo",
    "get_requires_for_build_sdist",
    "get_requires_for_build_wheel",
    "prepare_metadata_for_build_wheel",
    "prepare_metadata_for_repo",
    "repo_root_for_backend",
]

BACKEND_NAME = "wheelbuild"
BACKEND_VERSION = "1.0"
GENERATOR = f"ctf-solver-{BACKEND_NAME} {BACKEND_VERSION}"

PACKAGE_DIR = "ctf_solver"
ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
COMPRESS_LEVEL = 9
_IGNORED_DIR_NAMES = frozenset({"__pycache__"})
_IGNORED_SUFFIXES = frozenset({".pyc", ".pyo"})
_REQUIRED_PROJECT_KEYS = ("name", "version")


class WheelBuildError(RuntimeError):
    """Raised when the project metadata or source tree cannot form a valid wheel."""


# ---------------------------------------------------------------------------
# Project discovery / naming
# ---------------------------------------------------------------------------


def repo_root_for_backend() -> Path:
    """Return the project root this backend file belongs to (``<root>/tooling``)."""

    return Path(__file__).resolve().parents[1]


def _load_project(repo_root: str | os.PathLike[str] | None = None) -> tuple[Path, dict[str, Any]]:
    root = Path(repo_root).resolve() if repo_root is not None else repo_root_for_backend()
    pyproject_path = root / "pyproject.toml"
    if not pyproject_path.is_file():
        raise WheelBuildError(f"pyproject.toml not found at {pyproject_path}")
    try:
        data = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise WheelBuildError(f"cannot parse pyproject.toml: {exc}") from exc
    project = data.get("project")
    if not isinstance(project, dict):
        raise WheelBuildError("pyproject.toml has no [project] table")
    for key in _REQUIRED_PROJECT_KEYS:
        if not isinstance(project.get(key), str) or not project[key].strip():
            raise WheelBuildError(f"[project] {key} is required and must be a non-empty string")
    version = project["version"]
    if not re.fullmatch(r"[A-Za-z0-9_.+!-]+", version):
        raise WheelBuildError(f"[project] version is not wheel-safe: {version!r}")
    return root, data


def normalize_distribution_name(name: str) -> str:
    """PEP 503 style normalized distribution name used in wheel file names."""

    return re.sub(r"[-_.]+", "_", name).lower()


def _project_metadata(root: Path, data: dict[str, Any]) -> tuple[dict[str, Any], str]:
    project = data["project"]
    readme = ""
    readme_field = project.get("readme")
    readme_name = ""
    if isinstance(readme_field, str):
        readme_name = readme_field
    elif isinstance(readme_field, dict) and isinstance(readme_field.get("file"), str):
        readme_name = readme_field["file"]
    if readme_name:
        readme_path = root / readme_name
        if not readme_path.is_file():
            raise WheelBuildError(f"[project] readme file not found: {readme_path}")
        readme = readme_path.read_text(encoding="utf-8")
    return project, readme


def _dist_info_name(project: dict[str, Any]) -> str:
    return f"{normalize_distribution_name(project['name'])}-{project['version']}.dist-info"


def wheel_filename(project: dict[str, Any]) -> str:
    return f"{normalize_distribution_name(project['name'])}-{project['version']}-py3-none-any.whl"


# ---------------------------------------------------------------------------
# Content generation
# ---------------------------------------------------------------------------


def _metadata_headers(project: dict[str, Any]) -> list[str]:
    lines = [
        "Metadata-Version: 2.1",
        f"Name: {project['name']}",
        f"Version: {project['version']}",
    ]
    summary = project.get("description")
    if isinstance(summary, str) and summary.strip():
        lines.append(f"Summary: {' '.join(summary.split())}")
    requires_python = project.get("requires-python")
    if isinstance(requires_python, str) and requires_python.strip():
        lines.append(f"Requires-Python: {requires_python.strip()}")
    license_field = project.get("license")
    if isinstance(license_field, dict):
        license_text = license_field.get("text")
        if isinstance(license_text, str) and license_text.strip():
            lines.append(f"License: {' '.join(license_text.split())}")
    elif isinstance(license_field, str) and license_field.strip():
        lines.append(f"License: {' '.join(license_field.split())}")
    authors = project.get("authors")
    if isinstance(authors, list):
        names = [
            str(author.get("name")).strip()
            for author in authors
            if isinstance(author, dict) and str(author.get("name") or "").strip()
        ]
        if names:
            lines.append(f"Author: {', '.join(names)}")
    urls = project.get("urls")
    if isinstance(urls, dict):
        for label in sorted(str(key) for key in urls):
            lines.append(f"Project-URL: {label}, {urls[label]}")
    optional = project.get("optional-dependencies")
    if isinstance(optional, dict):
        for extra in sorted(str(name) for name in optional):
            requirements = optional[extra]
            if not isinstance(requirements, list):
                continue
            lines.append(f"Provides-Extra: {extra}")
            for requirement in requirements:
                lines.append(f'Requires-Dist: {requirement}; extra == "{extra}"')
    return lines


def _metadata_bytes(project: dict[str, Any], readme: str, readme_name: str) -> bytes:
    lines = _metadata_headers(project)
    if readme:
        content_type = "text/markdown" if readme_name.lower().endswith((".md", ".markdown")) else "text/plain"
        lines.append(f"Description-Content-Type: {content_type}")
        lines.append("")
        lines.append(readme)
        return ("\n".join(lines).rstrip("\n") + "\n").encode("utf-8")
    return ("\n".join(lines) + "\n").encode("utf-8")


def _wheel_bytes() -> bytes:
    return (
        "Wheel-Version: 1.0\n"
        f"Generator: {GENERATOR}\n"
        "Root-Is-Purelib: true\n"
        "Tag: py3-none-any\n"
    ).encode("utf-8")


def _entry_points_bytes(project: dict[str, Any]) -> bytes | None:
    scripts = project.get("scripts")
    if not isinstance(scripts, dict) or not scripts:
        return None
    lines = ["[console_scripts]"]
    for name in sorted(str(key) for key in scripts):
        lines.append(f"{name} = {scripts[name]}")
    return ("\n".join(lines) + "\n").encode("utf-8")


def discover_package_files(root: Path) -> list[tuple[str, bytes]]:
    """Return ``(wheel_arcname, bytes)`` for every file under ``ctf_solver/``."""

    package_root = root / PACKAGE_DIR
    if not package_root.is_dir():
        raise WheelBuildError(f"package directory not found: {package_root}")
    init_file = package_root / "__init__.py"
    if not init_file.is_file():
        raise WheelBuildError(f"missing {PACKAGE_DIR}/__init__.py")
    files: list[tuple[str, bytes]] = []
    for path in sorted(package_root.rglob("*")):
        if not path.is_file():
            continue
        relative_parts = path.relative_to(root).parts
        if any(part in _IGNORED_DIR_NAMES for part in relative_parts):
            continue
        if path.suffix in _IGNORED_SUFFIXES:
            continue
        arcname = "/".join(relative_parts)
        files.append((arcname, path.read_bytes()))
    files.sort(key=lambda item: item[0])
    return files


def _record_hash(data: bytes) -> tuple[str, int]:
    digest = hashlib.sha256(data).digest()
    encoded = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return f"sha256={encoded}", len(data)


def _record_bytes(entries: dict[str, bytes], dist_info: str) -> bytes:
    lines: list[str] = []
    for arcname in sorted(entries):
        value, size = _record_hash(entries[arcname])
        lines.append(f"{arcname},{value},{size}")
    lines.append(f"{dist_info}/RECORD,,")
    return ("\n".join(lines) + "\n").encode("utf-8")


def _collect_wheel_entries(root: Path) -> tuple[dict[str, Any], dict[str, bytes]]:
    data = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    project = data["project"]
    project, readme = _project_metadata(root, data)
    readme_name = ""
    readme_field = project.get("readme")
    if isinstance(readme_field, str):
        readme_name = readme_field
    elif isinstance(readme_field, dict) and isinstance(readme_field.get("file"), str):
        readme_name = readme_field["file"]
    dist_info = _dist_info_name(project)
    entries: dict[str, bytes] = {}
    for arcname, payload in discover_package_files(root):
        entries[arcname] = payload
    entries[f"{dist_info}/METADATA"] = _metadata_bytes(project, readme, readme_name)
    entries[f"{dist_info}/WHEEL"] = _wheel_bytes()
    entry_points = _entry_points_bytes(project)
    if entry_points is not None:
        entries[f"{dist_info}/entry_points.txt"] = entry_points
    entries[f"{dist_info}/RECORD"] = _record_bytes(entries, dist_info)
    return project, entries


def _write_wheel(wheel_path: Path, entries: dict[str, bytes]) -> None:
    wheel_path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = wheel_path.with_name(wheel_path.name + f".{os.getpid()}.tmp")
    try:
        with zipfile.ZipFile(
            temp_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=COMPRESS_LEVEL
        ) as archive:
            for arcname in sorted(entries):
                info = zipfile.ZipInfo(arcname, date_time=ZIP_TIMESTAMP)
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = 0o100644 << 16
                info.create_system = 3
                archive.writestr(info, entries[arcname])
        os.replace(temp_path, wheel_path)
    except BaseException:
        try:
            temp_path.unlink(missing_ok=True)
        except OSError:  # pragma: no cover - best-effort cleanup
            pass
        raise


# ---------------------------------------------------------------------------
# PEP 517 hooks
# ---------------------------------------------------------------------------


def build_wheel_for_repo(
    repo_root: str | os.PathLike[str],
    wheel_directory: str | os.PathLike[str],
) -> str:
    """Build a wheel from an explicit project root; returns the wheel file name."""

    root, _data = _load_project(repo_root)
    project, entries = _collect_wheel_entries(root)
    filename = wheel_filename(project)
    _write_wheel(Path(wheel_directory) / filename, entries)
    return filename


def prepare_metadata_for_repo(
    repo_root: str | os.PathLike[str],
    metadata_directory: str | os.PathLike[str],
) -> str:
    """Write ``<dist-info>`` metadata for an explicit project root."""

    root, data = _load_project(repo_root)
    project, readme = _project_metadata(root, data)
    readme_name = ""
    readme_field = project.get("readme")
    if isinstance(readme_field, str):
        readme_name = readme_field
    elif isinstance(readme_field, dict) and isinstance(readme_field.get("file"), str):
        readme_name = readme_field["file"]
    dist_info = _dist_info_name(project)
    target = Path(metadata_directory) / dist_info
    target.mkdir(parents=True, exist_ok=True)
    (target / "METADATA").write_bytes(_metadata_bytes(project, readme, readme_name))
    (target / "WHEEL").write_bytes(_wheel_bytes())
    entry_points = _entry_points_bytes(project)
    if entry_points is not None:
        (target / "entry_points.txt").write_bytes(entry_points)
    return dist_info


def get_requires_for_build_wheel(config_settings: dict[str, Any] | None = None) -> list[str]:
    """PEP 517: the backend has no build requirements (standard library only)."""

    return []


def get_requires_for_build_sdist(config_settings: dict[str, Any] | None = None) -> list[str]:
    return []


def prepare_metadata_for_build_wheel(
    metadata_directory: str,
    config_settings: dict[str, Any] | None = None,
) -> str:
    """Write ``<dist-info>`` metadata into ``metadata_directory`` and return its name."""

    return prepare_metadata_for_repo(repo_root_for_backend(), metadata_directory)


def build_wheel(
    wheel_directory: str,
    config_settings: dict[str, Any] | None = None,
    metadata_directory: str | None = None,
) -> str:
    """Build the pure-Python wheel and return its file name."""

    return build_wheel_for_repo(repo_root_for_backend(), wheel_directory)


def _sdist_files(root: Path) -> list[tuple[str, bytes]]:
    files: list[tuple[str, bytes]] = []
    candidates = [root / "pyproject.toml", root / "README.md"]
    for package_root in (root / "ctf_solver", root / "tooling", root / "scripts", root / ".dsh"):
        if package_root.is_dir():
            candidates.extend(sorted(package_root.rglob("*")))
    for path in candidates:
        if not path.is_file():
            continue
        relative_parts = path.relative_to(root).parts
        if any(part in _IGNORED_DIR_NAMES for part in relative_parts):
            continue
        if path.suffix in _IGNORED_SUFFIXES:
            continue
        files.append(("/".join(relative_parts), path.read_bytes()))
    files.sort(key=lambda item: item[0])
    return files


def build_sdist(sdist_directory: str, config_settings: dict[str, Any] | None = None) -> str:
    """Build a deterministic source distribution (PEP 517 optional hook)."""

    return build_sdist_for_repo(repo_root_for_backend(), sdist_directory)


def build_sdist_for_repo(
    repo_root: str | os.PathLike[str], sdist_directory: str | os.PathLike[str]
) -> str:
    """Build a deterministic sdist from an explicit project root."""

    root, data = _load_project(repo_root)
    project = data["project"]
    base = f"{normalize_distribution_name(project['name'])}-{project['version']}"
    filename = f"{base}.tar.gz"
    target = Path(sdist_directory) / filename
    target.parent.mkdir(parents=True, exist_ok=True)
    raw = io.BytesIO()
    with gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as gz:
        with tarfile.open(fileobj=gz, mode="w", format=tarfile.PAX_FORMAT) as archive:
            for relative, payload in _sdist_files(root):
                info = tarfile.TarInfo(f"{base}/{relative}")
                info.size = len(payload)
                info.mtime = 0
                info.mode = 0o644
                info.uid = 0
                info.gid = 0
                info.uname = ""
                info.gname = ""
                archive.addfile(info, io.BytesIO(payload))
    target.write_bytes(raw.getvalue())
    return filename
