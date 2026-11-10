"""Runtime configuration and on-disk layout.

All mutable runtime data lives outside Git under ``.ctf-solver-data`` and
``tasks/<task_id>`` (see docs/ARCHITECTURE.md section 12).
"""

from __future__ import annotations

import os
import shlex
from dataclasses import dataclass, field
from pathlib import Path

from .errors import ConfigError

DEFAULT_MAX_ACTIVE_WORKERS = 2
DEFAULT_REQUEST_TIMEOUT_S = 30.0
DEFAULT_STARTUP_TIMEOUT_S = 20.0
DEFAULT_STOP_TIMEOUT_S = 10.0
DEFAULT_MAX_OUTPUT_BYTES = 4 * 1024 * 1024


@dataclass(frozen=True)
class SolverPaths:
    root: Path
    data_dir: Path
    db_path: Path
    cas_dir: Path
    tasks_dir: Path
    exports_dir: Path
    captures_dir: Path
    sessions_dir: Path

    @classmethod
    def for_root(cls, root: str | os.PathLike[str]) -> "SolverPaths":
        base = Path(os.path.abspath(os.fspath(root)))
        data = base / ".ctf-solver-data"
        return cls(
            root=base,
            data_dir=data,
            db_path=data / "manager.sqlite",
            cas_dir=data / "cas" / "sha256",
            tasks_dir=base / "tasks",
            exports_dir=base / "exports",
            captures_dir=base / "captures",
            sessions_dir=data / "sessions",
        )

    def ensure(self) -> None:
        for directory in (
            self.data_dir,
            self.cas_dir,
            self.tasks_dir,
            self.exports_dir,
            self.captures_dir,
            self.sessions_dir,
        ):
            directory.mkdir(parents=True, exist_ok=True)

    def task_workspace(self, task_id: str) -> Path:
        return self.tasks_dir / task_id / "work"

    def task_dir(self, task_id: str) -> Path:
        return self.tasks_dir / task_id

    def task_evidence_dir(self, task_id: str) -> Path:
        return self.tasks_dir / task_id / "evidence"

    def writeup_path(self, task_id: str) -> Path:
        return self.tasks_dir / task_id / "writeup.md"

    def evidence_zip_path(self, task_id: str) -> Path:
        return self.tasks_dir / task_id / "evidence.zip"

    def manifest_path(self, task_id: str) -> Path:
        return self.tasks_dir / task_id / "evidence" / "manifest.sha256"


@dataclass
class SolverConfig:
    """Immutable-enough configuration for one Manager instance."""

    root: Path
    max_active_workers: int = DEFAULT_MAX_ACTIVE_WORKERS
    request_timeout_s: float = DEFAULT_REQUEST_TIMEOUT_S
    startup_timeout_s: float = DEFAULT_STARTUP_TIMEOUT_S
    stop_timeout_s: float = DEFAULT_STOP_TIMEOUT_S
    max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES
    allow_model_calls: bool = False  # Round 1: must stay False; see ADR-020.
    acp_command: list[str] | None = None
    acp_env: dict[str, str] = field(default_factory=dict)
    acp_cwd: str | None = None
    capture_mode: str = "desktop"  # "desktop" | "fake" (fake only for deterministic tests)
    extra: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.root = Path(os.path.abspath(os.fspath(self.root)))
        if self.max_active_workers < 1 or self.max_active_workers > 2:
            # The frozen product contract is "at most two active Workers".
            raise ConfigError(
                "max_active_workers must be 1 or 2; the approved product contract caps it at 2"
            )
        if self.allow_model_calls:
            raise ConfigError(
                "Round 1 does not authorize session/prompt or any model call (ADR-020)"
            )

    @property
    def paths(self) -> SolverPaths:
        return SolverPaths.for_root(self.root)

    def ensure_layout(self) -> SolverPaths:
        paths = self.paths
        paths.ensure()
        return paths


def discover_acp_command(env: dict[str, str] | None = None) -> list[str] | None:
    """Locate the audited ``dsh --profile acp`` launcher without assuming PATH.

    Order:
    1. ``CTF_SOLVER_ACP_COMMAND`` environment override (shell-style string).
    2. The locally installed DeepSeek Harness launcher path derived from
       ``LOCALAPPDATA``.
    3. ``dsh.cmd`` / ``dsh`` on PATH as a last resort.

    Returns ``None`` when nothing is found; callers must report the missing
    platform dependency instead of guessing.
    """

    environ = dict(os.environ if env is None else env)
    override = environ.get("CTF_SOLVER_ACP_COMMAND", "").strip()
    if override:
        return shlex.split(override, posix=False)

    local_appdata = environ.get("LOCALAPPDATA", "").strip()
    candidates: list[Path] = []
    if local_appdata:
        base = Path(local_appdata) / "Programs" / "DeepSeek Harness" / "resources" / "runtime" / "cli" / "bin"
        candidates.extend([base / "dsh.cmd", base / "dsh.exe", base / "dsh"])
    for candidate in candidates:
        if candidate.is_file():
            return [str(candidate)]
    import shutil

    for name in ("dsh.cmd", "dsh.exe", "dsh"):
        found = shutil.which(name)
        if found:
            return [found]
    return None


def build_acp_env(base: dict[str, str] | None = None, *, dsh_home: str | None = None) -> dict[str, str]:
    """Build a minimal environment for the managed ACP server process.

    The manager never inherits credentials or broad host environment state.
    A dedicated ``DSH_HOME`` is used by tests and by callers that need an
    isolated profile; production callers must only pass an already-audited
    home when they explicitly intend to isolate Harness state.
    """

    source = dict(os.environ if base is None else base)
    keep = (
        "SYSTEMROOT",
        "SYSTEMDRIVE",
        "WINDIR",
        "COMSPEC",
        "PATH",
        "TEMP",
        "TMP",
        "USERPROFILE",
        "HOMEDRIVE",
        "HOMEPATH",
        "APPDATA",
        "LOCALAPPDATA",
        "PROGRAMFILES",
        "PROGRAMFILES(X86)",
        "PROGRAMDATA",
        "NUMBER_OF_PROCESSORS",
        "PROCESSOR_ARCHITECTURE",
        "OS",
    )
    env = {key: source[key] for key in keep if key in source}
    if dsh_home:
        env["DSH_HOME"] = dsh_home
    env.setdefault("DSH_SHELL", "1")
    return env
