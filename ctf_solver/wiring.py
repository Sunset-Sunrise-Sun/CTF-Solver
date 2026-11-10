"""Production wiring for the Manager control server (Round 1 candidate).

Everything here composes the frozen module contracts. Tests can inject their own
fakes instead of using this module.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

from .core.config import SolverConfig, build_acp_env, discover_acp_command
from .core.errors import ConfigError
from .core.protocols import AcpClientFactory


def default_isolated_dsh_home(root: str | os.PathLike[str]) -> str:
    """Project-local isolated Harness home used by default in Round 1.

    Round 1 must not write into the live ``~/.dsh`` profile/session state. CLI and
    manager-server commands therefore default to this git-ignored project-local
    home. A caller that explicitly wants the live profile must pass an explicit
    ``--dsh-home``/config value after the owner authorizes that integration.
    """

    path = Path(os.path.abspath(os.fspath(root))) / ".ctf-solver-data" / "dsh-home"
    path.mkdir(parents=True, exist_ok=True)
    return str(path)


def _acp_launch_command(
    launcher: list[str], *, privacy_patch: str | os.PathLike[str] | None = None
) -> list[str]:
    """Build the audited ``dsh --profile acp`` launch command.

    Delegates to the audited launch helper (``ctf_solver.acp.launch``), which
    wraps a Windows ``.cmd`` launcher in ``cmd.exe /c``, always appends the
    ``--profile acp`` arguments and (Round 2 P0-3) the absolute project privacy
    ``--patch`` argument. Everything is an argv array (never a shell string).
    """

    try:
        from .acp.launch import build_acp_command
    except ImportError:  # pragma: no cover - only before the Round 2 module lands
        build_acp_command = None  # type: ignore[assignment]
    if build_acp_command is not None:
        return build_acp_command(launcher, privacy_patch=privacy_patch)
    if privacy_patch:
        raise ConfigError(
            "the ACP privacy patch requires the Round 2 launch helper; refusing to "
            "launch an unprotected Harness ACP profile"
        )
    if not launcher:
        raise ConfigError("empty ACP launcher command")
    executable = launcher[0]
    base = [str(item) for item in launcher[1:]]
    if executable.lower().endswith((".cmd", ".bat")):
        return [os.environ.get("COMSPEC", "cmd.exe"), "/c", executable, "--profile", "acp", *base]
    return [executable, "--profile", "acp", *base]


def default_acp_factory(config: SolverConfig) -> AcpClientFactory:
    def factory():
        from .acp.client import AcpClient

        command = config.acp_command
        if command is None:
            # Round 2 P0-3: the Manager-managed default ACP launch must compose
            # the project privacy patch. Missing/invalid patch fails closed.
            patch_path = config.privacy_patch_path
            if not patch_path.is_file():
                raise ConfigError(
                    f"the project Harness privacy patch is missing: {patch_path}; "
                    "refusing to launch an unprotected ACP Worker"
                )
            launcher = discover_acp_command()
            if launcher is None:
                raise ConfigError(
                    "the audited Harness ACP launcher (dsh) was not found; set "
                    "CTF_SOLVER_ACP_COMMAND or --acp-command to the exact launcher path"
                )
            command = _acp_launch_command(launcher, privacy_patch=str(patch_path))
        # An explicit acp_command is treated as a complete caller-supplied argv
        # (used by fake-ACP integration tests); the default real launch above is
        # the path that must and does include --profile acp --patch <abs path>.
        env = build_acp_env(base=os.environ, dsh_home=config.extra.get("dsh_home"))
        env.setdefault("PYTHONPATH", str(Path(__file__).resolve().parent.parent))
        env.setdefault("PYTHONUTF8", "1")
        return AcpClient(
            command,
            env=env,
            cwd=config.acp_cwd,
            startup_timeout_s=config.startup_timeout_s,
            request_timeout_s=config.request_timeout_s,
            allow_model_calls=False,
        )

    return factory


def build_security_service(config: SolverConfig) -> tuple[Any, Any, Any]:
    """Compose the human-confirmation approval/grant service for the local CLI.

    Deliberately does not start the ACP client, the IPC endpoint or a Worker:
    approval decisions must be made by a human at the local console, not by an
    agent-driven MCP process.
    """

    from .core.protocols import SystemClock
    from .evidence.store import EvidenceStore
    from .manager.approval_grant_service import ApprovalGrantService
    from .manager.store import ManagerStore

    paths = config.ensure_layout()
    store = ManagerStore(str(paths.db_path))
    evidence = EvidenceStore(str(paths.db_path), str(paths.cas_dir))
    service = ApprovalGrantService(store, evidence, SystemClock(), config)
    return service, store, evidence


def build_manager_service(
    config: SolverConfig,
    *,
    acp_factory: AcpClientFactory | None = None,
    store: Any = None,
    evidence: Any = None,
) -> Any:
    """Compose the real Manager service (SQLite, CAS, Broker, Runtime, delivery)."""

    from .delivery.deliverables import Deliverables
    from .delivery.screenshot import build_capturer
    from .evidence.store import EvidenceStore
    from .manager.service import ManagerService
    from .manager.store import ManagerStore
    from .policy.broker import Broker
    from .runtime.catalog import RuntimeCatalog
    from .runtime.executor import RuntimeExecutor
    from .runtime.pipeline import ExecutionPipeline

    paths = config.ensure_layout()
    manager_store = store or ManagerStore(str(paths.db_path))
    evidence_store = evidence or EvidenceStore(str(paths.db_path), str(paths.cas_dir))
    catalog = RuntimeCatalog.default()
    executor = RuntimeExecutor()
    broker = Broker(repository=manager_store, catalog=catalog)
    pipeline = ExecutionPipeline(
        repository=manager_store,
        evidence=evidence_store,
        broker=broker,
        executor=executor,
    )
    deliverables = Deliverables(evidence_store, paths)
    capturer = build_capturer(config.capture_mode)
    factory = acp_factory or default_acp_factory(config)
    return ManagerService(
        config=config,
        store=manager_store,
        acp_factory=factory,
        evidence=evidence_store,
        pipeline=pipeline,
        deliverables=deliverables,
        capturer=capturer,
    )
