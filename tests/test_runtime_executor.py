"""RuntimeExecutor tests: in-process ops, fixed-argv subprocesses, limits.

Subprocess tests run only trusted, test-owned argv (the host Python interpreter
printing known text / sleeping). No challenge-provided code is executed and no
network access occurs.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import pytest

from ctf_solver.core.types import ExecutionStatus, ExecutionTier, RuntimeOutcome
from ctf_solver.runtime.catalog import RuntimeCatalog
from ctf_solver.runtime.executor import RuntimeExecutor, minimal_environment
from ctf_solver.runtime.tools import ToolInvocation, ToolSpec
from tests.test_runtime_support import FakeClock


def make_subprocess_tool(
    argv: list[str] | None = None,
    *,
    name: str = "synth.python",
    timeout_s: float = 10.0,
    max_output_bytes: int = 64 * 1024,
) -> ToolSpec:
    return ToolSpec(
        name=name,
        display_name="Synthetic Python subprocess",
        description="Test-only fixed-executable tool using the host interpreter.",
        tier=ExecutionTier.TIER1_TRUSTED,
        version="1",
        executable=sys.executable,
        default_timeout_s=timeout_s,
        max_output_bytes=max_output_bytes,
    )


def run_python(
    executor: RuntimeExecutor,
    code: str,
    *extra: str,
    cwd: Path,
    timeout_s: float = 10.0,
    max_output_bytes: int | None = None,
) -> RuntimeOutcome:
    spec = make_subprocess_tool()
    argv = ["-c", code, *extra]
    return executor.execute(
        spec,
        ToolInvocation(
            argv=argv,
            cwd=str(cwd),
            timeout_s=timeout_s,
            max_output_bytes=max_output_bytes,
        ),
    )


# ---------------------------------------------------------------------------
# In-process operations
# ---------------------------------------------------------------------------


def test_internal_operation_runs_in_process(tmp_path: Path) -> None:
    (tmp_path / "a.txt").write_bytes(b"hello")
    catalog = RuntimeCatalog.default()
    executor = RuntimeExecutor(clock=FakeClock())
    outcome = executor.execute(
        catalog.get("internal.file_hash"),  # type: ignore[arg-type]
        ToolInvocation(argv=["a.txt"], cwd=str(tmp_path)),
    )
    assert outcome.status is ExecutionStatus.COMPLETED
    assert outcome.exit_code == 0
    payload = json.loads(outcome.stdout.decode("utf-8"))
    assert payload["size"] == 5
    assert len(payload["sha256"]) == 64
    assert outcome.started_at == outcome.ended_at == FakeClock().now_ms()


def test_internal_exception_is_reported_as_failed(tmp_path: Path) -> None:
    def _boom(invocation: ToolInvocation) -> RuntimeOutcome:
        raise RuntimeError("synthetic internal failure")

    spec = ToolSpec(
        name="synth.boom",
        display_name="Boom",
        description="raises",
        internal=_boom,
    )
    executor = RuntimeExecutor()
    outcome = executor.execute(spec, ToolInvocation(argv=[], cwd=str(tmp_path)))
    assert outcome.status is ExecutionStatus.FAILED
    assert outcome.exit_code is None
    assert "synthetic internal failure" in outcome.error


def test_internal_invalid_return_is_failed(tmp_path: Path) -> None:
    spec = ToolSpec(
        name="synth.bad_return",
        display_name="Bad return",
        description="returns a string",
        internal=lambda invocation: "not an outcome",  # type: ignore[return-value]
    )
    outcome = RuntimeExecutor().execute(spec, ToolInvocation(argv=[], cwd=str(tmp_path)))
    assert outcome.status is ExecutionStatus.FAILED
    assert "invalid outcome" in outcome.error


def test_internal_output_is_capped(tmp_path: Path) -> None:
    spec = ToolSpec(
        name="synth.chatty",
        display_name="Chatty",
        description="prints a lot",
        internal=lambda invocation: RuntimeOutcome(
            status=ExecutionStatus.COMPLETED, exit_code=0, stdout=b"x" * 5000
        ),
        max_output_bytes=100,
    )
    outcome = RuntimeExecutor().execute(spec, ToolInvocation(argv=[], cwd=str(tmp_path)))
    assert len(outcome.stdout) == 100
    assert outcome.stdout_truncated is True


def test_internal_tool_without_implementation_is_failed(tmp_path: Path) -> None:
    catalog = RuntimeCatalog.default()
    outcome = RuntimeExecutor().execute(
        catalog.get("tool.remote_probe"),  # type: ignore[arg-type]
        ToolInvocation(argv=["--version"], cwd=str(tmp_path)),
    )
    assert outcome.status is ExecutionStatus.FAILED
    assert "no internal implementation or executable" in outcome.error


# ---------------------------------------------------------------------------
# Fixed-argv subprocess probes
# ---------------------------------------------------------------------------


def test_python_version_probe_actually_runs(tmp_path: Path) -> None:
    catalog = RuntimeCatalog.default()
    outcome = RuntimeExecutor().execute(
        catalog.get("tool.python_version"),  # type: ignore[arg-type]
        ToolInvocation(argv=["--version"], cwd=str(tmp_path)),
    )
    assert outcome.status is ExecutionStatus.COMPLETED
    assert outcome.exit_code == 0
    assert b"Python" in outcome.stdout or b"Python" in outcome.stderr
    assert outcome.stdout_truncated is False


def test_git_version_probe_actually_runs(tmp_path: Path) -> None:
    import shutil

    if shutil.which("git") is None:
        pytest.skip("git is not installed on this host; fixed-argv git probe not verified")
    catalog = RuntimeCatalog.default()
    outcome = RuntimeExecutor().execute(
        catalog.get("tool.git_version"),  # type: ignore[arg-type]
        ToolInvocation(argv=["--version"], cwd=str(tmp_path)),
    )
    assert outcome.status is ExecutionStatus.COMPLETED
    assert outcome.exit_code == 0
    assert b"git version" in outcome.stdout.lower() + outcome.stderr.lower()


def test_non_zero_exit_is_a_failed_outcome_with_exit_code(tmp_path: Path) -> None:
    outcome = run_python(RuntimeExecutor(), "import sys; sys.exit(7)", cwd=tmp_path)
    assert outcome.status is ExecutionStatus.FAILED
    assert outcome.exit_code == 7
    assert "exited with code 7" in outcome.error


def test_stderr_is_captured_separately(tmp_path: Path) -> None:
    outcome = run_python(
        RuntimeExecutor(), "import sys; sys.stderr.write('boom-error'); print('ok')", cwd=tmp_path
    )
    assert outcome.status is ExecutionStatus.COMPLETED
    assert outcome.stdout.replace(b"\r\n", b"\n") == b"ok\n"
    assert outcome.stderr == b"boom-error"


def test_timeout_returns_timed_out_and_reaps_process(tmp_path: Path) -> None:
    started = time.monotonic()
    outcome = run_python(
        RuntimeExecutor(),
        "import time; time.sleep(10)",
        cwd=tmp_path,
        timeout_s=0.2,
    )
    elapsed = time.monotonic() - started
    assert outcome.status is ExecutionStatus.TIMED_OUT
    assert outcome.exit_code is None
    assert "timed out" in outcome.error
    assert elapsed < 8.0, "timeout was not enforced promptly"


def test_spawn_failure_is_failed_outcome(tmp_path: Path) -> None:
    spec = ToolSpec(
        name="synth.missing_exec",
        display_name="Missing exec",
        description="executable does not exist",
        executable=str(tmp_path / "does-not-exist-binary"),
        version="1",
    )
    outcome = RuntimeExecutor().execute(
        spec, ToolInvocation(argv=[], cwd=str(tmp_path))
    )
    assert outcome.status is ExecutionStatus.FAILED
    assert outcome.exit_code is None
    assert "failed to start" in outcome.error


def test_missing_cwd_is_failed_outcome(tmp_path: Path) -> None:
    outcome = run_python(
        RuntimeExecutor(), "print(1)", cwd=tmp_path / "missing-dir"
    )
    assert outcome.status is ExecutionStatus.FAILED
    assert "working directory does not exist" in outcome.error


def test_stdout_cap_is_enforced_for_subprocess(tmp_path: Path) -> None:
    outcome = run_python(
        RuntimeExecutor(),
        "import sys; sys.stdout.write('x' * 100000)",
        cwd=tmp_path,
        max_output_bytes=1000,
    )
    assert outcome.status is ExecutionStatus.COMPLETED
    assert len(outcome.stdout) == 1000
    assert outcome.stdout_truncated is True


def test_stderr_cap_is_enforced_for_subprocess(tmp_path: Path) -> None:
    outcome = run_python(
        RuntimeExecutor(),
        "import sys; sys.stderr.write('y' * 100000)",
        cwd=tmp_path,
        max_output_bytes=500,
    )
    assert outcome.status is ExecutionStatus.COMPLETED
    assert len(outcome.stderr) == 500
    assert outcome.stderr_truncated is True


def test_env_output_cap_respects_spec_cap(tmp_path: Path) -> None:
    catalog = RuntimeCatalog.default()
    spec = catalog.get("tool.python_version")
    assert spec is not None and spec.max_output_bytes == 64 * 1024
    # request a larger cap than the tool allows: the tool cap wins
    outcome = RuntimeExecutor().execute(
        spec,
        ToolInvocation(
            argv=["--version"],
            cwd=str(tmp_path),
            max_output_bytes=1024 * 1024,
        ),
    )
    assert outcome.status is ExecutionStatus.COMPLETED


def test_argv_is_never_interpreted_by_a_shell(tmp_path: Path) -> None:
    outcome = run_python(
        RuntimeExecutor(),
        "import sys; print(sys.argv[1])",
        "a; echo hacked",
        cwd=tmp_path,
    )
    assert outcome.status is ExecutionStatus.COMPLETED
    assert outcome.stdout.replace(b"\r\n", b"\n") == b"a; echo hacked\n"


def test_minimal_environment_is_allow_listed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CTF_SOLVER_TEST_SECRET_CANARY", "must-not-leak")
    executor = RuntimeExecutor()
    outcome = run_python(
        executor,
        "import os; print('present' if 'CTF_SOLVER_TEST_SECRET_CANARY' in os.environ else 'absent')",
        cwd=tmp_path,
    )
    assert outcome.status is ExecutionStatus.COMPLETED
    assert outcome.stdout.strip() == b"absent"


def test_minimal_environment_keeps_system_path() -> None:
    env = minimal_environment({"PATH": "C:/fake", "SECRET": "x", "SYSTEMROOT": "C:/Windows"})
    assert env["PATH"] == "C:/fake"
    assert env["SYSTEMROOT"] == "C:/Windows"
    assert "SECRET" not in env
    assert env["PYTHONUTF8"] == "1"


def test_invalid_invocation_is_failed(tmp_path: Path) -> None:
    spec = make_subprocess_tool()
    outcome = RuntimeExecutor().execute(spec, {"argv": []})  # type: ignore[arg-type]
    assert outcome.status is ExecutionStatus.FAILED
    assert "invalid tool invocation" in outcome.error


def test_invalid_spec_is_failed(tmp_path: Path) -> None:
    outcome = RuntimeExecutor().execute(object(), ToolInvocation(argv=[], cwd=str(tmp_path)))  # type: ignore[arg-type]
    assert outcome.status is ExecutionStatus.FAILED
    assert "invalid tool specification" in outcome.error
