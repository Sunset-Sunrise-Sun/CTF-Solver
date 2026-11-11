"""Typed runtime executor: internal operations or fixed-argv subprocesses.

Security properties enforced here (see docs/INTERFACES.md section 5.1):

- subprocess calls receive an argv **array** and are started with
  ``shell=False``; no shell string is ever constructed;
- the child environment is a minimal allow-list (no inherited secrets, API
  keys or credentials) unless the caller injects a test environment;
- stdout/stderr are read through bounded capture threads so a chatty tool can
  never exhaust host memory; ``truncated`` flags are reported honestly;
- non-zero exit returns ``ExecutionStatus.FAILED`` with the exit code, timeout
  returns ``ExecutionStatus.TIMED_OUT``, and a spawn failure returns
  ``ExecutionStatus.FAILED`` with error text. Expected failures never raise.
"""

from __future__ import annotations

import os
import subprocess
import threading
from dataclasses import dataclass
from typing import Mapping

from ..core.protocols import Clock, SystemClock
from ..core.types import ExecutionStatus, RuntimeOutcome
from .tools import ToolInvocation, ToolSpec

__all__ = ["RuntimeExecutor", "DEFAULT_MAX_OUTPUT_BYTES"]

#: Hard ceiling for captured bytes per stream regardless of configuration.
DEFAULT_MAX_OUTPUT_BYTES = 4 * 1024 * 1024
MAX_TIMEOUT_S = 600.0
MIN_TIMEOUT_S = 0.05
CAPTURE_CHUNK = 64 * 1024

_ENV_KEYS = (
    "SYSTEMROOT",
    "SYSTEMDRIVE",
    "WINDIR",
    "COMSPEC",
    "PATH",
    "PATHEXT",
    "TEMP",
    "TMP",
    "USERPROFILE",
    "HOMEDRIVE",
    "HOMEPATH",
    "APPDATA",
    "LOCALAPPDATA",
    "PROGRAMDATA",
    "PROGRAMFILES",
    "PROGRAMFILES(X86)",
    "NUMBER_OF_PROCESSORS",
    "PROCESSOR_ARCHITECTURE",
    "OS",
)

_CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0


def minimal_environment(base: Mapping[str, str] | None = None) -> dict[str, str]:
    """Return a minimal child environment (allow-list, never a full inherit)."""

    source = dict(os.environ if base is None else base)
    env = {key: source[key] for key in _ENV_KEYS if key in source}
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"
    return env


class _BoundedStreamReader:
    """Drain one pipe into a bounded buffer from a daemon thread."""

    def __init__(self, stream: object, limit: int) -> None:
        self._stream = stream
        self._limit = max(1, int(limit))
        self._chunks: list[bytes] = []
        self._total = 0
        self.truncated = False
        self._thread = threading.Thread(
            target=self._run, name="ctf-exec-output-capture", daemon=True
        )

    def start(self) -> None:
        self._thread.start()

    def join(self, timeout: float) -> None:
        self._thread.join(timeout)

    @property
    def alive(self) -> bool:
        return self._thread.is_alive()

    def _run(self) -> None:
        stream = self._stream
        try:
            while True:
                chunk = stream.read(CAPTURE_CHUNK)  # type: ignore[attr-defined]
                if not chunk:
                    break
                if isinstance(chunk, str):  # defensive: text-mode pipe
                    chunk = chunk.encode("utf-8")
                remaining = self._limit - self._total
                if remaining > 0:
                    take = chunk[:remaining]
                    self._chunks.append(take)
                    self._total += len(take)
                    if len(chunk) > len(take):
                        self.truncated = True
                else:
                    self.truncated = True
        except (OSError, ValueError):
            pass
        finally:
            try:
                stream.close()  # type: ignore[attr-defined]
            except (OSError, ValueError):
                pass

    def data(self) -> bytes:
        return b"".join(self._chunks)


@dataclass
class _CaptureResult:
    stdout: bytes
    stderr: bytes
    stdout_truncated: bool
    stderr_truncated: bool


class RuntimeExecutor:
    """Execute one validated :class:`ToolSpec` invocation."""

    def __init__(
        self,
        clock: Clock | None = None,
        *,
        env: Mapping[str, str] | None = None,
        max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
    ) -> None:
        self.clock: Clock = clock or SystemClock()
        self._env = dict(env) if env is not None else minimal_environment()
        if max_output_bytes <= 0:
            raise ValueError("max_output_bytes must be positive")
        self.max_output_bytes = int(max_output_bytes)

    # -- public API ---------------------------------------------------------

    def execute(self, spec: ToolSpec, invocation: ToolInvocation) -> RuntimeOutcome:
        if not isinstance(spec, ToolSpec):
            return RuntimeOutcome(
                status=ExecutionStatus.FAILED,
                error=f"invalid tool specification: {type(spec).__name__}",
                started_at=self.clock.now_ms(),
                ended_at=self.clock.now_ms(),
            )
        if not isinstance(invocation, ToolInvocation):
            return RuntimeOutcome(
                status=ExecutionStatus.FAILED,
                error=f"invalid tool invocation: {type(invocation).__name__}",
                started_at=self.clock.now_ms(),
                ended_at=self.clock.now_ms(),
            )
        limit = self._output_limit(spec, invocation)
        if spec.internal is not None:
            return self._execute_internal(spec, invocation, limit)
        if spec.executable:
            return self._execute_subprocess(spec, invocation, limit)
        return RuntimeOutcome(
            status=ExecutionStatus.FAILED,
            error="tool has no internal implementation or executable configured",
            started_at=self.clock.now_ms(),
            ended_at=self.clock.now_ms(),
        )

    # -- helpers ------------------------------------------------------------

    def _output_limit(self, spec: ToolSpec, invocation: ToolInvocation) -> int:
        candidates = [self.max_output_bytes, spec.max_output_bytes]
        if invocation.max_output_bytes is not None:
            candidates.append(int(invocation.max_output_bytes))
        return max(1, min(candidates))

    @staticmethod
    def _timeout(invocation: ToolInvocation) -> float:
        try:
            value = float(invocation.timeout_s)
        except (TypeError, ValueError):
            value = 30.0
        return min(max(value, MIN_TIMEOUT_S), MAX_TIMEOUT_S)

    def _execute_internal(
        self, spec: ToolSpec, invocation: ToolInvocation, limit: int
    ) -> RuntimeOutcome:
        started_at = self.clock.now_ms()
        try:
            outcome = spec.internal(invocation)  # type: ignore[misc]
        except Exception as exc:  # expected failures are reported, never raised
            return RuntimeOutcome(
                status=ExecutionStatus.FAILED,
                error=f"{type(exc).__name__}: {exc}",
                started_at=started_at,
                ended_at=self.clock.now_ms(),
            )
        if not isinstance(outcome, RuntimeOutcome):
            return RuntimeOutcome(
                status=ExecutionStatus.FAILED,
                error=f"internal tool returned an invalid outcome: {type(outcome).__name__}",
                started_at=started_at,
                ended_at=self.clock.now_ms(),
            )
        stdout = outcome.stdout
        stderr = outcome.stderr
        if len(stdout) > limit:
            stdout = stdout[:limit]
            stdout_truncated = True
        else:
            stdout_truncated = bool(outcome.stdout_truncated)
        if len(stderr) > limit:
            stderr = stderr[:limit]
            stderr_truncated = True
        else:
            stderr_truncated = bool(outcome.stderr_truncated)
        return RuntimeOutcome(
            status=outcome.status,
            exit_code=outcome.exit_code,
            stdout=stdout,
            stderr=stderr,
            started_at=outcome.started_at or started_at,
            ended_at=outcome.ended_at or self.clock.now_ms(),
            stdout_truncated=stdout_truncated,
            stderr_truncated=stderr_truncated,
            error=outcome.error,
        )

    def _execute_subprocess(
        self, spec: ToolSpec, invocation: ToolInvocation, limit: int
    ) -> RuntimeOutcome:
        started_at = self.clock.now_ms()
        argv = invocation.argv
        if not isinstance(argv, list) or not all(isinstance(item, str) for item in argv):
            return RuntimeOutcome(
                status=ExecutionStatus.FAILED,
                error="argv must be an array of strings",
                started_at=started_at,
                ended_at=self.clock.now_ms(),
            )
        command = [str(spec.executable), *argv]
        cwd = str(invocation.cwd)
        if not os.path.isdir(cwd):
            return RuntimeOutcome(
                status=ExecutionStatus.FAILED,
                error=f"working directory does not exist: {cwd}",
                started_at=started_at,
                ended_at=self.clock.now_ms(),
            )
        timeout = self._timeout(invocation)
        try:
            process = subprocess.Popen(
                command,
                cwd=cwd,
                env=dict(self._env),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                bufsize=0,
                creationflags=_CREATE_NO_WINDOW,
            )
        except (OSError, subprocess.SubprocessError, ValueError) as exc:
            return RuntimeOutcome(
                status=ExecutionStatus.FAILED,
                error=f"failed to start tool executable {spec.executable!r}: {exc}",
                started_at=started_at,
                ended_at=self.clock.now_ms(),
            )
        assert process.stdout is not None and process.stderr is not None
        stdout_reader = _BoundedStreamReader(process.stdout, limit)
        stderr_reader = _BoundedStreamReader(process.stderr, limit)
        stdout_reader.start()
        stderr_reader.start()
        timed_out = False
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            self._terminate(process)
        finally:
            stdout_reader.join(timeout=5.0)
            stderr_reader.join(timeout=5.0)
            if stdout_reader.alive or stderr_reader.alive:  # pragma: no cover - defensive
                self._close_pipe(process.stdout)
                self._close_pipe(process.stderr)
                stdout_reader.join(timeout=1.0)
                stderr_reader.join(timeout=1.0)
        ended_at = self.clock.now_ms()
        capture = _CaptureResult(
            stdout=stdout_reader.data(),
            stderr=stderr_reader.data(),
            stdout_truncated=stdout_reader.truncated,
            stderr_truncated=stderr_reader.truncated,
        )
        if timed_out:
            return RuntimeOutcome(
                status=ExecutionStatus.TIMED_OUT,
                exit_code=None,
                stdout=capture.stdout,
                stderr=capture.stderr,
                started_at=started_at,
                ended_at=ended_at,
                stdout_truncated=capture.stdout_truncated,
                stderr_truncated=capture.stderr_truncated,
                error=f"tool timed out after {timeout:.1f}s",
            )
        return_code = process.returncode
        if return_code == 0:
            return RuntimeOutcome(
                status=ExecutionStatus.COMPLETED,
                exit_code=0,
                stdout=capture.stdout,
                stderr=capture.stderr,
                started_at=started_at,
                ended_at=ended_at,
                stdout_truncated=capture.stdout_truncated,
                stderr_truncated=capture.stderr_truncated,
            )
        return RuntimeOutcome(
            status=ExecutionStatus.FAILED,
            exit_code=return_code,
            stdout=capture.stdout,
            stderr=capture.stderr,
            started_at=started_at,
            ended_at=ended_at,
            stdout_truncated=capture.stdout_truncated,
            stderr_truncated=capture.stderr_truncated,
            error=f"tool exited with code {return_code}",
        )

    @staticmethod
    def _terminate(process: subprocess.Popen) -> None:
        try:
            process.kill()
        except OSError:  # pragma: no cover - process already gone
            pass
        try:
            process.wait(timeout=10.0)
        except subprocess.TimeoutExpired:  # pragma: no cover - defensive
            pass

    @staticmethod
    def _close_pipe(stream: object) -> None:
        try:
            stream.close()  # type: ignore[attr-defined]
        except (OSError, ValueError):  # pragma: no cover - defensive
            pass
