"""Subprocess and timing helpers shared by tests."""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Callable, Iterable, Mapping

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SRC_ROOT = PROJECT_ROOT  # package lives at repository root (no installation step)


def child_env(**overrides: str) -> dict[str, str]:
    """Minimal child environment with the repository importable."""

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
        "NUMBER_OF_PROCESSORS",
        "PROCESSOR_ARCHITECTURE",
        "PYTHONIOENCODING",
    )
    env = {key: os.environ[key] for key in keep if key in os.environ}
    env["PYTHONPATH"] = os.pathsep.join(
        [str(PROJECT_ROOT)] + ([os.environ["PYTHONPATH"]] if os.environ.get("PYTHONPATH") else [])
    )
    env["PYTHONUTF8"] = "1"
    env.update({str(key): str(value) for key, value in overrides.items()})
    return env


def start_module(
    module: str,
    *args: str,
    env: Mapping[str, str] | None = None,
    cwd: str | os.PathLike[str] | None = None,
    stdin: int | None = subprocess.PIPE,
    stdout: int | None = subprocess.PIPE,
    stderr: int | None = subprocess.PIPE,
    text: bool = True,
) -> subprocess.Popen:
    command = [sys.executable, "-m", module, *map(str, args)]
    return subprocess.Popen(
        command,
        cwd=str(cwd or PROJECT_ROOT),
        env=dict(env or child_env()),
        stdin=stdin,
        stdout=stdout,
        stderr=stderr,
        text=text,
        encoding="utf-8" if text else None,
        errors="replace" if text else None,
    )


def run_module(
    module: str,
    *args: str,
    env: Mapping[str, str] | None = None,
    cwd: str | os.PathLike[str] | None = None,
    timeout: float = 120.0,
    input_text: str | None = None,
) -> subprocess.CompletedProcess:
    command = [sys.executable, "-m", module, *map(str, args)]
    return subprocess.run(
        command,
        cwd=str(cwd or PROJECT_ROOT),
        env=dict(env or child_env()),
        input=input_text,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
    )


def wait_until(
    predicate: Callable[[], bool],
    *,
    timeout: float = 15.0,
    interval: float = 0.02,
    message: str = "condition not met in time",
) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(interval)
    raise AssertionError(message)


def terminate(proc: subprocess.Popen | None, *, timeout: float = 10.0) -> None:
    """Terminate a child process and always reap it (no orphaned Workers)."""

    if proc is None:
        return
    if proc.poll() is None:
        try:
            proc.terminate()
        except OSError:
            pass
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            kill = getattr(signal, "SIGKILL", None)
            try:
                proc.kill() if kill is None else proc.send_signal(kill)
            except OSError:
                pass
            try:
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:  # pragma: no cover - hard failure
                raise
    for stream in (getattr(proc, "stdout", None), getattr(proc, "stderr", None), getattr(proc, "stdin", None)):
        try:
            if stream is not None:
                stream.close()
        except OSError:
            pass


def read_available(proc: subprocess.Popen, *, timeout: float = 10.0) -> tuple[str, str]:
    """Wait for process completion and return (stdout, stderr)."""

    out, err = proc.communicate(timeout=timeout)
    return out or "", err or ""


def assert_processes_reaped(procs: Iterable[subprocess.Popen]) -> None:
    """Fail if any Popen object still reports a running process.

    This is the reliable cross-platform check on Windows: ``os.kill(pid, 0)``
    can succeed for an already-reaped child because the PID may be reused or the
    CRT may map it differently, so prefer ``Popen.poll()``.
    """

    for proc in procs:
        if proc is None:
            continue
        if proc.poll() is None:
            raise AssertionError(f"child process {proc.pid} is still running")


def assert_no_process_leak(pids: Iterable[int]) -> None:
    """Legacy PID-based check; prefer :func:`assert_processes_reaped`.

    On Windows PID liveness is inherently racy, so this helper only reports a
    process when the OS still exposes it; tests should prefer Popen.poll().
    """

    for pid in pids:
        if pid <= 0:
            continue
        try:
            os.kill(pid, 0)
        except OSError:
            continue
        raise AssertionError(f"child process {pid} is still running")
