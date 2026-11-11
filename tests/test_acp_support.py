"""Shared fixtures/helpers for the ACP client and transport tests.

This module deliberately contains **no test functions**; it is imported by
``tests/test_acp_*.py`` so the subprocess/fixture plumbing lives in one place.
Every spawned process is registered and cleaned up (reaped), because the Round 1
contract forbids orphan Workers.
"""

from __future__ import annotations

import io
import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable, Iterator

import pytest

from ctf_solver.acp.client import AcpClient
from ctf_solver.acp.transport import JsonRpcStdioTransport
from tests.support.proc import PROJECT_ROOT, child_env, start_module, terminate, wait_until

#: Diagnostics keys docs/INTERFACES.md section 3.2 requires the client to expose.
REQUIRED_DIAGNOSTICS_KEYS = frozenset(
    {
        "state",
        "pid",
        "command",
        "protocol_version",
        "pending_requests",
        "last_error",
        "stderr_tail",
        "started_at",
        "request_count",
        "response_count",
        "malformed_lines",
    }
)


def fake_server_command(*args: str) -> list[str]:
    return [sys.executable, "-m", "ctf_solver.acp.fake_server", *map(str, args)]


@pytest.fixture
def fake_processes() -> Iterator[Callable[..., tuple[subprocess.Popen, JsonRpcStdioTransport]]]:
    """Spawn fake-server processes wrapped in raw transports; reap all at exit."""

    processes: list[subprocess.Popen] = []
    transports: list[JsonRpcStdioTransport] = []

    def spawn(
        *args: str, stderr_path: str | Path | None = None
    ) -> tuple[subprocess.Popen, JsonRpcStdioTransport]:
        process = start_module(
            "ctf_solver.acp.fake_server",
            *args,
            env=child_env(),
            cwd=PROJECT_ROOT,
            text=False,
        )
        processes.append(process)
        transport = JsonRpcStdioTransport(
            process, stderr_path=str(stderr_path) if stderr_path is not None else None
        )
        transports.append(transport)
        return process, transport

    yield spawn

    for transport in transports:
        try:
            transport.shutdown(timeout_s=1.0)
        except Exception:  # pragma: no cover - best-effort teardown
            pass
    for process in processes:
        terminate(process)


@pytest.fixture
def make_client() -> Iterator[Callable[..., AcpClient]]:
    """Create :class:`AcpClient` instances against the fake ACP server."""

    clients: list[AcpClient] = []

    def factory(
        scenario: str = "normal",
        *,
        args: tuple[str, ...] = (),
        env: dict[str, str] | None = None,
        cwd: str | None = None,
        allow_model_calls: bool = False,
        startup_timeout_s: float = 15.0,
        request_timeout_s: float = 15.0,
        stderr_path: str | Path | None = None,
        command: list[str] | None = None,
    ) -> AcpClient:
        command = command or fake_server_command("--scenario", scenario, *args)
        client = AcpClient(
            command,
            env=env if env is not None else child_env(),
            cwd=cwd if cwd is not None else str(PROJECT_ROOT),
            startup_timeout_s=startup_timeout_s,
            request_timeout_s=request_timeout_s,
            stderr_path=str(stderr_path) if stderr_path is not None else None,
            allow_model_calls=allow_model_calls,
        )
        clients.append(client)
        return client

    yield factory

    for client in clients:
        try:
            client.stop()
        except Exception:  # pragma: no cover - best-effort teardown
            pass


def read_jsonl(path: str | Path) -> list[dict[str, Any]]:
    """Read a JSONL file, ignoring blank lines; returns [] when missing."""

    target = Path(path)
    if not target.exists():
        return []
    records: list[dict[str, Any]] = []
    for line in target.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            records.append(json.loads(line))
    return records


def wait_for_jsonl_event(
    path: str | Path,
    predicate: Callable[[dict[str, Any]], bool],
    *,
    timeout: float = 5.0,
) -> dict[str, Any]:
    """Wait until a JSONL record matching ``predicate`` exists and return it."""

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for record in read_jsonl(path):
            if predicate(record):
                return record
        time.sleep(0.02)
    raise AssertionError(f"no matching JSONL record in {path} within {timeout}s")


def decode_zstd_session_log(data: bytes) -> list[dict[str, Any]]:
    """Decode a (possibly multi-frame) zstd JSON-Lines session log."""

    try:
        import zstandard  # already-installed optional backend

        payload = zstandard.ZstdDecompressor().stream_reader(io.BytesIO(data)).read()
    except ImportError:  # pragma: no cover - Python >= 3.14 stdlib fallback
        from compression import zstd

        payload = zstd.decompress(data)
    return [
        json.loads(line)
        for line in payload.decode("utf-8").splitlines()
        if line.strip()
    ]


def count_zstd_frames(data: bytes) -> int:
    return data.count(b"\x28\xb5\x2f\xfd")


def assert_reaped(target: Any) -> None:
    """Assert a process (or an ``AcpClient`` owning one) has been reaped.

    ``tests.support.proc.assert_no_process_leak`` uses ``os.kill(pid, 0)``,
    which on Windows reports a *terminated* process as alive while the
    ``Popen`` handle is still open (and may even terminate it). These tests
    therefore check the authoritative ``Popen.poll()``/``wait()`` result: a
    reaped process has a non-``None`` return code and is not alive.
    """

    if isinstance(target, AcpClient):
        assert target.is_alive() is False
        assert target.diagnostics()["exit_code"] is not None
    else:
        assert target.poll() is not None


__all__ = [
    "PROJECT_ROOT",
    "REQUIRED_DIAGNOSTICS_KEYS",
    "fake_processes",
    "make_client",
    "fake_server_command",
    "read_jsonl",
    "wait_for_jsonl_event",
    "decode_zstd_session_log",
    "count_zstd_frames",
    "child_env",
    "start_module",
    "terminate",
    "wait_until",
]
