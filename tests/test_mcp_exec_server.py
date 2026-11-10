"""Tests for the Worker-scoped ``ctf-exec`` MCP server and loopback bridge."""

from __future__ import annotations

import json
import socket
import threading
import time
from typing import Any

import pytest

from ctf_solver.core.types import ExecutionResult, ExecutionStatus
from ctf_solver.mcp.bridge import ManagerIpcClient, parse_ipc_url
from ctf_solver.mcp.client import McpRemoteError, McpStdioClient
from tests.support.proc import PROJECT_ROOT, child_env

GOOD_TOKEN = "test-worker-token-123"


class FakeManagerIpc:
    """Minimal loopback IPC endpoint implementing the Manager-side contracts."""

    def __init__(self) -> None:
        self.requests: list[dict[str, Any]] = []
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(8)
        self._sock.settimeout(0.2)
        self.port = self._sock.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, name="fake-ipc", daemon=True)
        self._thread.start()

    @property
    def url(self) -> str:
        return f"tcp://127.0.0.1:{self.port}"

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn: socket.socket) -> None:
        with conn:
            buffer = bytearray()
            while b"\n" not in buffer:
                chunk = conn.recv(65536)
                if not chunk:
                    return
                buffer.extend(chunk)
            try:
                request = json.loads(bytes(buffer).split(b"\n", 1)[0].decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                conn.sendall(b'{"id":1,"error":{"message":"bad json","reason_code":"ipc_protocol_error"}}\n')
                return
            self.requests.append(request)
            response = self._respond(request)
            conn.sendall(json.dumps(response, ensure_ascii=False).encode("utf-8") + b"\n")

    def _respond(self, request: dict[str, Any]) -> dict[str, Any]:
        rpc_id = request.get("id", 1)
        if request.get("token") != GOOD_TOKEN:
            return {
                "id": rpc_id,
                "error": {"message": "invalid worker token", "reason_code": "denied"},
            }
        method = request.get("method")
        if method == "ping":
            return {"id": rpc_id, "result": {"ok": True}}
        if method == "worker_info":
            return {"id": rpc_id, "result": {"worker_id": "w-test", "task_id": "t-test"}}
        if method == "ctf_exec":
            params = request.get("params") or {}
            result = ExecutionResult(
                execution_id="exec-test-1",
                task_id=str(params.get("task_id", "")),
                worker_id=str(params.get("worker_id", "")),
                step_id=str(params.get("step_id", "")),
                tool_name=str(params.get("tool_name", "")),
                tool_version="1.0",
                argv=[str(item) for item in params.get("argv", [])],
                cwd=str(params.get("cwd", "")),
                status=ExecutionStatus.COMPLETED,
                started_at=1_700_000_000_000,
                ended_at=1_700_000_000_100,
                exit_code=0,
                stdout_sha256="a" * 64,
                stdout_preview="synthetic output",
                reason_code="",
                request=params,
            )
            return {"id": rpc_id, "result": result.to_dict()}
        return {"id": rpc_id, "error": {"message": f"unknown method {method}", "reason_code": "ipc_error"}}

    def close(self) -> None:
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass
        self._thread.join(timeout=5)


@pytest.fixture()
def fake_ipc():
    server = FakeManagerIpc()
    try:
        yield server
    finally:
        server.close()


def _exec_client(url: str, token: str = GOOD_TOKEN) -> McpStdioClient:
    env = child_env(
        CTF_SOLVER_IPC_URL=url,
        CTF_SOLVER_WORKER_TOKEN=token,
    )
    return McpStdioClient(
        [__import__("sys").executable, "-m", "ctf_solver.mcp.exec_server"],
        env=env,
        cwd=str(PROJECT_ROOT),
        request_timeout=30.0,
    )


def test_parse_ipc_url() -> None:
    assert parse_ipc_url("tcp://127.0.0.1:1234") == ("127.0.0.1", 1234)
    assert parse_ipc_url("localhost:9") == ("localhost", 9)
    with pytest.raises(ValueError):
        parse_ipc_url("nonsense")


def test_exec_server_exposes_one_typed_tool(fake_ipc: FakeManagerIpc) -> None:
    client = _exec_client(fake_ipc.url)
    client.start()
    try:
        client.initialize()
        tools = client.list_tools()
        assert [tool["name"] for tool in tools] == ["ctf_exec"]
        schema = tools[0]["inputSchema"]
        assert set(schema["required"]) == {"task_id", "worker_id", "step_id", "tool_name", "argv", "cwd"}
        # There is no shell/command-string tool argument: argv is an array and no
        # property named "shell"/"command" exists.
        assert "shell" not in schema["properties"]
        assert "command" not in schema["properties"]
        assert schema["properties"]["argv"]["type"] == "array"
    finally:
        client.close()


def test_exec_server_forwards_typed_request_and_returns_result(fake_ipc: FakeManagerIpc) -> None:
    client = _exec_client(fake_ipc.url)
    client.start()
    try:
        client.initialize()
        arguments = {
            "task_id": "t-test",
            "worker_id": "w-test",
            "step_id": "step-1",
            "tool_name": "internal.file_hash",
            "argv": ["challenge.txt"],
            "cwd": "D:/synthetic/tasks/t-test/work",
            "timeout_s": 10,
        }
        is_error, result = client.call_tool("ctf_exec", arguments)
        assert is_error is False, result
        assert result["status"] == "completed"
        assert result["argv"] == ["challenge.txt"]
        assert result["stdout_preview"] == "synthetic output"
        forwarded = [req for req in fake_ipc.requests if req.get("method") == "ctf_exec"]
        assert forwarded, fake_ipc.requests
        assert forwarded[-1]["params"] == arguments
        assert forwarded[-1]["token"] == GOOD_TOKEN
    finally:
        client.close()


def test_exec_server_fails_closed_on_bad_token(fake_ipc: FakeManagerIpc) -> None:
    client = _exec_client(fake_ipc.url, token="wrong-token")
    client.start()
    try:
        client.initialize()
        is_error, payload = client.call_tool(
            "ctf_exec",
            {
                "task_id": "t-test",
                "worker_id": "w-test",
                "step_id": "step-1",
                "tool_name": "internal.file_hash",
                "argv": ["x"],
                "cwd": "D:/synthetic/tasks/t-test/work",
            },
        )
        assert is_error is True
        assert payload["reason_code"] == "denied"
    finally:
        client.close()


def test_exec_server_identity_comes_from_env_not_arguments(fake_ipc: FakeManagerIpc) -> None:
    client = _exec_client(fake_ipc.url)
    client.start()
    try:
        client.initialize()
        # Strict schema validation rejects unknown identity fields instead of
        # silently ignoring them: identity can only come from the environment.
        with pytest.raises(McpRemoteError) as info:
            client.call_tool(
                "ctf_exec",
                {
                    "task_id": "t-test",
                    "worker_id": "w-test",
                    "step_id": "s",
                    "tool_name": "internal.file_hash",
                    "argv": ["x"],
                    "cwd": "D:/synthetic/tasks/t-test/work",
                    "worker_token": "attacker-supplied-token",
                },
            )
        assert info.value.code == -32602
        assert not [req for req in fake_ipc.requests if req.get("method") == "ctf_exec"]
        # A valid call still uses the env token and cannot be overridden.
        is_error, payload = client.call_tool(
            "ctf_exec",
            {
                "task_id": "t-test",
                "worker_id": "w-test",
                "step_id": "s",
                "tool_name": "internal.file_hash",
                "argv": ["x"],
                "cwd": "D:/synthetic/tasks/t-test/work",
            },
        )
        assert is_error is False, payload
        forwarded = [req for req in fake_ipc.requests if req.get("method") == "ctf_exec"][-1]
        assert forwarded["token"] == GOOD_TOKEN
    finally:
        client.close()


def test_exec_server_rejects_non_array_argv(fake_ipc: FakeManagerIpc) -> None:
    client = _exec_client(fake_ipc.url)
    client.start()
    try:
        client.initialize()
        with pytest.raises(McpRemoteError) as info:
            client.call_tool(
                "ctf_exec",
                {
                    "task_id": "t-test",
                    "worker_id": "w-test",
                    "step_id": "s",
                    "tool_name": "internal.file_hash",
                    "argv": "echo hello; rm -rf /",
                    "cwd": "D:/synthetic/tasks/t-test/work",
                },
            )
        assert info.value.code == -32602
        assert not [req for req in fake_ipc.requests if req.get("method") == "ctf_exec"]
    finally:
        client.close()


def test_bridge_ping_and_worker_info(fake_ipc: FakeManagerIpc) -> None:
    bridge = ManagerIpcClient(fake_ipc.url, GOOD_TOKEN, timeout_s=10)
    assert bridge.ping()["ok"] is True
    info = bridge.worker_info()
    assert info["worker_id"] == "w-test"


def test_bridge_reports_unavailable_manager() -> None:
    # Reserve a port then close it so the connection is refused.
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    bridge = ManagerIpcClient(f"tcp://127.0.0.1:{port}", GOOD_TOKEN, timeout_s=1)
    time.sleep(0.05)
    with pytest.raises(Exception) as info:
        bridge.ping()
    assert getattr(info.value, "reason_code", "") in {"ipc_unavailable", "ipc_protocol_error"}
