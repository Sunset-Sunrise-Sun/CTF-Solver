"""Tests for the minimal MCP stdio protocol (server framework + client)."""

from __future__ import annotations

import json
import subprocess
import sys

import pytest

from ctf_solver.mcp.client import McpClientTimeout, McpRemoteError, McpStdioClient
from tests.support.proc import PROJECT_ROOT, child_env, start_module, terminate


def _client(*args: str) -> McpStdioClient:
    return McpStdioClient(
        [sys.executable, "-m", "tests.support.mcp_test_servers", *args],
        env=child_env(),
        cwd=str(PROJECT_ROOT),
        request_timeout=20.0,
    )


def test_initialize_and_tool_listing() -> None:
    client = _client("echo")
    client.start()
    try:
        result = client.initialize()
        assert result["protocolVersion"]
        assert result["serverInfo"]["name"] == "mcp-echo"
        assert "capabilities" in result
        assert result.get("discovery", {}).get("serverInfo", {}).get("name") == "mcp-echo"
        tools = client.list_tools()
        names = sorted(tool["name"] for tool in tools)
        assert names == ["echo", "fail", "large", "slow"]
        for tool in tools:
            assert tool["description"]
            assert tool["inputSchema"]["type"] == "object"
    finally:
        client.close()


def test_tool_call_round_trip() -> None:
    client = _client("echo")
    client.start()
    try:
        client.initialize()
        is_error, payload = client.call_tool("echo", {"message": "hello"})
        assert is_error is False
        assert payload == {"echo": "hello", "count": 5}
    finally:
        client.close()


def test_tool_error_is_reported_not_crashing_server() -> None:
    client = _client("echo")
    client.start()
    try:
        client.initialize()
        is_error, payload = client.call_tool("fail")
        assert is_error is True
        assert payload["reason_code"] == "synthetic_failure"
        # Server still alive and responsive after a tool error.
        is_error2, payload2 = client.call_tool("echo", {"message": "still here"})
        assert is_error2 is False
        assert payload2["echo"] == "still here"
    finally:
        client.close()


def test_unknown_tool_raises_protocol_error() -> None:
    client = _client("echo")
    client.start()
    try:
        client.initialize()
        with pytest.raises(McpRemoteError) as info:
            client.call_tool("no_such_tool")
        assert info.value.code == -32602
    finally:
        client.close()


def test_missing_required_argument_is_protocol_error() -> None:
    client = _client("echo")
    client.start()
    try:
        client.initialize()
        with pytest.raises(McpRemoteError) as info:
            client.request("tools/call", {"name": "echo", "arguments": {}})
        assert info.value.code == -32602
    finally:
        client.close()


def test_large_payload_round_trip() -> None:
    client = _client("echo")
    client.start()
    try:
        client.initialize()
        is_error, payload = client.call_tool("large", {"size": 250_000})
        assert is_error is False
        assert len(payload["blob"]) == 250_000
    finally:
        client.close()


def test_concurrent_requests_are_correlated() -> None:
    import threading

    client = _client("echo")
    client.start()
    try:
        client.initialize()
        results: dict[int, dict] = {}
        errors: list[BaseException] = []

        def worker(index: int) -> None:
            try:
                is_error, payload = client.call_tool("echo", {"message": f"msg-{index}"})
                assert not is_error
                results[index] = payload
            except BaseException as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(index,)) for index in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)
        assert not errors
        assert len(results) == 8
        for index, payload in results.items():
            assert payload["echo"] == f"msg-{index}"
    finally:
        client.close()


def test_client_timeout_does_not_kill_server() -> None:
    client = _client("echo")
    client.start()
    try:
        client.initialize()
        with pytest.raises(McpClientTimeout):
            client.request("tools/call", {"name": "slow", "arguments": {"delay": 2.0}}, timeout=0.2)
        is_error, payload = client.call_tool("echo", {"message": "after timeout"})
        assert is_error is False
        assert payload["echo"] == "after timeout"
    finally:
        client.close()


def test_malformed_json_line_gets_parse_error_and_server_survives() -> None:
    proc = start_module("tests.support.mcp_test_servers", "echo")
    try:
        assert proc.stdin is not None and proc.stdout is not None
        proc.stdin.write("this is not json\n")
        proc.stdin.write(
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {"protocolVersion": "2025-06-18", "capabilities": {}},
                }
            )
            + "\n"
        )
        proc.stdin.flush()
        first = json.loads(proc.stdout.readline())
        assert first["error"]["code"] == -32700
        second = json.loads(proc.stdout.readline())
        assert second["id"] == 1
        assert second["result"]["protocolVersion"]
        proc.stdin.close()
        assert proc.wait(timeout=15) == 0
    finally:
        terminate(proc)


def test_multiple_messages_in_one_write() -> None:
    proc = start_module("tests.support.mcp_test_servers", "echo")
    try:
        assert proc.stdin is not None and proc.stdout is not None
        payload = (
            json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping"})
            + "\n"
            + json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
            + "\n"
        )
        proc.stdin.write(payload)
        proc.stdin.flush()
        responses = [json.loads(proc.stdout.readline()) for _ in range(2)]
        assert {response["id"] for response in responses} == {1, 2}
        proc.stdin.close()
        assert proc.wait(timeout=15) == 0
    finally:
        terminate(proc)


def test_stdio_eof_exits_cleanly() -> None:
    client = _client("echo")
    client.start()
    client.initialize()
    client.close()
    assert client.exit_code == 0


def test_server_rejects_missing_environment_identity() -> None:
    env = child_env()
    env.pop("CTF_SOLVER_IPC_URL", None)
    proc = subprocess.run(
        [sys.executable, "-m", "ctf_solver.mcp.exec_server"],
        cwd=str(PROJECT_ROOT),
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
    )
    assert proc.returncode != 0
    assert "CTF_SOLVER_IPC_URL" in (proc.stderr or "")
