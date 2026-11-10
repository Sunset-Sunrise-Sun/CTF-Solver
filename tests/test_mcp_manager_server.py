"""Tests for the Manager control MCP surface (tool schemas and dispatch)."""

from __future__ import annotations

import sys

from ctf_solver.mcp.client import McpRemoteError, McpStdioClient
from tests.support.proc import PROJECT_ROOT, child_env


def _manager_client() -> McpStdioClient:
    return McpStdioClient(
        [sys.executable, "-m", "tests.support.mcp_test_servers", "manager"],
        env=child_env(),
        cwd=str(PROJECT_ROOT),
        request_timeout=30.0,
    )


EXPECTED_TOOLS = {
    "ctf_task_create",
    "ctf_task_list",
    "ctf_task_status",
    "ctf_task_continue",
    "ctf_task_pause",
    "ctf_task_cancel",
    "ctf_approval_request",
    "ctf_approval_list",
    "ctf_grant_revoke",
    "ctf_grant_list",
    "ctf_flag_candidate",
    "ctf_screenshot_capture",
    "ctf_session_ingest",
    "ctf_events_export",
    "ctf_writeup_build",
    "ctf_evidence_zip",
    "ctf_runtime_status",
}

FORBIDDEN_MODEL_ESCALATION_TOOLS = {"ctf_approval_decide", "ctf_grant_create"}


def test_manager_tool_surface_and_schemas() -> None:
    client = _manager_client()
    client.start()
    try:
        client.initialize()
        tools = client.list_tools()
        names = {tool["name"] for tool in tools}
        assert names == EXPECTED_TOOLS
        assert not (names & FORBIDDEN_MODEL_ESCALATION_TOOLS)
        for tool in tools:
            assert tool["description"]
            schema = tool["inputSchema"]
            assert schema["type"] == "object"
            assert "properties" in schema
            assert "required" in schema
    finally:
        client.close()


def test_task_lifecycle_tools() -> None:
    client = _manager_client()
    client.start()
    try:
        client.initialize()
        is_error, created = client.call_tool(
            "ctf_task_create",
            {
                "title": "Synthetic web challenge",
                "category": "web",
                "conversation_id": "conv-1",
                "source": "synthetic-local",
            },
        )
        assert is_error is False, created
        assert created["category"] == "misc"  # stub returns its fixed Task
        status = client.call_tool("ctf_task_status", {"task_id": created["task_id"]})
        assert status[0] is False
        assert status[1]["task"]["task_id"] == created["task_id"]
        listed = client.call_tool("ctf_task_list", {})
        assert listed[0] is False
        assert isinstance(listed[1], list) and listed[1]
        continued = client.call_tool("ctf_task_continue", {"task_id": created["task_id"], "message": "继续"})
        assert continued[0] is False
        assert continued[1]["model_call_suppressed"] is True
        paused = client.call_tool("ctf_task_pause", {"task_id": created["task_id"]})
        assert paused[0] is False
        cancelled = client.call_tool("ctf_task_cancel", {"task_id": created["task_id"]})
        assert cancelled[0] is False
        assert cancelled[1]["status"] == "cancel_requested"
    finally:
        client.close()


def test_approval_grant_and_flag_tools() -> None:
    client = _manager_client()
    client.start()
    try:
        client.initialize()
        _, task = client.call_tool(
            "ctf_task_create",
            {"title": "x", "category": "misc", "conversation_id": "conv-1"},
        )
        task_id = task["task_id"]
        is_error, approval = client.call_tool(
            "ctf_approval_request",
            {
                "task_id": task_id,
                "action_kind": "remote_target",
                "details": {"target": {"host": "127.0.0.1", "port": 31337}, "profile": "synthetic-local"},
                "ttl_s": 60,
            },
        )
        assert is_error is False
        assert approval["status"] == "pending"
        assert client.call_tool("ctf_approval_list", {})[1]
        # There is no MCP tool that can approve on the model's behalf.
        for forbidden in FORBIDDEN_MODEL_ESCALATION_TOOLS:
            assert forbidden not in EXPECTED_TOOLS
            try:
                client.call_tool(forbidden, {"approval_id": approval["approval_id"]})
            except McpRemoteError as exc:
                assert exc.code == -32602
            else:  # pragma: no cover
                raise AssertionError(f"forbidden escalation tool {forbidden} is exposed")
        # Grants cannot be created through MCP either; list/revoke remain.
        assert client.call_tool("ctf_grant_list", {})[0] is False
        is_error, missing = client.call_tool("ctf_grant_revoke", {"grant_id": "grant-does-not-exist"})
        assert is_error is True
        flag = client.call_tool(
            "ctf_flag_candidate",
            {"task_id": task_id, "flag": "flag{synthetic}", "source": "local-reproduction"},
        )
        assert flag[0] is False
        assert flag[1]["flag_state"] == "candidate"
        # No submission tool exists on the control surface at all.
        assert "ctf_flag_submit" not in EXPECTED_TOOLS
    finally:
        client.close()


def test_evidence_and_delivery_tools_delegate() -> None:
    client = _manager_client()
    client.start()
    try:
        client.initialize()
        _, task = client.call_tool(
            "ctf_task_create",
            {"title": "x", "category": "misc", "conversation_id": "conv-1"},
        )
        task_id = task["task_id"]
        for tool, arguments in (
            ("ctf_events_export", {"task_id": task_id}),
            ("ctf_writeup_build", {"task_id": task_id}),
            ("ctf_evidence_zip", {"task_id": task_id}),
            ("ctf_session_ingest", {"task_id": task_id}),
            ("ctf_screenshot_capture", {"task_id": task_id, "step_id": "s1", "scope": "desktop"}),
        ):
            is_error, payload = client.call_tool(tool, arguments)
            assert is_error is False, (tool, payload)
        # The session-log tool must not accept a caller-supplied path.
        tool_schemas = {tool["name"]: tool["inputSchema"] for tool in client.list_tools()}
        assert "path" not in tool_schemas["ctf_session_ingest"]["properties"]
        status = client.call_tool("ctf_runtime_status", {})
        assert status[0] is False
        assert "acp" in status[1]
        assert status[1]["security"]["approval_decide_via_mcp"].startswith("removed")
    finally:
        client.close()


def test_unknown_task_is_a_tool_error_not_a_crash() -> None:
    client = _manager_client()
    client.start()
    try:
        client.initialize()
        is_error, payload = client.call_tool("ctf_task_status", {"task_id": "t-does-not-exist"})
        assert is_error is True
        assert payload["reason_code"] == "not_found"
        # Server remains usable.
        assert client.call_tool("ctf_runtime_status", {})[0] is False
    finally:
        client.close()


def test_unknown_tool_raises_protocol_error() -> None:
    client = _manager_client()
    client.start()
    try:
        client.initialize()
        try:
            client.call_tool("ctf_not_a_tool")
        except McpRemoteError as exc:
            assert exc.code == -32602
        else:  # pragma: no cover
            raise AssertionError("expected McpRemoteError")
    finally:
        client.close()
