"""Round 2 security/integration regression tests (Lead-owned).

These tests verify the owner-mandated Round 2 security remediations end to end
at the Manager/MCP/CLI boundaries:

* the model can request an approval but can never decide one or create a grant;
* session-log ingestion is registry-derived (no caller file path);
* ACP permission events are mapped through the Manager session registry;
* challenge files are imported only from the project intake root, hashed and
  isolated per Task;
* MCP argument schemas enforce types/additionalProperties, not just required;
* the default ACP launch command is the audited ``dsh --profile acp``.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from ctf_solver.core.errors import StateError
from ctf_solver.core.types import TaskStatus
from ctf_solver.manager.session_logs import SessionLogError
from ctf_solver.mcp.client import McpRemoteError, McpStdioClient
from tests.support.proc import PROJECT_ROOT, child_env, run_module
from tests.test_manager_service import build_service


def test_mcp_argument_schema_rejects_wrong_types_and_extra_fields() -> None:
    client = McpStdioClient(
        [sys.executable, "-m", "tests.support.mcp_test_servers", "manager"],
        env=child_env(),
        cwd=str(PROJECT_ROOT),
        request_timeout=30.0,
    )
    client.start()
    try:
        client.initialize()
        with pytest.raises(McpRemoteError) as info:
            client.call_tool("ctf_task_list", {"status": 123})
        assert info.value.code == -32602
        with pytest.raises(McpRemoteError) as info2:
            client.call_tool("ctf_task_status", {"task_id": "t-stub0001", "evil": "x"})
        assert info2.value.code == -32602
        with pytest.raises(McpRemoteError) as info3:
            client.call_tool("ctf_session_ingest", {"task_id": "t-stub0001", "path": "C:/Windows/win.ini"})
        assert info3.value.code == -32602
    finally:
        client.close()


def test_agent_cannot_decide_approvals_or_create_grants(tmp_path) -> None:
    service, _acp, _evidence, _pipeline, _deliverables, store = build_service(tmp_path)
    try:
        service.start()
        task = service.create_task(title="t", category="misc", conversation_id="conv")
        approval = service.request_approval(
            task.task_id, action_kind="tool_action", details={"tool": "internal.file_hash"}
        )
        for approver in ("human", "false", "true", "SYSTEM", ""):
            with pytest.raises(StateError):
                service.decide_approval(approval.approval_id, approved=True, approver=approver)
        with pytest.raises(StateError):
            service.create_network_grant(
                task.task_id,
                competition_profile="synthetic-local",
                host="127.0.0.1",
                port=31337,
                ttl_s=60,
                max_calls=1,
                approver="human",
            )
        # The approval remains pending: no Agent path changed it.
        assert service.list_approvals(task_id=task.task_id)[0].status.value == "pending"
    finally:
        service.shutdown()
        store.close()


def test_session_ingest_uses_manager_registry_only(tmp_path) -> None:
    service, _acp, _evidence, _pipeline, _deliverables, store = build_service(tmp_path)
    try:
        service.start()
        # A queued Task has no Worker/session registry entry yet: ingestion fails
        # closed instead of reading a caller-supplied path.
        from ctf_solver.core.types import Category, TaskRecord

        queued_id = "t-queued-ingest"
        workspace = service.config.paths.task_workspace(queued_id)
        workspace.mkdir(parents=True, exist_ok=True)
        store.create_task(
            TaskRecord(
                task_id=queued_id,
                conversation_id="conv",
                title="queued",
                category=Category.MISC,
                workspace_path=str(workspace),
            )
        )
        # SessionLogResolver requires an actual Worker mapping; the Manager
        # refuses before touching any file.
        with pytest.raises(SessionLogError):
            service.ingest_session_log(queued_id)
        # No method signature accepts a path at all.
        import inspect

        signature = inspect.signature(service.ingest_session_log)
        assert "path" not in signature.parameters
    finally:
        service.shutdown()
        store.close()


def test_acp_permission_events_are_mapped_through_session_registry(tmp_path) -> None:
    service, _acp, evidence, _pipeline, _deliverables, store = build_service(tmp_path)
    try:
        service.start()
        task = service.create_task(title="permissions", category="misc", conversation_id="conv")
        session_id = str(task.acp_session_id)
        response = service._on_permission_request(  # noqa: SLF001 - regression test of mapping
            {"sessionId": session_id, "toolCall": {"toolCallId": "call-1"}}
        )
        assert response == {"outcome": {"outcome": "cancelled"}}
        events = [event for event in evidence.events if event["event_type"] == "acp_permission_rejected"]
        assert len(events) == 1
        assert events[0]["task_id"] == task.task_id
        assert events[0]["worker_id"] == task.worker_id

        # Unknown session: a system diagnostic, never an event against a wrong Task.
        unknown = service._on_permission_request(  # noqa: SLF001
            {"sessionId": "session-not-in-registry", "toolCall": {"toolCallId": "call-2"}}
        )
        assert unknown == {"outcome": {"outcome": "cancelled"}}
        assert len([e for e in evidence.events if e["event_type"] == "acp_permission_rejected"]) == 1
        diagnostics = service.runtime_status()["diagnostics"]
        assert any(item["code"] == "acp_permission_unknown_session" for item in diagnostics)
    finally:
        service.shutdown()
        store.close()


def _write_intake(intake_root: Path, rel: str, data: bytes) -> Path:
    intake_root.mkdir(parents=True, exist_ok=True)
    target = intake_root / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    return target


def test_challenge_file_intake_is_controlled_hashed_and_isolated(tmp_path) -> None:
    service, _acp, evidence, _pipeline, _deliverables, store = build_service(tmp_path)
    try:
        service.start()
        intake = service.config.intake_root
        _write_intake(intake, "challenge.zip", b"PK\x03\x04synthetic")
        _write_intake(intake, "dir/note.txt", b"hello challenge")

        task = service.create_task(
            title="with files",
            category="misc",
            conversation_id="conv",
            supplied_files=["challenge.zip", "dir/note.txt"],
        )
        work = Path(task.workspace_path)
        assert (work / "inputs" / "challenge.zip").is_file()
        assert (work / "inputs" / "dir" / "note.txt").read_bytes() == b"hello challenge"
        inputs = service.get_task_status(task.task_id)["inputs"]
        assert {item["rel_path"] for item in inputs} == {"challenge.zip", "dir/note.txt"}
        by_rel = {item["rel_path"]: item for item in inputs}
        assert by_rel["challenge.zip"]["size"] == len(b"PK\x03\x04synthetic")
        assert by_rel["challenge.zip"]["sha256"]

        # A second Task gets its own isolated copy; changing one cannot affect the other.
        other = service.create_task(
            title="other", category="misc", conversation_id="conv", supplied_files=["dir/note.txt"]
        )
        other_copy = Path(other.workspace_path) / "inputs" / "dir" / "note.txt"
        assert other_copy.is_file()
        (work / "inputs" / "dir" / "note.txt").write_bytes(b"modified")
        assert other_copy.read_bytes() == b"hello challenge"

        # The Writeup records the real input material hashes/sizes (rendered by
        # the real WriteupBuilder from the durable task_created evidence event).
        from ctf_solver.delivery.writeup import WriteupBuilder

        class _TaskEvents:
            def __init__(self, task_id: str, events: list[dict]) -> None:
                self.task_id = task_id
                self.events = events

            def list_events(self, *, task_id=None, **kwargs):
                return [event for event in self.events if event["task_id"] == task_id]

            def list_screenshots(self, task_id):
                return []

        created = [e for e in evidence.events if e["event_type"] == "task_created"][-2]
        text = WriteupBuilder(_TaskEvents(task.task_id, evidence.events)).render(
            service.get_task(task.task_id)
        )
        assert created["payload"]["supplied_inputs"]
        assert "challenge.zip" in text
        assert by_rel["challenge.zip"]["sha256"] in text
        assert created["payload"]["supplied_inputs"][0]["sha256"] == by_rel["challenge.zip"]["sha256"]
    finally:
        service.shutdown()
        store.close()


@pytest.mark.parametrize("bad", ["../outside.txt", "C:/Windows/win.ini", "/etc/passwd", "dir/../../x"])
def test_intake_rejects_unsafe_paths(tmp_path, bad: str) -> None:
    service, _acp, _evidence, _pipeline, _deliverables, store = build_service(tmp_path)
    try:
        service.start()
        (service.config.intake_root).mkdir(parents=True, exist_ok=True)
        with pytest.raises(Exception):
            service.create_task(
                title="bad intake", category="misc", conversation_id="conv", supplied_files=[bad]
            )
        # The Task must not silently continue as if material had been imported.
        tasks = [task for task in service.list_tasks() if task.title == "bad intake"]
        assert tasks and tasks[0].status is TaskStatus.FAILED
        assert service.get_task_status(tasks[0].task_id)["inputs"] == []
    finally:
        service.shutdown()
        store.close()


def test_default_acp_launch_command_includes_profile(monkeypatch, tmp_path) -> None:
    from ctf_solver.core.config import SolverConfig
    from ctf_solver.wiring import default_acp_factory

    launcher = tmp_path / "dsh.cmd"
    launcher.write_text("@echo off\r\n", encoding="ascii")
    monkeypatch.setattr("ctf_solver.wiring.discover_acp_command", lambda: [str(launcher)])
    config = SolverConfig(root=tmp_path / "project")
    client = default_acp_factory(config)()
    command = client.diagnostics().get("command")
    assert command, "AcpClient diagnostics must expose its launch argv for verification"
    assert "--profile" in command and "acp" in command
    assert command.index("--profile") < command.index("acp")
    # A .cmd launcher is wrapped in the COMSPEC, never executed as a shell string.
    assert Path(command[0]).name.lower() in {"cmd.exe", "cmd"}


def test_manager_server_treats_explicit_acp_command_as_complete() -> None:
    from ctf_solver.mcp.manager_server import _parse_acp_command

    assert _parse_acp_command(None) is None
    assert _parse_acp_command("") is None
    parsed = _parse_acp_command("python -m ctf_solver.acp.fake_server")
    assert parsed == ["python", "-m", "ctf_solver.acp.fake_server"]


def test_approval_cli_without_tty_fails_closed(tmp_path) -> None:
    config_root = tmp_path / "project"
    config_root.mkdir()
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "ctf_solver",
            "approval",
            "confirm",
            "--root",
            str(config_root),
            "--approval-id",
            "apr-missing",
        ],
        cwd=str(PROJECT_ROOT),
        env=child_env(),
        capture_output=True,
        input="",
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
    )
    assert result.returncode != 0
    combined = (result.stdout or "") + (result.stderr or "")
    assert "console" in combined.lower() or "tty" in combined.lower() or "approval" in combined.lower()


def test_grant_cli_requires_a_confirmed_approval(tmp_path) -> None:
    config_root = tmp_path / "project"
    config_root.mkdir()
    result = run_module(
        "ctf_solver",
        "grant",
        "create",
        "--root",
        str(config_root),
        "--approval-id",
        "apr-does-not-exist",
        "--host",
        "127.0.0.1",
        "--port",
        "31337",
    )
    assert result.returncode != 0
    assert "grant" in ((result.stdout or "") + (result.stderr or "")).lower()
