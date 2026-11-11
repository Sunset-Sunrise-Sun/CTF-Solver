"""End-to-end Round 1 stack test: Manager MCP + real ACP client + fake ACP server
+ Worker ctf-exec MCP server + Broker/Runtime + SQLite/CAS evidence + delivery.

No model call is made, no real challenge data is used and no network target is
contacted. The fake ACP server speaks the audited stdio ND-JSON protocol.
"""

from __future__ import annotations

import json
import sqlite3
import sys
import time
import zipfile
from pathlib import Path

import pytest

from ctf_solver.core.canonical import file_sha256
from ctf_solver.delivery.bundle import EvidenceBundleBuilder
from ctf_solver.mcp.client import McpStdioClient
from tests.support.proc import PROJECT_ROOT, child_env, terminate, wait_until


def _fake_acp_launcher(logs: Path, record: Path) -> str:
    return (
        f"{sys.executable} -m ctf_solver.acp.fake_server --scenario normal "
        f"--session-log {logs} --record {record}"
    )


def _manager_command(root: Path, logs: Path, record: Path, session_root: Path) -> list[str]:
    return [
        sys.executable,
        "-m",
        "ctf_solver.mcp.manager_server",
        "--root",
        str(root),
        "--capture-mode",
        "fake",
        "--session-log-root",
        str(session_root),
    ]


@pytest.fixture()
def stack(tmp_path: Path):
    root = tmp_path / "project"
    root.mkdir()
    logs = tmp_path / "session-logs"
    logs.mkdir()
    record = tmp_path / "acp-record"
    record.mkdir()
    session_root = tmp_path / "harness-sessions"
    session_root.mkdir()
    client = McpStdioClient(
        _manager_command(root, logs, record, session_root),
        env=child_env(CTF_SOLVER_TEST_ACP_COMMAND=_fake_acp_launcher(logs, record)),
        cwd=str(PROJECT_ROOT),
        request_timeout=90.0,
    )
    client.start()
    try:
        client.initialize(client_info={"name": "round1-integration-test", "version": "0.1.0"})
        yield client, root, logs, record, session_root
    finally:
        client.close()


def _task_status(client: McpStdioClient, task_id: str) -> dict:
    is_error, payload = client.call_tool("ctf_task_status", {"task_id": task_id})
    assert is_error is False, payload
    return payload


def _read_workers(root: Path) -> list[dict]:
    db = root / ".ctf-solver-data" / "manager.sqlite"
    wait_until(db.is_file, timeout=20, message="manager database was not created")
    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute("SELECT worker_id, task_id, acp_session_id, worker_token, workspace_path FROM workers").fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def _start_exec_client(ipc_url: str, token: str) -> McpStdioClient:
    env = child_env(CTF_SOLVER_IPC_URL=ipc_url, CTF_SOLVER_WORKER_TOKEN=token)
    client = McpStdioClient(
        [sys.executable, "-m", "ctf_solver.mcp.exec_server"],
        env=env,
        cwd=str(PROJECT_ROOT),
        request_timeout=90.0,
    )
    client.start()
    client.initialize()
    return client


def test_full_round1_stack(stack) -> None:
    client, root, logs, record, session_root = stack

    # 1. Runtime status: manager + ACP client + IPC up.
    is_error, status = client.call_tool("ctf_runtime_status", {})
    assert is_error is False
    assert status["acp"]["ready"] is True
    assert status["ipc_url"].startswith("tcp://127.0.0.1:")
    assert status["round1_limits"]["model_calls"].startswith("blocked")
    ipc_url = status["ipc_url"]

    # 2. Three Tasks -> two active Workers + one FIFO queued Task.
    tasks = []
    for index in range(3):
        is_error, task = client.call_tool(
            "ctf_task_create",
            {
                "title": f"Synthetic challenge {index}",
                "category": ["web", "misc", "crypto"][index],
                "conversation_id": "conv-integration",
                "source": "synthetic-local",
                "notes": "Synthetic challenge description used for integration evidence.",
            },
        )
        assert is_error is False, task
        tasks.append(task)
    assert [task["status"] for task in tasks] == ["running", "running", "queued"]
    assert len({task["acp_session_id"] for task in tasks[:2]}) == 2
    assert len({task["workspace_path"] for task in tasks[:2]}) == 2
    status_third = _task_status(client, tasks[2]["task_id"])
    assert status_third["queue_position"] == 1
    assert status_third["worker"] is None

    # 3. Worker mapping persisted in SQLite (authoritative registry).
    workers = _read_workers(root)
    assert len(workers) == 2
    by_task = {worker["task_id"]: worker for worker in workers}
    worker0 = by_task[tasks[0]["task_id"]]
    assert worker0["acp_session_id"] == tasks[0]["acp_session_id"]

    # 4. Fake ACP server wrote real multi-frame session logs for the sessions.
    wait_until(
        lambda: (logs / f"{tasks[0]['acp_session_id']}.zstd").is_file(),
        timeout=20,
        message="fake ACP session log was not written",
    )
    log_path = logs / f"{tasks[0]['acp_session_id']}.zstd"
    data = log_path.read_bytes()
    assert data[:4] == b"\x28\xb5\x2f\xfd"
    assert len(data) > 100

    # 5. Typed ctf-exec through the Worker MCP server -> Manager IPC -> Broker -> Runtime.
    workspace = Path(tasks[0]["workspace_path"])
    synthetic_file = workspace / "synthetic.txt"
    synthetic_file.write_text("synthetic challenge content\n", encoding="utf-8")
    expected_sha = file_sha256(synthetic_file)
    exec_client = _start_exec_client(ipc_url, worker0["worker_token"])
    try:
        is_error, result = exec_client.call_tool(
            "ctf_exec",
            {
                "task_id": tasks[0]["task_id"],
                "worker_id": tasks[0]["worker_id"],
                "step_id": "step-hash-1",
                "tool_name": "internal.file_hash",
                "argv": ["synthetic.txt"],
                "cwd": str(workspace),
                "timeout_s": 15,
            },
        )
        assert is_error is False, result
        assert result["status"] == "completed", result
        assert result["exit_code"] == 0
        parsed = json.loads(result["stdout_preview"])
        assert parsed["sha256"] == expected_sha
        assert result["task_id"] == tasks[0]["task_id"]
        assert result["worker_id"] == tasks[0]["worker_id"]

        # 6. Denied call is distinguishable and does not execute.
        is_error, denied = exec_client.call_tool(
            "ctf_exec",
            {
                "task_id": tasks[0]["task_id"],
                "worker_id": tasks[0]["worker_id"],
                "step_id": "step-denied-1",
                "tool_name": "tool.remote_probe",
                "argv": ["example.invalid"],
                "cwd": str(workspace),
                "network_target": {"host": "example.invalid", "port": 80, "protocol": "tcp", "method": "GET"},
            },
        )
        assert is_error is False, denied
        assert denied["status"] in {"denied", "blocked"}, denied
        assert denied["reason_code"], denied
    finally:
        exec_client.close()

    # 7. Status/executions + evidence chain.
    task_status = _task_status(client, tasks[0]["task_id"])
    assert len(task_status["executions"]) >= 2
    statuses = sorted(row["status"] for row in task_status["executions"])
    assert "completed" in statuses
    assert "denied" in statuses
    assert task_status["evidence"]["chain_head_seq"] > 0

    # 8. Session-log ingestion (multi-frame zstd -> normalized evidence, idempotent).
    # The Manager resolves the log from its own Task/Worker/session registry; the
    # test materializes the real Harness layout under the configured sessions root.
    harness_dir = session_root / "fake-harness-slug" / str(tasks[0]["acp_session_id"])
    harness_dir.mkdir(parents=True, exist_ok=True)
    (harness_dir / "session.v4.jsonl.zstd").write_bytes(log_path.read_bytes())
    is_error, ingest = client.call_tool(
        "ctf_session_ingest", {"task_id": tasks[0]["task_id"]}
    )
    assert is_error is False, (ingest, client.diagnostics())
    assert ingest["appended"] > 0
    before_reingest = _task_status(client, tasks[0]["task_id"])["evidence"]["chain_head_seq"]
    is_error, ingest2 = client.call_tool(
        "ctf_session_ingest", {"task_id": tasks[0]["task_id"]}
    )
    assert is_error is False, ingest2
    assert ingest2["appended"] == 0
    assert ingest2["skipped_duplicates"] >= ingest["appended"]
    # The Manager still records one evidence_ingested lifecycle event per request,
    # so the chain head advances only by those manager records, never by duplicates.
    after_reingest = _task_status(client, tasks[0]["task_id"])["evidence"]["chain_head_seq"]
    assert after_reingest == before_reingest + 1

    # 9. Explicit screenshot (fake capture mode) bound to the Task/Worker/Step/session.
    is_error, shot = client.call_tool(
        "ctf_screenshot_capture",
        {"task_id": tasks[0]["task_id"], "step_id": "step-hash-1", "scope": "desktop"},
    )
    assert is_error is False, shot
    assert shot["status"] == "ok"
    assert shot["sha256"] and shot["width"] > 0 and shot["height"] > 0
    assert shot["step_id"] == "step-hash-1"
    assert shot["session_id"] == tasks[0]["acp_session_id"]

    # 10. Candidate Flag only; no submission.
    is_error, flag = client.call_tool(
        "ctf_flag_candidate",
        {"task_id": tasks[0]["task_id"], "flag": "flag{synthetic_round1}", "source": "synthetic-fixture"},
    )
    assert is_error is False
    assert flag["flag_state"] == "candidate"
    assert flag["submitted"] is False

    # 11. Continue is accepted but suppressed (no model call).
    is_error, continued = client.call_tool("ctf_task_continue", {"task_id": tasks[1]["task_id"], "message": "继续"})
    assert is_error is False
    assert continued["model_call_suppressed"] is True

    # 12. Deliverables: events.jsonl, Writeup, evidence ZIP with verified manifest.
    for tool in ("ctf_events_export", "ctf_writeup_build", "ctf_evidence_zip"):
        is_error, export = client.call_tool(tool, {"task_id": tasks[0]["task_id"]})
        assert is_error is False, (tool, export)
    writeup_path = Path(tasks[0]["workspace_path"]).parent / "writeup.md"
    zip_path = Path(tasks[0]["workspace_path"]).parent / "evidence.zip"
    assert writeup_path.is_file()
    writeup_text = writeup_path.read_text(encoding="utf-8")
    assert "## 4. Chronological steps" in writeup_text
    assert "internal.file_hash" in writeup_text
    assert "denied" in writeup_text
    assert "synthetic_round1" in writeup_text
    assert zip_path.is_file()
    with zipfile.ZipFile(zip_path) as archive:
        names = archive.namelist()
    assert "writeup.md" in names and "events.jsonl" in names and "manifest.sha256" in names
    assert any(name.startswith("screenshots/") for name in names)
    report = EvidenceBundleBuilder.verify_zip(zip_path, root / "verify-zip")
    assert report["ok"] is True, report["problems"]

    # 13. Cancel a running Task -> the FIFO Task is promoted.
    is_error, cancelled = client.call_tool("ctf_task_cancel", {"task_id": tasks[1]["task_id"], "reason": "integration test"})
    assert is_error is False, cancelled
    assert cancelled["status"] == "cancelled"
    wait_until(
        lambda: _task_status(client, tasks[2]["task_id"])["task"]["status"] == "running",
        timeout=20,
        message="FIFO Task was not promoted after slot release",
    )
    final_status = _task_status(client, tasks[2]["task_id"])
    assert final_status["task"]["status"] == "running"
    assert final_status["worker"] is not None
    assert final_status["worker"]["acp_session_id"] not in {
        tasks[0]["acp_session_id"],
        tasks[1]["acp_session_id"],
    }
    assert final_status["worker"]["task_id"] == tasks[2]["task_id"]
    assert final_status["task"]["acp_session_id"] == final_status["worker"]["acp_session_id"]


def test_manager_serves_control_while_acp_unavailable(tmp_path: Path) -> None:
    """The control plane must not pretend Workers run when ACP cannot start."""

    root = tmp_path / "project-degraded"
    root.mkdir()
    client = McpStdioClient(
        [
            sys.executable,
            "-m",
            "ctf_solver.mcp.manager_server",
            "--root",
            str(root),
            "--capture-mode",
            "fake",
        ],
        env=child_env(
            CTF_SOLVER_TEST_ACP_COMMAND="definitely-not-a-real-acp-command-xyz"
        ),
        cwd=str(PROJECT_ROOT),
        request_timeout=60.0,
    )
    client.start()
    try:
        client.initialize()
        is_error, status = client.call_tool("ctf_runtime_status", {})
        assert is_error is False
        assert status["acp"]["ready"] is False
        is_error, task = client.call_tool(
            "ctf_task_create",
            {"title": "cannot-run", "category": "misc", "conversation_id": "conv-degraded"},
        )
        assert is_error is True, task
        assert task.get("reason_code") == "acp_unavailable", task
        assert task.get("details", {}).get("acp_ready") is False, task
        # No fake queued Task may be persisted when no Worker can ever start.
        is_error, tasks = client.call_tool("ctf_task_list", {})
        assert is_error is False
        assert tasks == []
    finally:
        client.close()
