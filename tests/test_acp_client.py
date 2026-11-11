"""AcpClient lifecycle, diagnostics, session isolation, cancel and shutdown tests."""

from __future__ import annotations

import sys

import pytest

from ctf_solver.acp.client import AcpClient
from ctf_solver.core.errors import (
    AcpError,
    AcpProcessExited,
    AcpRemoteError,
    AcpStateError,
    AcpTimeout,
    ModelCallNotAuthorized,
    ValidationError,
)
from ctf_solver.core.protocols import AcpSessionClient
from tests.support.proc import wait_until
from tests.test_acp_support import (
    REQUIRED_DIAGNOSTICS_KEYS,
    assert_reaped,
    count_zstd_frames,
    decode_zstd_session_log,
    fake_server_command,
    make_client,
    read_jsonl,
    wait_for_jsonl_event,
)

PROMPT_CONTENT = [{"type": "text", "text": "synthetic prompt; never a model call"}]


def test_lifecycle_states_and_diagnostics_contract(make_client):
    client = make_client()
    assert client.state == "stopped"
    assert isinstance(client, AcpSessionClient)

    client.start()
    pid = client.diagnostics()["pid"]
    try:
        assert client.state == "ready"
        assert client.is_alive() is True

        diagnostics = client.diagnostics()
        missing = REQUIRED_DIAGNOSTICS_KEYS - set(diagnostics)
        assert not missing, f"missing diagnostics keys: {sorted(missing)}"
        assert diagnostics["protocol_version"] == 1
        assert diagnostics["pid"] > 0
        assert diagnostics["command"] == fake_server_command("--scenario", "normal")
        assert diagnostics["request_count"] >= 1
        assert diagnostics["response_count"] >= 1
        assert diagnostics["pending_requests"] == 0
        assert diagnostics["last_error"] is None
        assert diagnostics["started_at"] is not None
        assert diagnostics["allow_model_calls"] is False
        # The server banner is drained into the bounded stderr tail.
        wait_until(
            lambda: "fake-acp" in client.diagnostics()["stderr_tail"], timeout=5.0
        )
    finally:
        client.stop()

    assert client.state == "stopped"
    assert client.is_alive() is False
    stopped = client.diagnostics()
    assert stopped["exit_code"] == 0
    assert_reaped(client)

    # stop() is idempotent and must not raise or change the recorded exit code.
    client.stop()
    client.stop()
    assert client.diagnostics()["exit_code"] == 0


def test_restart_after_stop(make_client, tmp_path):
    client = make_client()
    client.start()
    first_pid = client.diagnostics()["pid"]
    client.stop()
    client.start()
    second_pid = client.diagnostics()["pid"]
    try:
        assert second_pid != first_pid
        workspace = tmp_path / "restart-work"
        workspace.mkdir()
        session = client.new_session(str(workspace))
        assert session["sessionId"]
    finally:
        client.stop()
    assert client.state == "stopped"


def test_spawn_failure_sets_failed_state(make_client):
    client = make_client(command=["this-executable-does-not-exist-ctf-solver"])
    with pytest.raises(AcpError):
        client.start()
    assert client.state == "failed"
    diagnostics = client.diagnostics()
    assert diagnostics["last_error"]
    assert "spawn" in diagnostics["last_error"].lower()
    client.stop()
    assert client.state == "stopped"


def test_initialize_process_exit_sets_failed_state_with_exit_code(make_client):
    client = make_client(command=[sys.executable, "-c", "import sys; sys.exit(3)"])
    with pytest.raises(AcpProcessExited):
        client.start()
    assert client.state == "failed"
    wait_until(lambda: client.diagnostics()["exit_code"] == 3)
    assert client.diagnostics()["last_error"]
    client.stop()


def test_startup_timeout_fails_and_reaps(make_client):
    client = make_client(
        command=[sys.executable, "-c", "import time; time.sleep(5)"],
        startup_timeout_s=0.3,
    )
    with pytest.raises(AcpTimeout):
        client.start()
    assert client.state == "failed"
    client.stop(timeout_s=0.2)
    assert client.state == "stopped"
    assert client.is_alive() is False


def test_new_session_validates_cwd_before_sending(make_client, tmp_path):
    client = make_client()
    client.start()
    request_count_before = client.diagnostics()["request_count"]

    with pytest.raises(ValidationError):
        client.new_session("relative/work")
    with pytest.raises(ValidationError):
        client.new_session(str(tmp_path / "does-not-exist"))
    assert client.diagnostics()["request_count"] == request_count_before

    workspace = tmp_path / "work"
    workspace.mkdir()
    result = client.new_session(str(workspace))
    assert result["sessionId"]
    assert isinstance(result["configOptions"], list) and result["configOptions"]
    assert client.diagnostics()["request_count"] == request_count_before + 1


def test_new_session_forwards_mcp_servers_and_records_them(make_client, tmp_path):
    record_dir = tmp_path / "record"
    client = make_client(args=("--record", str(record_dir)))
    client.start()
    workspace_one = tmp_path / "task-one" / "work"
    workspace_two = tmp_path / "task-two" / "work"
    workspace_one.mkdir(parents=True)
    workspace_two.mkdir(parents=True)

    spec_one = {
        "name": "ctf-exec",
        "command": sys.executable,
        "args": ["-m", "ctf_solver.mcp.exec_server"],
        "env": {"CTF_SOLVER_IPC_URL": "http://127.0.0.1:12345", "CTF_SOLVER_WORKER_TOKEN": "t1"},
    }
    spec_two = {
        "name": "ctf-exec",
        "command": sys.executable,
        "args": ["-m", "ctf_solver.mcp.exec_server"],
        "env": {"CTF_SOLVER_IPC_URL": "http://127.0.0.1:12346", "CTF_SOLVER_WORKER_TOKEN": "t2"},
    }

    session_one = client.new_session(str(workspace_one), mcp_servers=[spec_one])
    session_two = client.new_session(str(workspace_two), mcp_servers=[spec_two])

    records = read_jsonl(record_dir / "session-new.jsonl")
    assert len(records) == 2
    by_session = {record["sessionId"]: record for record in records}
    assert by_session[session_one["sessionId"]]["cwd"] == str(workspace_one)
    assert by_session[session_one["sessionId"]]["mcpServers"] == [spec_one]
    assert by_session[session_two["sessionId"]]["cwd"] == str(workspace_two)
    assert by_session[session_two["sessionId"]]["mcpServers"] == [spec_two]


def test_two_independent_sessions_and_close_isolation(make_client, tmp_path):
    client = make_client(allow_model_calls=True)
    client.start()
    workspace_one = tmp_path / "one" / "work"
    workspace_two = tmp_path / "two" / "work"
    workspace_one.mkdir(parents=True)
    workspace_two.mkdir(parents=True)

    session_one = client.new_session(str(workspace_one))
    session_two = client.new_session(str(workspace_two))
    assert session_one["sessionId"] != session_two["sessionId"]

    client.close_session(session_one["sessionId"])
    inactive = client.list_sessions()["sessions"]
    assert [item["sessionId"] for item in inactive] == [session_one["sessionId"]]

    # The still-active session is unaffected by closing the other one.
    response = client.prompt(session_two["sessionId"], PROMPT_CONTENT)
    assert response["stopReason"] == "end_turn"
    assert response["synthetic"] is True
    with pytest.raises(AcpRemoteError):
        client.prompt(session_one["sessionId"], PROMPT_CONTENT)

    client.close_session(session_two["sessionId"])
    both = client.list_sessions()["sessions"]
    assert [item["sessionId"] for item in both] == [
        session_two["sessionId"],
        session_one["sessionId"],
    ]


def test_list_sessions_is_newest_first_and_excludes_active(make_client, tmp_path):
    client = make_client()
    client.start()
    sessions = []
    for index in range(3):
        workspace = tmp_path / f"ws-{index}" / "work"
        workspace.mkdir(parents=True)
        sessions.append(client.new_session(str(workspace)))

    # All active sessions are excluded from session/list.
    assert client.list_sessions()["sessions"] == []

    client.close_session(sessions[0]["sessionId"])
    client.close_session(sessions[2]["sessionId"])
    listed = client.list_sessions()["sessions"]
    assert [item["sessionId"] for item in listed] == [
        sessions[2]["sessionId"],
        sessions[0]["sessionId"],
    ]

    # cwd filtering still works after the active-session exclusion.
    filtered = client.list_sessions(cwd=str(tmp_path / "ws-2" / "work"))["sessions"]
    assert [item["sessionId"] for item in filtered] == [sessions[2]["sessionId"]]

    client.close_session(sessions[1]["sessionId"])
    assert [item["sessionId"] for item in client.list_sessions()["sessions"]] == [
        sessions[2]["sessionId"],
        sessions[1]["sessionId"],
        sessions[0]["sessionId"],
    ]


def test_resume_session_semantics(make_client, tmp_path):
    client = make_client()
    client.start()
    workspace = tmp_path / "resume-work"
    other_workspace = tmp_path / "other-work"
    workspace.mkdir()
    other_workspace.mkdir()
    session = client.new_session(str(workspace))
    session_id = session["sessionId"]

    # Resuming an active session is an error.
    with pytest.raises(AcpRemoteError):
        client.resume_session(session_id, str(workspace))

    client.close_session(session_id)
    resumed = client.resume_session(session_id, str(workspace))
    assert resumed["sessionId"] == session_id
    assert "configOptions" in resumed

    # A resumed session is active again and therefore hidden from session/list.
    assert client.list_sessions()["sessions"] == []

    # cwd mismatch and unknown ids are server errors; relative cwd is rejected
    # locally before any request is sent.
    client.close_session(session_id)
    with pytest.raises(AcpRemoteError):
        client.resume_session(session_id, str(other_workspace))
    with pytest.raises(AcpRemoteError):
        client.resume_session("sess-does-not-exist", str(workspace))
    request_count_before = client.diagnostics()["request_count"]
    with pytest.raises(ValidationError):
        client.resume_session(session_id, "relative/work")
    assert client.diagnostics()["request_count"] == request_count_before


def test_prompt_gate_blocks_by_default_and_server_is_not_contacted(
    make_client, tmp_path
):
    log_dir = tmp_path / "server-log"
    client = make_client(args=("--log-dir", str(log_dir)))
    client.start()
    workspace = tmp_path / "gate-work"
    workspace.mkdir()
    session = client.new_session(str(workspace))
    request_count_before = client.diagnostics()["request_count"]

    with pytest.raises(ModelCallNotAuthorized):
        client.prompt(session["sessionId"], PROMPT_CONTENT)

    assert client.diagnostics()["request_count"] == request_count_before
    assert client.state == "ready"
    assert not [
        event for event in read_jsonl(log_dir / "server-events.jsonl") if event.get("event") == "prompt"
    ]


def test_prompt_allowed_returns_deterministic_synthetic_result(make_client, tmp_path):
    client = make_client(allow_model_calls=True)
    client.start()
    updates: list[dict] = []
    client.set_session_update_handler(updates.append)
    workspace = tmp_path / "prompt-work"
    workspace.mkdir()
    session = client.new_session(str(workspace))

    result = client.prompt(session["sessionId"], PROMPT_CONTENT)
    assert result["stopReason"] == "end_turn"
    assert result["synthetic"] is True
    assert result["agentMessage"]["content"][0]["type"] == "text"

    wait_until(lambda: len(updates) == 1)
    assert updates[0]["sessionId"] == session["sessionId"]
    assert updates[0]["update"]["sessionUpdate"] == "agent_message_chunk"
    assert client.diagnostics()["session_updates"] == 1


def test_cancel_session_is_notification_and_process_stays_alive(make_client, tmp_path):
    log_dir = tmp_path / "cancel-log"
    client = make_client(args=("--log-dir", str(log_dir)))
    client.start()
    workspace = tmp_path / "cancel-work"
    workspace.mkdir()
    session = client.new_session(str(workspace))

    client.cancel_session(session["sessionId"])
    assert client.diagnostics()["cancel_notifications"] == 1
    # ACP cancel stops a turn; it is NOT an OS process kill.
    assert client.is_alive() is True
    assert client.state == "ready"

    event = wait_for_jsonl_event(
        log_dir / "server-events.jsonl", lambda record: record.get("event") == "cancel"
    )
    assert event["sessionId"] == session["sessionId"]

    # The session can still be closed normally after cancellation.
    client.close_session(session["sessionId"])


def test_cancel_that_kills_process_is_detected_as_crash(make_client, tmp_path):
    client = make_client("exit-on-cancel")
    client.start()
    workspace = tmp_path / "cancel-exit-work"
    workspace.mkdir()
    session = client.new_session(str(workspace))
    pid = client.diagnostics()["pid"]

    client.cancel_session(session["sessionId"])
    wait_until(lambda: client.is_alive() is False, timeout=5.0)
    wait_until(lambda: client.state == "crashed", timeout=5.0)
    wait_until(lambda: client.diagnostics()["exit_code"] == 5, timeout=5.0)
    assert "exited" in (client.diagnostics()["last_error"] or "").lower()

    with pytest.raises(AcpProcessExited):
        client.new_session(str(workspace))
    client.stop()
    assert client.state == "stopped"
    assert_reaped(client)


def test_crash_after_initialize_sets_crashed_with_exit_code(make_client, tmp_path):
    client = make_client("crash-after-init")
    client.start()
    assert client.state == "ready"
    pid = client.diagnostics()["pid"]
    wait_until(lambda: client.is_alive() is False, timeout=5.0)
    wait_until(lambda: client.state == "crashed", timeout=5.0)
    wait_until(lambda: client.diagnostics()["exit_code"] == 7, timeout=5.0)
    workspace = tmp_path / "crash-work"
    workspace.mkdir()
    with pytest.raises(AcpProcessExited):
        client.list_sessions()
    client.stop()
    assert_reaped(client)


def test_requests_after_stop_raise_state_error(make_client, tmp_path):
    client = make_client()
    client.start()
    workspace = tmp_path / "after-stop-work"
    workspace.mkdir()
    session = client.new_session(str(workspace))
    client.stop()

    with pytest.raises(AcpStateError):
        client.list_sessions()
    with pytest.raises(AcpStateError):
        client.new_session(str(workspace))
    with pytest.raises(AcpStateError):
        client.close_session(session["sessionId"])
    with pytest.raises(AcpStateError):
        client.cancel_session(session["sessionId"])
    # The model-call gate still wins over lifecycle state checks.
    with pytest.raises(ModelCallNotAuthorized):
        client.prompt(session["sessionId"], PROMPT_CONTENT)


def test_graceful_shutdown_records_stderr_file_and_reaps(make_client, tmp_path):
    stderr_path = tmp_path / "client-stderr.log"
    client = make_client(stderr_path=stderr_path)
    client.start()
    workspace = tmp_path / "shutdown-work"
    workspace.mkdir()
    client.new_session(str(workspace))
    pid = client.diagnostics()["pid"]

    client.stop()
    assert client.state == "stopped"
    assert client.is_alive() is False
    assert client.diagnostics()["exit_code"] == 0
    wait_until(lambda: stderr_path.exists() and "fake-acp" in stderr_path.read_text(encoding="utf-8"))
    assert_reaped(client)


def test_session_log_fixture_is_written_for_each_new_session(make_client, tmp_path):
    log_dir = tmp_path / "session-logs"
    client = make_client(args=("--session-log", str(log_dir)))
    client.start()
    workspace = tmp_path / "session-log-work"
    workspace.mkdir()
    session = client.new_session(str(workspace))
    session_id = session["sessionId"]

    canonical = log_dir / "session.v4.jsonl.zstd"
    per_session = log_dir / f"{session_id}.zstd"
    assert canonical.exists()
    assert per_session.exists()

    data = canonical.read_bytes()
    assert data.startswith(b"\x28\xb5\x2f\xfd")
    # Multiple concatenated frames, not a single-frame log.
    assert count_zstd_frames(data) >= 2

    records = decode_zstd_session_log(data)
    header = records[0]
    assert header["type"] == "session"
    assert header["data"]["id"] == session_id
    assert header["data"]["cwd"] == str(workspace)
    call_ids = [
        record["data"].get("callId") for record in records if record["type"] == "tool/call"
    ]
    result_ids = [
        record["data"]["message"]["toolCallId"]
        for record in records
        if record["type"] == "tool/result"
    ]
    assert call_ids and call_ids == result_ids


def test_stop_before_start_and_double_start(make_client):
    client = make_client()
    assert client.is_alive() is False
    client.stop()  # no-op before start
    assert client.state == "stopped"

    client.start()
    with pytest.raises(AcpStateError):
        client.start()  # already ready
    client.stop()
    assert client.state == "stopped"


def test_constructor_validates_command_and_timeouts():
    with pytest.raises(ValidationError):
        AcpClient([])
    with pytest.raises(ValidationError):
        AcpClient([""])
    with pytest.raises(ValidationError):
        AcpClient([sys.executable], startup_timeout_s=0)
    with pytest.raises(ValidationError):
        AcpClient([sys.executable], request_timeout_s=-1)


def test_malformed_server_lines_are_diagnostics_not_failures(make_client, tmp_path):
    client = make_client("malformed")
    client.start()
    # The server emitted non-JSON lines before each response; the handshake and
    # later requests still succeed and the diagnostics count the garbage.
    wait_until(lambda: client.diagnostics()["malformed_lines"] >= 1)
    assert client.state == "ready"
    workspace = tmp_path / "malformed-work"
    workspace.mkdir()
    session = client.new_session(str(workspace))
    assert session["sessionId"]
    assert client.diagnostics()["malformed_lines"] >= 2


def test_request_timeout_keeps_client_usable(make_client, tmp_path):
    client = make_client("slow", startup_timeout_s=5.0, request_timeout_s=0.1)
    client.start()
    workspace = tmp_path / "slow-work"
    workspace.mkdir()

    with pytest.raises(AcpTimeout):
        client.new_session(str(workspace))
    assert client.state == "ready"
    assert client.diagnostics()["last_error"]
    assert client.diagnostics()["timed_out_requests"] == 1
    # A late response must not crash the transport; stop still reaps cleanly.
    client.stop()
    assert client.state == "stopped"
    assert client.diagnostics()["exit_code"] is not None


def test_session_argument_validation(make_client, tmp_path):
    client = make_client(allow_model_calls=True)
    client.start()
    workspace = tmp_path / "validation-work"
    workspace.mkdir()
    session = client.new_session(str(workspace))
    session_id = session["sessionId"]
    request_count = client.diagnostics()["request_count"]

    with pytest.raises(ValidationError):
        client.new_session(str(workspace), mcp_servers="python -m x")  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        client.new_session(str(workspace), mcp_servers=[{"name": "x"}, "bad"])  # type: ignore[list-item]
    with pytest.raises(ValidationError):
        client.prompt("", PROMPT_CONTENT)
    with pytest.raises(ValidationError):
        client.prompt(session_id, "plain string")  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        client.prompt(session_id, [{"type": "text"}, "bad"])  # type: ignore[list-item]
    with pytest.raises(ValidationError):
        client.list_sessions(cwd="relative/work")
    with pytest.raises(ValidationError):
        client.set_permission_handler("not-callable")  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        client.set_session_update_handler(42)  # type: ignore[arg-type]

    # All of those failed before any request was sent.
    assert client.diagnostics()["request_count"] == request_count


def test_unknown_session_errors(make_client, tmp_path):
    client = make_client()
    client.start()
    workspace = tmp_path / "unknown-work"
    workspace.mkdir()
    with pytest.raises(AcpRemoteError):
        client.close_session("sess-does-not-exist")
    with pytest.raises(AcpRemoteError):
        client.resume_session("sess-does-not-exist", str(workspace))
    # A cancel notification for an unknown session is fire-and-forget.
    client.cancel_session("sess-does-not-exist")
    assert client.is_alive() is True
    assert client.diagnostics()["cancel_notifications"] == 1


def test_each_session_gets_its_own_session_log(make_client, tmp_path):
    log_dir = tmp_path / "session-logs"
    client = make_client(args=("--session-log", str(log_dir)))
    client.start()
    sessions = []
    for index in range(2):
        workspace = tmp_path / f"log-ws-{index}"
        workspace.mkdir()
        sessions.append(client.new_session(str(workspace)))

    session_ids = [session["sessionId"] for session in sessions]
    assert len(set(session_ids)) == 2
    for session_id in session_ids:
        assert (log_dir / f"{session_id}.zstd").exists()
    decoded_ids = set()
    for session_id in session_ids:
        records = decode_zstd_session_log((log_dir / f"{session_id}.zstd").read_bytes())
        decoded_ids.add(records[0]["data"]["id"])
    assert decoded_ids == set(session_ids)
