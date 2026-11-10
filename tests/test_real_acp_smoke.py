"""Zero-model-call smoke test against the locally installed Harness ACP server.

This test is opt-in (``CTF_SOLVER_ENABLE_REAL_ACP=1``) because it launches the
audited local Harness installation with an **isolated temporary DSH_HOME**.
It makes no model call: only ``initialize``, two ``session/new`` calls, an
active-session list check, close, and stdin-EOF shutdown. It is allowed by
ROUND_1_IMPLEMENTATION_TASK.md section 4 and ADR-019/ADR-020.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from ctf_solver.core.config import build_acp_env, discover_acp_command
from ctf_solver.core.errors import ModelCallNotAuthorized
from ctf_solver.wiring import _acp_launch_command

pytestmark = pytest.mark.real_acp


@pytest.mark.skipif(
    os.environ.get("CTF_SOLVER_ENABLE_REAL_ACP", "") != "1",
    reason="real ACP smoke test is opt-in (CTF_SOLVER_ENABLE_REAL_ACP=1); Round 1 default is fake-only",
)
def test_zero_model_call_acp_lifecycle_smoke(tmp_path: Path) -> None:
    from ctf_solver.acp.client import AcpClient

    launcher = discover_acp_command()
    if launcher is None:
        pytest.fail("the audited Harness ACP launcher (dsh) was not found on this machine")
    command = _acp_launch_command(launcher)
    temp_home = tmp_path / "temp-dsh-home"
    temp_home.mkdir()
    workspace_a = tmp_path / "workspaces" / "task-a" / "work"
    workspace_b = tmp_path / "workspaces" / "task-b" / "work"
    workspace_a.mkdir(parents=True)
    workspace_b.mkdir(parents=True)
    env = build_acp_env(base=os.environ, dsh_home=str(temp_home))
    env.setdefault("PYTHONPATH", str(Path(__file__).resolve().parents[1]))
    env.setdefault("PYTHONUTF8", "1")
    client = AcpClient(
        command,
        env=env,
        startup_timeout_s=60.0,
        request_timeout_s=60.0,
        allow_model_calls=False,
    )
    try:
        client.start()
        diagnostics = client.diagnostics()
        assert diagnostics["state"] == "ready"
        assert diagnostics["protocol_version"] == 1

        # The Round 1 prompt gate is client-side: no request is sent.
        with pytest.raises(ModelCallNotAuthorized):
            client.prompt("not-a-session", [{"type": "text", "text": "must never be sent"}])

        session_a = client.new_session(cwd=str(workspace_a.resolve()))
        session_b = client.new_session(cwd=str(workspace_b.resolve()))
        assert session_a["sessionId"] and session_b["sessionId"]
        assert session_a["sessionId"] != session_b["sessionId"]

        listing = client.list_sessions(cwd=str(workspace_a.resolve()))
        active_ids = {item.get("sessionId") for item in listing.get("sessions", [])}
        # Active sessions are documented to be excluded from session/list.
        assert session_a["sessionId"] not in active_ids
        assert session_b["sessionId"] not in active_ids

        client.close_session(session_a["sessionId"])
        # Closing one session must not affect the other.
        listing_after = client.list_sessions()
        remaining_ids = {item.get("sessionId") for item in listing_after.get("sessions", [])}
        assert session_b["sessionId"] not in remaining_ids

        client.close_session(session_b["sessionId"])
    finally:
        client.stop()
    diagnostics = client.diagnostics()
    assert diagnostics["exit_code"] == 0, diagnostics
    # An isolated home was used; the global Harness home was not addressed by this test.
    assert temp_home.is_dir()
    assert any(temp_home.iterdir()), "the isolated DSH_HOME should contain the generated ACP profile"
