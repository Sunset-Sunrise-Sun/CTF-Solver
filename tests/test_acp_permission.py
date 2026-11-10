"""Permission round-trip tests (server -> client ``session/request_permission``).

The fake server asks for a one-shot permission decision during
``session/prompt``; the client's handler answers; the outcome is recorded both
in the prompt result and in the server's ``server-events.jsonl`` log. Round 1
never talks to a real model: the fake server returns a deterministic synthetic
result and the client gate is what blocks un-authorized use.
"""

from __future__ import annotations

import pytest

from ctf_solver.acp import models
from ctf_solver.core.errors import ModelCallNotAuthorized
from tests.test_acp_support import (
    make_client,
    read_jsonl,
    wait_for_jsonl_event,
)

PROMPT_CONTENT = [{"type": "text", "text": "synthetic permission round-trip"}]


def _permission_events(log_dir, event: str):
    return [
        record
        for record in read_jsonl(log_dir / "server-events.jsonl")
        if record.get("event") == event
    ]


def test_permission_allow_once_round_trip(make_client, tmp_path):
    log_dir = tmp_path / "permission-log"
    client = make_client(
        "permission-request", args=("--log-dir", str(log_dir)), allow_model_calls=True
    )
    client.start()
    workspace = tmp_path / "permission-work"
    workspace.mkdir()
    session = client.new_session(str(workspace))

    received: list[dict] = []

    def handler(params: dict) -> dict:
        received.append(params)
        return models.permission_selected(models.ALLOW_ONCE)

    client.set_permission_handler(handler)
    result = client.prompt(session["sessionId"], PROMPT_CONTENT)

    assert result["permissionOutcome"] == {
        "outcome": "selected",
        "optionId": models.ALLOW_ONCE,
    }
    assert len(received) == 1
    params = received[0]
    assert params["sessionId"] == session["sessionId"]
    # Only the audited one-shot options are offered.
    assert [option["optionId"] for option in params["options"]] == [
        models.ALLOW_ONCE,
        models.REJECT_ONCE,
    ]
    assert params["toolCall"]["toolCallId"]

    request_event = wait_for_jsonl_event(
        log_dir / "server-events.jsonl",
        lambda record: record.get("event") == "permission_request",
    )
    assert [option["optionId"] for option in request_event["options"]] == [
        models.ALLOW_ONCE,
        models.REJECT_ONCE,
    ]
    decision = wait_for_jsonl_event(
        log_dir / "server-events.jsonl",
        lambda record: record.get("event") == "permission_decision",
    )
    assert decision["outcome"] == {"outcome": "selected", "optionId": models.ALLOW_ONCE}
    assert client.diagnostics()["permission_requests"] == 1


def test_permission_reject_once_round_trip(make_client, tmp_path):
    log_dir = tmp_path / "permission-log"
    client = make_client(
        "permission-request", args=("--log-dir", str(log_dir)), allow_model_calls=True
    )
    client.start()
    workspace = tmp_path / "permission-work"
    workspace.mkdir()
    session = client.new_session(str(workspace))
    client.set_permission_handler(
        lambda params: models.permission_selected(models.REJECT_ONCE)
    )

    result = client.prompt(session["sessionId"], PROMPT_CONTENT)
    assert result["permissionOutcome"] == {
        "outcome": "selected",
        "optionId": models.REJECT_ONCE,
    }
    decisions = _permission_events(log_dir, "permission_decision")
    assert decisions[-1]["outcome"] == {
        "outcome": "selected",
        "optionId": models.REJECT_ONCE,
    }


def test_permission_cancelled_round_trip(make_client, tmp_path):
    log_dir = tmp_path / "permission-log"
    client = make_client(
        "permission-request", args=("--log-dir", str(log_dir)), allow_model_calls=True
    )
    client.start()
    workspace = tmp_path / "permission-work"
    workspace.mkdir()
    session = client.new_session(str(workspace))
    client.set_permission_handler(lambda params: models.permission_cancelled())

    result = client.prompt(session["sessionId"], PROMPT_CONTENT)
    assert result["permissionOutcome"] == {"outcome": "cancelled"}
    decisions = _permission_events(log_dir, "permission_decision")
    assert decisions[-1]["outcome"] == {"outcome": "cancelled"}


def test_permission_without_handler_fails_closed(make_client, tmp_path):
    log_dir = tmp_path / "permission-log"
    client = make_client(
        "permission-request", args=("--log-dir", str(log_dir)), allow_model_calls=True
    )
    client.start()
    workspace = tmp_path / "permission-work"
    workspace.mkdir()
    session = client.new_session(str(workspace))

    result = client.prompt(session["sessionId"], PROMPT_CONTENT)
    assert result["permissionOutcome"] == {"outcome": "cancelled"}
    assert client.diagnostics()["permission_requests"] == 1
    assert client.diagnostics()["permission_handler_errors"] == 0


def test_permission_handler_exception_fails_closed(make_client, tmp_path):
    log_dir = tmp_path / "permission-log"
    client = make_client(
        "permission-request", args=("--log-dir", str(log_dir)), allow_model_calls=True
    )
    client.start()
    workspace = tmp_path / "permission-work"
    workspace.mkdir()
    session = client.new_session(str(workspace))

    def broken_handler(params: dict) -> dict:
        raise RuntimeError("handler failure must not be treated as an approval")

    client.set_permission_handler(broken_handler)
    result = client.prompt(session["sessionId"], PROMPT_CONTENT)
    assert result["permissionOutcome"] == {"outcome": "cancelled"}
    assert client.diagnostics()["permission_handler_errors"] == 1


def test_permission_handler_invalid_payload_fails_closed(make_client, tmp_path):
    log_dir = tmp_path / "permission-log"
    client = make_client(
        "permission-request", args=("--log-dir", str(log_dir)), allow_model_calls=True
    )
    client.start()
    workspace = tmp_path / "permission-work"
    workspace.mkdir()
    session = client.new_session(str(workspace))
    client.set_permission_handler(lambda params: "allow")  # type: ignore[return-value]

    result = client.prompt(session["sessionId"], PROMPT_CONTENT)
    assert result["permissionOutcome"] == {"outcome": "cancelled"}
    assert client.diagnostics()["permission_handler_errors"] == 1


def test_prompt_gate_is_client_side_even_when_server_answers_prompts(
    make_client, tmp_path
):
    log_dir = tmp_path / "permission-log"
    # permission-request scenario would ask for permission if it were prompted,
    # proving the server supports prompts; the client gate must stop it first.
    client = make_client("permission-request", args=("--log-dir", str(log_dir)))
    client.start()
    workspace = tmp_path / "gate-work"
    workspace.mkdir()
    session = client.new_session(str(workspace))
    client.set_permission_handler(lambda params: models.permission_selected(models.ALLOW_ONCE))

    with pytest.raises(ModelCallNotAuthorized):
        client.prompt(session["sessionId"], PROMPT_CONTENT)

    assert client.diagnostics()["permission_requests"] == 0
    assert client.diagnostics()["request_count"] >= 1
    events = read_jsonl(log_dir / "server-events.jsonl")
    assert not [event for event in events if event.get("event") == "permission_request"]
    assert not [event for event in events if event.get("event") == "prompt"]
