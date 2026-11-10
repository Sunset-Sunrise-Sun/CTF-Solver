"""Pure contract-level tests for the ACP model helpers (no subprocesses).

These cover the validation/negative paths the client relies on: protocol
version negotiation, session result shapes, workspace/mcpServers validation and
the exact permission payloads from docs/INTERFACES.md section 3.
"""

from __future__ import annotations

import pytest

from ctf_solver.acp import models
from ctf_solver.core.errors import AcpProtocolError, ValidationError


def test_protocol_version_is_one():
    assert models.PROTOCOL_VERSION == 1
    assert models.SUPPORTED_PROTOCOL_VERSIONS == {1}


def test_initialize_params_advertise_no_filesystem_or_terminal_capabilities():
    params = models.build_initialize_params()
    assert params["protocolVersion"] == 1
    assert params["clientCapabilities"]["fs"] == {
        "readTextFile": False,
        "writeTextFile": False,
    }
    assert params["clientCapabilities"]["terminal"] is False
    assert params["clientInfo"]["name"] == "ctf-solver"


def test_parse_initialize_result_accepts_nested_capabilities():
    info = models.parse_initialize_result(
        {
            "protocolVersion": 1,
            "agentCapabilities": {
                "mcpCapabilities": {"http": False, "sse": True},
                "sessionCapabilities": {"new": True, "list": True},
            },
            "agentInfo": {"name": "server", "version": "9"},
        }
    )
    assert info.protocol_version == 1
    assert info.mcp_capabilities == {"http": False, "sse": True}
    assert info.session_capabilities == {"new": True, "list": True}
    assert info.agent_info == {"name": "server", "version": "9"}


def test_parse_initialize_result_accepts_flat_capabilities():
    info = models.parse_initialize_result(
        {
            "protocolVersion": 1,
            "mcpCapabilities": {"http": True},
            "sessionCapabilities": {"close": True},
        }
    )
    assert info.mcp_capabilities == {"http": True}
    assert info.session_capabilities == {"close": True}
    assert info.agent_info == {}


@pytest.mark.parametrize(
    "result",
    [
        None,
        [],
        "initialize-result",
        {},
        {"protocolVersion": 2},
        {"protocolVersion": "1"},
        {"protocolVersion": True},
    ],
)
def test_parse_initialize_result_rejects_bad_shapes_and_versions(result):
    with pytest.raises(AcpProtocolError):
        models.parse_initialize_result(result)


@pytest.mark.parametrize(
    "result",
    [
        None,
        {},
        {"sessionId": ""},
        {"sessionId": 42},
        {"sessionId": "sess-1", "configOptions": "not-a-list"},
        {"sessionId": "sess-1", "configOptions": [1, 2]},
    ],
)
def test_parse_session_result_rejects_invalid_results(result):
    with pytest.raises(AcpProtocolError):
        models.parse_session_result(result, method="session/new")


def test_parse_session_result_preserves_config_options():
    info = models.parse_session_result(
        {
            "sessionId": "sess-1",
            "configOptions": [{"id": "model", "currentValue": "fake"}],
            "modes": {"currentModeId": "code"},
        },
        method="session/new",
    )
    assert info.session_id == "sess-1"
    assert info.config_options == [{"id": "model", "currentValue": "fake"}]
    assert info.raw["modes"] == {"currentModeId": "code"}


def test_validate_workspace_cwd(tmp_path):
    workspace = tmp_path / "work"
    workspace.mkdir()
    assert models.validate_workspace_cwd(str(workspace)) == str(workspace)
    with pytest.raises(ValidationError):
        models.validate_workspace_cwd("relative/work")
    with pytest.raises(ValidationError):
        models.validate_workspace_cwd(str(tmp_path / "missing"))
    with pytest.raises(ValidationError):
        models.validate_workspace_cwd("")
    with pytest.raises(ValidationError):
        models.validate_workspace_cwd(None)


def test_validate_mcp_servers_rejects_shell_strings_and_non_objects():
    with pytest.raises(ValidationError):
        models.validate_mcp_servers("python -m x")
    with pytest.raises(ValidationError):
        models.validate_mcp_servers(["python -m x"])
    with pytest.raises(ValidationError):
        models.validate_mcp_servers([{"name": "x"}, "bad"])

    spec = {"name": "ctf-exec", "args": ["-m", "ctf_solver.mcp.exec_server"]}
    validated = models.validate_mcp_servers([spec])
    assert validated == [spec]
    assert validated[0] is not spec  # defensive copy, caller cannot mutate later
    assert models.validate_mcp_servers(None) == []


def test_validate_session_id():
    assert models.validate_session_id("sess-1") == "sess-1"
    for bad in ("", "   ", None, 7):
        with pytest.raises(ValidationError):
            models.validate_session_id(bad)


def test_permission_payloads_are_exact():
    assert models.default_permission_options() == [
        {"optionId": "allow-once", "name": "Allow once", "kind": "allow_once"},
        {"optionId": "reject-once", "name": "Reject once", "kind": "reject_once"},
    ]
    assert models.permission_selected(models.ALLOW_ONCE) == {
        "outcome": {"outcome": "selected", "optionId": "allow-once"}
    }
    assert models.permission_selected(models.REJECT_ONCE) == {
        "outcome": {"outcome": "selected", "optionId": "reject-once"}
    }
    assert models.permission_cancelled() == {"outcome": {"outcome": "cancelled"}}
    # Persistent/blanket permission options are not modelled in Round 1.
    with pytest.raises(ValidationError):
        models.permission_selected("allow-always")


def test_permission_outcome_parsing():
    assert models.permission_outcome(
        {"outcome": {"outcome": "selected", "optionId": "allow-once"}}
    ) == {"outcome": "selected", "optionId": "allow-once"}
    assert models.permission_outcome(
        {"outcome": {"outcome": "cancelled"}}
    ) == {"outcome": "cancelled"}
    for bad in (
        None,
        {},
        {"outcome": {}},
        {"outcome": {"outcome": "selected"}},
        {"outcome": {"outcome": "selected", "optionId": "allow-always"}},
        {"outcome": {"outcome": "maybe"}},
    ):
        with pytest.raises(AcpProtocolError):
            models.permission_outcome(bad)


def test_permission_request_params_shape():
    params = models.build_permission_request_params(session_id="sess-1")
    assert params["sessionId"] == "sess-1"
    assert [option["optionId"] for option in params["options"]] == [
        "allow-once",
        "reject-once",
    ]
    assert params["toolCall"]["toolCallId"]
    with pytest.raises(ValidationError):
        models.build_permission_request_params(session_id="")
