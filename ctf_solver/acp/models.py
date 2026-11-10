"""Small typed helpers shared by the ACP client, transport and fake server.

These helpers own the few protocol facts that the frozen contract pins down so
that the client, the fake server and the tests cannot drift apart:

* JSON-RPC 2.0 / ACP protocol version 1 only;
* ``initialize`` result shape (``protocolVersion``, ``agentInfo``,
  ``mcpCapabilities``, ``sessionCapabilities``);
* ``session/new`` / ``session/resume`` result shape (``sessionId`` required,
  ``configOptions`` preserved);
* the two permission option ids the audited Harness exposes
  (``allow-once`` / ``reject-once``), including the exact response payload the
  permission handler must return.

Nothing here performs I/O or spawns processes; it is a pure contract layer.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Mapping

from ..core.errors import AcpProtocolError, ValidationError

#: The only ACP protocol version Round 1 speaks. A different version is a
#: protocol error, never silently accepted.
PROTOCOL_VERSION = 1
SUPPORTED_PROTOCOL_VERSIONS: frozenset[int] = frozenset({PROTOCOL_VERSION})

#: Audited Harness permission options. The Manager-facing contract only ever
#: needs one-shot decisions; persistent "always" options are deliberately not
#: modelled.
ALLOW_ONCE = "allow-once"
REJECT_ONCE = "reject-once"
PERMISSION_OPTION_IDS: tuple[str, ...] = (ALLOW_ONCE, REJECT_ONCE)

#: JSON-RPC 2.0 standard error codes used by the transport / fake server.
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603
#: ACP-shaped session errors (stable within this package; tests assert on the
#: typed exception, not on the numeric code).
SESSION_NOT_FOUND = -32010
SESSION_BUSY = -32011
PERMISSION_REJECTED = -32012


def _is_mapping(value: Any) -> bool:
    return isinstance(value, Mapping)


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


# ---------------------------------------------------------------------------
# initialize
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class InitializeInfo:
    """Validated ``initialize`` result, stored on the client for diagnostics."""

    protocol_version: int
    agent_info: dict[str, Any] = field(default_factory=dict)
    mcp_capabilities: dict[str, Any] = field(default_factory=dict)
    session_capabilities: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)


def build_initialize_params() -> dict[str, Any]:
    """Build the client half of the ACP ``initialize`` handshake.

    The client advertises no filesystem or terminal capabilities: Round 1 does
    not grant Workers host filesystem/terminal access through ACP, and the
    Manager/Broker owns tool execution instead.
    """

    return {
        "protocolVersion": PROTOCOL_VERSION,
        "clientCapabilities": {
            "fs": {"readTextFile": False, "writeTextFile": False},
            "terminal": False,
            "mcpCapabilities": {"http": False, "sse": False},
        },
        "clientInfo": {"name": "ctf-solver", "version": "0.1.0"},
    }


def parse_initialize_result(result: Any) -> InitializeInfo:
    """Validate the ``initialize`` result; raise ``AcpProtocolError`` otherwise."""

    if not _is_mapping(result):
        raise AcpProtocolError(
            "ACP initialize result must be a JSON object",
            details={"result_type": type(result).__name__},
        )
    version = result.get("protocolVersion")
    if not _is_int(version) or version not in SUPPORTED_PROTOCOL_VERSIONS:
        raise AcpProtocolError(
            f"unsupported ACP protocolVersion {version!r}; expected 1",
            details={"protocol_version": version, "supported": sorted(SUPPORTED_PROTOCOL_VERSIONS)},
        )
    capabilities = result.get("agentCapabilities")
    capabilities = dict(capabilities) if _is_mapping(capabilities) else {}
    mcp_capabilities = capabilities.get("mcpCapabilities")
    if not _is_mapping(mcp_capabilities):
        mcp_capabilities = result.get("mcpCapabilities")
    mcp_capabilities = dict(mcp_capabilities) if _is_mapping(mcp_capabilities) else {}
    session_capabilities = capabilities.get("sessionCapabilities")
    if not _is_mapping(session_capabilities):
        session_capabilities = result.get("sessionCapabilities")
    session_capabilities = (
        dict(session_capabilities) if _is_mapping(session_capabilities) else {}
    )
    agent_info = result.get("agentInfo")
    agent_info = dict(agent_info) if _is_mapping(agent_info) else {}
    return InitializeInfo(
        protocol_version=version,
        agent_info=agent_info,
        mcp_capabilities=mcp_capabilities,
        session_capabilities=session_capabilities,
        raw=dict(result),
    )


# ---------------------------------------------------------------------------
# sessions
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SessionInfo:
    """Validated ``session/new`` or ``session/resume`` result."""

    session_id: str
    config_options: list[dict[str, Any]] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)


def validate_session_id(session_id: Any) -> str:
    if not isinstance(session_id, str) or not session_id.strip():
        raise ValidationError("ACP session_id must be a non-empty string")
    return session_id


def validate_workspace_cwd(cwd: Any) -> str:
    """Validate a session workspace before a request is sent.

    ``session/new``/``session/resume`` must only be issued for an absolute,
    existing directory; a relative or missing cwd is rejected locally so a bad
    Manager call never reaches the Harness process.
    """

    if not isinstance(cwd, str) or not cwd.strip():
        raise ValidationError("ACP session cwd must be a non-empty string")
    if not os.path.isabs(cwd):
        raise ValidationError(f"ACP session cwd must be an absolute path: {cwd!r}")
    if not os.path.isdir(cwd):
        raise ValidationError(f"ACP session cwd does not exist or is not a directory: {cwd!r}")
    return cwd


def validate_mcp_servers(mcp_servers: Any) -> list[dict[str, Any]]:
    """Validate the optional ``session/new.mcpServers`` array.

    Each entry is a plain JSON object (the Worker-scoped ``ctf-exec`` MCP server
    spec). No shell string is ever accepted here, and no extra fields are
    invented: the array is forwarded to the server verbatim.
    """

    if mcp_servers is None:
        return []
    if not isinstance(mcp_servers, (list, tuple)):
        raise ValidationError("mcpServers must be a list of objects")
    validated: list[dict[str, Any]] = []
    for index, server in enumerate(mcp_servers):
        if not _is_mapping(server):
            raise ValidationError(f"mcpServers[{index}] must be an object")
        validated.append(dict(server))
    return validated


def parse_session_result(result: Any, *, method: str) -> SessionInfo:
    """Validate a session result and keep ``configOptions`` intact."""

    if not _is_mapping(result):
        raise AcpProtocolError(
            f"ACP {method} result must be a JSON object",
            details={"method": method, "result_type": type(result).__name__},
        )
    session_id = result.get("sessionId")
    if not isinstance(session_id, str) or not session_id.strip():
        raise AcpProtocolError(
            f"ACP {method} result is missing a non-empty sessionId",
            details={"method": method},
        )
    config_options = result.get("configOptions")
    if config_options is None:
        config_options = []
    if not isinstance(config_options, list) or not all(
        _is_mapping(item) for item in config_options
    ):
        raise AcpProtocolError(
            f"ACP {method} configOptions must be an array of objects",
            details={"method": method},
        )
    return SessionInfo(
        session_id=session_id,
        config_options=[dict(item) for item in config_options],
        raw=dict(result),
    )


def build_new_session_params(cwd: str, mcp_servers: Any = None) -> dict[str, Any]:
    return {"cwd": cwd, "mcpServers": validate_mcp_servers(mcp_servers)}


def build_session_list_params(cwd: str | None = None) -> dict[str, Any]:
    params: dict[str, Any] = {}
    if cwd is not None:
        params["cwd"] = validate_workspace_cwd(cwd)
    return params


def build_resume_params(session_id: str, cwd: str) -> dict[str, Any]:
    return {"sessionId": validate_session_id(session_id), "cwd": cwd}


# ---------------------------------------------------------------------------
# permissions
# ---------------------------------------------------------------------------


def default_permission_options() -> list[dict[str, Any]]:
    """The audited Harness permission choices: one-shot allow or reject."""

    return [
        {"optionId": ALLOW_ONCE, "name": "Allow once", "kind": "allow_once"},
        {"optionId": REJECT_ONCE, "name": "Reject once", "kind": "reject_once"},
    ]


def build_permission_request_params(
    *,
    session_id: str,
    tool_call: Mapping[str, Any] | None = None,
    options: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build server -> client ``session/request_permission`` params."""

    call = dict(tool_call) if tool_call is not None else {
        "toolCallId": "call-synthetic-permission",
        "title": "Synthetic ctf-exec call",
        "kind": "execute",
        "status": "pending",
    }
    return {
        "sessionId": validate_session_id(session_id),
        "toolCall": call,
        "options": list(options) if options is not None else default_permission_options(),
    }


def permission_selected(option_id: str) -> dict[str, Any]:
    """Exact payload a permission handler returns to allow/reject one action."""

    if option_id not in PERMISSION_OPTION_IDS:
        raise ValidationError(
            f"unsupported permission option id {option_id!r}; "
            f"expected one of {', '.join(PERMISSION_OPTION_IDS)}"
        )
    return {"outcome": {"outcome": "selected", "optionId": option_id}}


def permission_cancelled() -> dict[str, Any]:
    """Exact payload a permission handler returns when no decision is made."""

    return {"outcome": {"outcome": "cancelled"}}


def permission_outcome(payload: Any) -> dict[str, Any]:
    """Extract and validate the ``outcome`` object from a permission response.

    Server-side helper (also used by tests) so a malformed reply is rejected
    instead of being recorded as if a human had decided.
    """

    if not _is_mapping(payload):
        raise AcpProtocolError("permission response must be a JSON object")
    outcome = payload.get("outcome")
    if not _is_mapping(outcome):
        raise AcpProtocolError("permission response is missing an outcome object")
    kind = outcome.get("outcome")
    if kind == "cancelled":
        return {"outcome": "cancelled"}
    if kind == "selected":
        option_id = outcome.get("optionId")
        if option_id not in PERMISSION_OPTION_IDS:
            raise AcpProtocolError(
                f"permission selected an unsupported optionId {option_id!r}",
                details={"supported": list(PERMISSION_OPTION_IDS)},
            )
        return {"outcome": "selected", "optionId": option_id}
    raise AcpProtocolError(f"unsupported permission outcome {kind!r}")
