"""Worker-scoped MCP server exposing exactly one typed tool: ``ctf_exec``.

The Worker (Harness ACP session) receives this MCP server through
``session/new.mcpServers``. Identity (IPC URL and per-Worker bearer token) is
injected through the environment by the Manager; it is never part of tool
arguments, so a Worker cannot impersonate another Task/Worker.

Run::

    python -m ctf_solver.mcp.exec_server

Environment:
    CTF_SOLVER_IPC_URL       tcp://127.0.0.1:<port> of the Manager IPC endpoint
    CTF_SOLVER_WORKER_TOKEN  per-Worker bearer token
    CTF_SOLVER_IPC_TIMEOUT   optional per-call timeout seconds (default 120)
"""

from __future__ import annotations

import os
import sys
from typing import Any

from ..core.errors import DenyReason, ValidationError
from .bridge import ManagerIpcClient
from .protocol import McpServer, McpTool, McpToolError

EXEC_TOOL_NAME = "ctf_exec"

_CTF_EXEC_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "task_id": {"type": "string", "description": "Owning Task ID (from Manager)."},
        "worker_id": {"type": "string", "description": "Owning Worker ID (from Manager)."},
        "step_id": {
            "type": "string",
            "description": "Worker-chosen step identifier (alphanumeric, dot, dash, underscore; <=64).",
        },
        "tool_name": {
            "type": "string",
            "description": "Typed allowlisted tool identifier from the Manager tool catalogue.",
        },
        "tool_version": {
            "type": "string",
            "description": "Optional exact tool-version constraint.",
        },
        "argv": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Argument vector. Never a shell command string.",
        },
        "cwd": {
            "type": "string",
            "description": "Absolute working directory inside the Task workspace.",
        },
        "input_files": {
            "type": "array",
            "description": "Input file paths (relative to cwd) with SHA-256 hashes.",
            "items": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "sha256": {"type": "string"},
                },
                "required": ["path"],
            },
        },
        "output_paths": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Declared output paths (relative to cwd, inside the workspace).",
        },
        "network_grant_id": {"type": "string"},
        "approval_id": {"type": "string"},
        "network_target": {
            "type": "object",
            "properties": {
                "host": {"type": "string"},
                "port": {"type": "integer"},
                "protocol": {"type": "string"},
                "method": {"type": "string"},
                "path": {"type": "string"},
            },
            "required": ["host"],
        },
        "timeout_s": {"type": "number", "description": "Wall-clock timeout in seconds (0.1-600)."},
        "tier": {"type": "integer", "description": "Requested execution tier (0/1/2)."},
        "max_output_bytes": {"type": "integer"},
    },
    "required": ["task_id", "worker_id", "step_id", "tool_name", "argv", "cwd"],
    "additionalProperties": False,
}


class ExecToolService:
    def __init__(self, client: ManagerIpcClient) -> None:
        self.client = client

    def ctf_exec(self, arguments: dict[str, Any]) -> dict[str, Any]:
        # Structural validation is repeated Manager-side; the MCP layer only
        # forwards a typed payload and never builds a command string.
        if not isinstance(arguments.get("argv"), list):
            raise McpToolError(
                "argv must be an array of strings",
                reason_code=DenyReason.ARGV_SCHEMA_VIOLATION.value,
            )
        try:
            return self.client.execute(arguments)
        except McpToolError:
            raise
        except ValidationError as exc:
            raise McpToolError(exc.message, reason_code=exc.reason_code, details=exc.details) from exc


def build_server(env: dict[str, str] | None = None) -> McpServer:
    environ = dict(os.environ if env is None else env)
    ipc_url = environ.get("CTF_SOLVER_IPC_URL", "").strip()
    token = environ.get("CTF_SOLVER_WORKER_TOKEN", "").strip()
    timeout_s = float(environ.get("CTF_SOLVER_IPC_TIMEOUT", "120") or "120")
    if not ipc_url or not token:
        raise SystemExit(
            "ctf-exec MCP server requires CTF_SOLVER_IPC_URL and CTF_SOLVER_WORKER_TOKEN "
            "in the environment (injected by the Manager for this Worker session)"
        )
    client = ManagerIpcClient(ipc_url, token, timeout_s=timeout_s)
    service = ExecToolService(client)
    server = McpServer(
        name="ctf-exec",
        version="0.1.0",
        instructions=(
            "Typed CTF execution interface. Call ctf_exec with an allowlisted tool id and an "
            "argv array. This server does not expose a shell and cannot bypass the Manager Broker."
        ),
        tools=[
            McpTool(
                name=EXEC_TOOL_NAME,
                description=(
                    "Execute one typed, allowlisted trusted tool inside the Task workspace. "
                    "Returns an execution record including status, exit code, argv, cwd, "
                    "stdout/stderr previews and CAS refs, timestamps, and denials."
                ),
                input_schema=_CTF_EXEC_SCHEMA,
                annotations={"readOnlyHint": False, "destructiveHint": False},
                handler=service.ctf_exec,
            )
        ],
    )
    return server


def main(argv: list[str] | None = None) -> int:
    server = build_server()
    return server.serve()


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main(sys.argv[1:]))
