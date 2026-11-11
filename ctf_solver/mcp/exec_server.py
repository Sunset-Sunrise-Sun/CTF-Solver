"""Worker-scoped MCP server exposing exactly one typed tool: ``ctf_exec``.

The Worker (Harness ACP session) receives this MCP server through
``session/new.mcpServers``. Identity (IPC URL and per-Worker bearer token) is
injected through the environment by the Manager; it is never part of tool
arguments, so a Worker cannot impersonate another Task/Worker.

Run::

    python -m ctf_solver.mcp.exec_server

Environment:
    CTF_SOLVER_IPC_URL          tcp://127.0.0.1:<port> of the Manager IPC endpoint
    CTF_SOLVER_WORKER_TOKEN     per-Worker bearer token
    CTF_SOLVER_TASK_ID          optional owning Task id (Manager-injected)
    CTF_SOLVER_IPC_TIMEOUT      optional per-call timeout seconds (default 120)
    CTF_SOLVER_MCP_HANDSHAKE_FILE
                                optional integration-evidence file; written only
                                after the real MCP ``initialize`` request and
                                updated after ``tools/list`` (never at process
                                start), proving protocol-level mount.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import time
from pathlib import Path
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


class HandshakeRecorder:
    """Persist protocol-level evidence from the MCP child spawned by Harness.

    Round 2 P1: writing a file at process start only proves that a process was
    spawned. This recorder only writes after an ``initialize`` request has been
    answered, and enriches the record after ``tools/list``. The evidence thus
    proves that this exact ACP-spawned MCP child completed protocol mounting.
    """

    def __init__(
        self,
        path: str,
        *,
        token: str,
        task_id: str,
        server_name: str,
        server_version: str,
    ) -> None:
        self.path = Path(path)
        self.worker_token_sha256 = hashlib.sha256(token.encode("utf-8")).hexdigest()
        self.task_id = task_id
        self.server_name = server_name
        self.server_version = server_version
        self.initialize_received = False
        self.tools_list_received = False
        self.protocol_version = ""
        self.tool_names: list[str] = []
        self.initialize_at_ms: int | None = None
        self.tools_list_at_ms: int | None = None

    def on_initialize(self, params: dict[str, Any], result: dict[str, Any]) -> None:
        self.initialize_received = True
        self.initialize_at_ms = int(time.time() * 1000)
        self.protocol_version = str(result.get("protocolVersion", ""))
        self._write()

    def on_tools_list(self, result: dict[str, Any]) -> None:
        self.tools_list_received = True
        self.tools_list_at_ms = int(time.time() * 1000)
        names = [
            str(tool.get("name"))
            for tool in result.get("tools", [])
            if isinstance(tool, dict) and tool.get("name")
        ]
        self.tool_names = names
        self._write()

    def _payload(self) -> dict[str, Any]:
        return {
            "pid": os.getpid(),
            # A Windows venv launcher can redirect to a child interpreter, so
            # Popen.pid may be this process's parent rather than its own pid.
            # Recording both lets evidence/tests distinguish launcher and
            # executor without weakening the handshake assertion.
            "parent_pid": os.getppid(),
            "task_id": self.task_id,
            "worker_token_sha256": self.worker_token_sha256,
            "server_name": self.server_name,
            "server_version": self.server_version,
            "initialize_received": self.initialize_received,
            "tools_list_received": self.tools_list_received,
            "protocol_version": self.protocol_version,
            "tool_names": self.tool_names,
            "initialize_at_ms": self.initialize_at_ms,
            "tools_list_at_ms": self.tools_list_at_ms,
        }

    def _write(self) -> None:
        payload = self._payload()
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(self.path.suffix + ".tmp")
            tmp.write_text(
                json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            tmp.replace(self.path)
        except OSError:
            # Evidence failure must never affect the Worker's MCP protocol.
            return


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
    handshake_path = (environ.get("CTF_SOLVER_MCP_HANDSHAKE_FILE") or "").strip()
    recorder: HandshakeRecorder | None = None
    if handshake_path:
        recorder = HandshakeRecorder(
            handshake_path,
            token=token,
            task_id=environ.get("CTF_SOLVER_TASK_ID", "").strip(),
            server_name="ctf-exec",
            server_version="0.1.1",
        )
    client = ManagerIpcClient(ipc_url, token, timeout_s=timeout_s)
    service = ExecToolService(client)
    server = McpServer(
        name="ctf-exec",
        version="0.1.1",
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
        on_initialize=recorder.on_initialize if recorder is not None else None,
        on_tools_list=recorder.on_tools_list if recorder is not None else None,
    )
    return server


def main(argv: list[str] | None = None) -> int:
    server = build_server()
    return server.serve()


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main(sys.argv[1:]))
