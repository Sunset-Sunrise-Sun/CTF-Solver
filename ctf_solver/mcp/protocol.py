"""Minimal MCP (Model Context Protocol) stdio server framework.

Round 1 needs a small, deterministic, dependency-free MCP server implementation
for two surfaces:

* Manager control tools (main-conversation side in Round 2),
* the Worker-scoped ``ctf-exec`` tool.

The transport is newline-delimited JSON-RPC 2.0 on stdio (the audited Harness
MCP client uses stdio and calls ``server/discover`` -> ``initialize`` ->
``notifications/initialized`` -> ``tools/list`` -> ``tools/call``).

Design constraints:
* stdout carries protocol messages only; diagnostics go to stderr.
* tool failures are returned as ``isError`` tool results, not protocol crashes;
* malformed requests produce JSON-RPC error responses and keep the server alive;
* stdin EOF shuts the server down cleanly with exit code 0.
"""

from __future__ import annotations

import json
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Callable, BinaryIO, TextIO

PROTOCOL_VERSION = "2025-06-18"
SUPPORTED_PROTOCOL_VERSIONS = ("2024-11-05", "2025-03-26", "2025-06-18")

PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603

SERVER_NAME = "ctf-solver"
SERVER_VERSION = "0.1.0"


class McpToolError(Exception):
    """A controlled tool failure surfaced to the caller as ``isError`` content."""

    def __init__(self, message: str, *, reason_code: str = "tool_error", details: dict[str, Any] | None = None):
        super().__init__(message)
        self.message = message
        self.reason_code = reason_code
        self.details = details or {}

    def to_payload(self) -> dict[str, Any]:
        return {
            "error": type(self).__name__,
            "reason_code": self.reason_code,
            "message": self.message,
            "details": self.details,
        }


@dataclass
class McpTool:
    name: str
    description: str
    input_schema: dict[str, Any]
    handler: Callable[[dict[str, Any]], Any]
    annotations: dict[str, Any] = field(default_factory=dict)

    def describe(self) -> dict[str, Any]:
        entry: dict[str, Any] = {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.input_schema,
        }
        if self.annotations:
            entry["annotations"] = self.annotations
        return entry


@dataclass
class ToolCallOutcome:
    payload: Any
    is_error: bool = False


class JsonRpcProtocolError(Exception):
    def __init__(self, code: int, message: str, data: Any = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.data = data


def _json_default(value: Any) -> Any:
    to_dict = getattr(value, "to_dict", None)
    if callable(to_dict):
        return to_dict()
    raise TypeError(f"object of type {type(value).__name__} is not JSON serializable")


def json_dumps(value: Any) -> str:
    return json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), default=_json_default
    )


class McpServer:
    """A small synchronous MCP server over newline-delimited JSON-RPC 2.0."""

    def __init__(
        self,
        *,
        name: str = SERVER_NAME,
        version: str = SERVER_VERSION,
        tools: list[McpTool] | None = None,
        instructions: str | None = None,
        max_workers: int = 4,
    ) -> None:
        self.name = name
        self.version = version
        self.instructions = instructions
        self.tools = {tool.name: tool for tool in tools or []}
        self._max_workers = max(1, int(max_workers))
        self._write_lock = threading.Lock()
        self._pool = ThreadPoolExecutor(max_workers=self._max_workers, thread_name_prefix="mcp")
        self._stopped = threading.Event()
        self._out: TextIO | None = None
        self._in: TextIO | None = None
        self._pending = 0
        self._pending_lock = threading.Lock()

    # -- registration -------------------------------------------------

    def register_tool(self, tool: McpTool) -> None:
        self.tools[tool.name] = tool

    # -- protocol -----------------------------------------------------

    def _capabilities(self) -> dict[str, Any]:
        return {"tools": {"listChanged": False}}

    def _server_info(self) -> dict[str, Any]:
        return {"name": self.name, "version": self.version}

    def _discover_result(self) -> dict[str, Any]:
        return {
            "serverInfo": self._server_info(),
            "capabilities": self._capabilities(),
            "protocolVersions": list(SUPPORTED_PROTOCOL_VERSIONS),
        }

    def _initialize_result(self, params: dict[str, Any]) -> dict[str, Any]:
        requested = params.get("protocolVersion")
        version = requested if requested in SUPPORTED_PROTOCOL_VERSIONS else PROTOCOL_VERSION
        result: dict[str, Any] = {
            "protocolVersion": version,
            "capabilities": self._capabilities(),
            "serverInfo": self._server_info(),
        }
        if self.instructions:
            result["instructions"] = self.instructions
        return result

    def _tools_list_result(self) -> dict[str, Any]:
        return {"tools": [tool.describe() for tool in self.tools.values()]}

    def _validate_arguments(self, tool: McpTool, arguments: Any) -> dict[str, Any]:
        if arguments is None:
            arguments = {}
        if not isinstance(arguments, dict):
            raise JsonRpcProtocolError(INVALID_PARAMS, "tools/call arguments must be an object")
        schema = tool.input_schema or {}
        required = schema.get("required") or []
        missing = [key for key in required if key not in arguments]
        if missing:
            raise JsonRpcProtocolError(
                INVALID_PARAMS,
                f"missing required argument(s) for tool {tool.name}: {', '.join(missing)}",
                data={"missing": missing},
            )
        return arguments

    def _call_tool(self, params: dict[str, Any]) -> dict[str, Any]:
        name = params.get("name")
        if not isinstance(name, str):
            raise JsonRpcProtocolError(INVALID_PARAMS, "tools/call requires a string name")
        tool = self.tools.get(name)
        if tool is None:
            raise JsonRpcProtocolError(INVALID_PARAMS, f"unknown tool: {name}")
        arguments = self._validate_arguments(tool, params.get("arguments"))
        try:
            payload = tool.handler(arguments)
        except McpToolError as exc:
            return {
                "content": [{"type": "text", "text": json_dumps(exc.to_payload())}],
                "isError": True,
            }
        except JsonRpcProtocolError:
            raise
        except Exception as exc:  # noqa: BLE001 - tool failures must not kill the server
            return {
                "content": [
                    {
                        "type": "text",
                        "text": json_dumps(
                            {
                                "error": type(exc).__name__,
                                "reason_code": "tool_internal_error",
                                "message": str(exc),
                            }
                        ),
                    }
                ],
                "isError": True,
            }
        return {
            "content": [{"type": "text", "text": json_dumps(payload)}],
            "isError": False,
        }

    def _handle_request(self, method: str, params: dict[str, Any]) -> Any:
        if method in ("server/discover", "discover"):
            return self._discover_result()
        if method == "initialize":
            return self._initialize_result(params)
        if method == "ping":
            return {}
        if method == "tools/list":
            return self._tools_list_result()
        if method == "tools/call":
            return self._call_tool(params)
        if method == "notifications/initialized":
            return None
        raise JsonRpcProtocolError(METHOD_NOT_FOUND, f"method not found: {method}")

    # -- IO -----------------------------------------------------------

    def _write(self, message: dict[str, Any]) -> None:
        line = json_dumps(message)
        with self._write_lock:
            assert self._out is not None
            self._out.write(line + "\n")
            self._out.flush()

    def _error_response(self, rpc_id: Any, code: int, message: str, data: Any = None) -> dict[str, Any]:
        error: dict[str, Any] = {"code": code, "message": message}
        if data is not None:
            error["data"] = data
        return {"jsonrpc": "2.0", "id": rpc_id, "error": error}

    def _process_line(self, line: str) -> None:
        stripped = line.strip()
        if not stripped:
            return
        rpc_id: Any = None
        try:
            message = json.loads(stripped)
        except (ValueError, TypeError):
            self._write(self._error_response(None, PARSE_ERROR, "invalid JSON"))
            return
        if not isinstance(message, dict):
            self._write(self._error_response(None, INVALID_REQUEST, "request must be a JSON object"))
            return
        rpc_id = message.get("id")
        method = message.get("method")
        params = message.get("params") or {}
        if not isinstance(method, str):
            if "id" in message:
                self._write(self._error_response(rpc_id, INVALID_REQUEST, "missing method"))
            return
        if not isinstance(params, dict):
            if "id" in message:
                self._write(self._error_response(rpc_id, INVALID_PARAMS, "params must be an object"))
            return
        is_notification = "id" not in message
        if is_notification:
            try:
                self._handle_request(method, params)
            except Exception:  # noqa: BLE001 - notifications never get responses
                pass
            return

        def run() -> None:
            try:
                result = self._handle_request(method, params)
            except JsonRpcProtocolError as exc:
                self._write(self._error_response(rpc_id, exc.code, exc.message, exc.data))
                return
            except Exception as exc:  # noqa: BLE001
                self._write(self._error_response(rpc_id, INTERNAL_ERROR, str(exc)))
                return
            if result is None and method == "notifications/initialized":
                return
            self._write({"jsonrpc": "2.0", "id": rpc_id, "result": result})

        self._pool.submit(run)

    def serve(self, stdin: TextIO | None = None, stdout: TextIO | None = None) -> int:
        self._in = stdin or sys.stdin
        self._out = stdout or sys.stdout
        try:
            for line in self._in:
                if self._stopped.is_set():
                    break
                self._process_line(line)
        finally:
            self._stopped.set()
            self._pool.shutdown(wait=True)
        return 0

    def stop(self) -> None:
        self._stopped.set()


def build_success(payload: Any) -> ToolCallOutcome:
    return ToolCallOutcome(payload=payload, is_error=False)
