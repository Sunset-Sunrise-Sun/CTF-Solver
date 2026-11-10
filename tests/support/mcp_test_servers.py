"""Test-only MCP servers run as subprocesses by Lead tests."""

from __future__ import annotations

import sys
import time

from ctf_solver.mcp.protocol import McpServer, McpTool, McpToolError


def _echo(arguments: dict) -> dict:
    return {"echo": arguments.get("message", ""), "count": len(arguments.get("message", ""))}


def _fail(_arguments: dict) -> dict:
    raise McpToolError("synthetic tool failure", reason_code="synthetic_failure", details={"hint": "expected"})


def _slow(arguments: dict) -> dict:
    time.sleep(float(arguments.get("delay", 0.25)))
    return {"slept": True}


def _large(arguments: dict) -> dict:
    size = int(arguments.get("size", 100_000))
    return {"blob": "x" * size}


def echo_server() -> McpServer:
    return McpServer(
        name="mcp-echo",
        version="0.0.1",
        tools=[
            McpTool(
                name="echo",
                description="Echo a message.",
                input_schema={
                    "type": "object",
                    "properties": {"message": {"type": "string"}},
                    "required": ["message"],
                },
                handler=_echo,
            ),
            McpTool(
                name="fail",
                description="Always fail with a controlled tool error.",
                input_schema={"type": "object", "properties": {}},
                handler=_fail,
            ),
            McpTool(
                name="slow",
                description="Sleep then answer.",
                input_schema={
                    "type": "object",
                    "properties": {"delay": {"type": "number"}},
                },
                handler=_slow,
            ),
            McpTool(
                name="large",
                description="Return a large payload.",
                input_schema={
                    "type": "object",
                    "properties": {"size": {"type": "integer"}},
                },
                handler=_large,
            ),
        ],
    )


def manager_server() -> McpServer:
    from ctf_solver.mcp.manager_server import build_server

    from .manager_stub import StubManager

    return build_server(StubManager())


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    target = args[0] if args else "echo"
    if target == "manager":
        return manager_server().serve()
    if target == "echo":
        return echo_server().serve()
    print(f"unknown test server: {target}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
