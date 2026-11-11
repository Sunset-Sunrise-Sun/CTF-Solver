"""Tiny MCP stdio probe used by Round 2 mount/discovery diagnostics.

On startup it writes a handshake JSON file (env ``PROBE_HANDSHAKE_FILE``), then
speaks minimal ND-JSON MCP so the Harness MCP client can complete
``server/discover`` / ``initialize`` / ``tools/list`` without a model call.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path


def _write_handshake() -> None:
    target = os.environ.get("PROBE_HANDSHAKE_FILE", "")
    if not target:
        return
    path = Path(target)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps({"pid": os.getpid(), "started_at_ms": int(time.time() * 1000), "probe": True}) + "\n",
        encoding="utf-8",
    )


def _write(chunk: dict) -> None:
    sys.stdout.write(json.dumps(chunk, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def main() -> int:
    _write_handshake()
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except ValueError:
            continue
        method = message.get("method")
        rpc_id = message.get("id")
        if method in ("server/discover", "discover"):
            result = {
                "serverInfo": {"name": "probe", "version": "0.0.1"},
                "capabilities": {"tools": {}},
                "protocolVersions": ["2025-06-18"],
            }
        elif method == "initialize":
            result = {
                "protocolVersion": "2025-06-18",
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "probe", "version": "0.0.1"},
            }
        elif method in ("notifications/initialized", "notifications/cancelled"):
            continue
        elif method == "tools/list":
            result = {"tools": [{"name": "probe", "description": "probe", "inputSchema": {"type": "object"}}]}
        elif method == "ping":
            result = {}
        else:
            result = {}
        if rpc_id is not None:
            _write({"jsonrpc": "2.0", "id": rpc_id, "result": result})
    return 0


if __name__ == "__main__":
    sys.exit(main())
