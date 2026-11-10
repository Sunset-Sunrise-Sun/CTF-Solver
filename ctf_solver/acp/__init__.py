"""ACP Client transport for the managed DeepSeek Harness ACP server.

Public surface (docs/INTERFACES.md section 3):

* :class:`ctf_solver.acp.client.AcpClient` — the Manager-facing ACP session
  client implementing ``ctf_solver.core.protocols.AcpSessionClient``;
* :class:`ctf_solver.acp.transport.JsonRpcStdioTransport` — ND-JSON JSON-RPC
  2.0 stdio framing, correlation, timeouts and diagnostics;
* :mod:`ctf_solver.acp.models` — shared protocol shape helpers;
* :mod:`ctf_solver.acp.fake_server` — deterministic fake ACP server process
  used by tests (``python -m ctf_solver.acp.fake_server``).
"""

from __future__ import annotations

from .client import AcpClient
from .models import (
    ALLOW_ONCE,
    PROTOCOL_VERSION,
    REJECT_ONCE,
    InitializeInfo,
    SessionInfo,
)
from .transport import JsonRpcStdioTransport

__all__ = [
    "ALLOW_ONCE",
    "PROTOCOL_VERSION",
    "REJECT_ONCE",
    "AcpClient",
    "InitializeInfo",
    "JsonRpcStdioTransport",
    "SessionInfo",
]
