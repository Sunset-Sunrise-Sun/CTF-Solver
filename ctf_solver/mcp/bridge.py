"""Loopback IPC client used by the Worker-scoped ``ctf-exec`` MCP server.

The Manager exposes a tiny ND-JSON JSON-RPC endpoint on loopback. Each Worker
gets an unguessable token that is injected into its ACP session ``mcpServers``
environment; tool arguments can never override identity.
"""

from __future__ import annotations

import json
import socket
from typing import Any

from .protocol import McpToolError

DEFAULT_TIMEOUT_S = 120.0


class ManagerIpcClient:
    def __init__(
        self,
        ipc_url: str,
        worker_token: str,
        *,
        timeout_s: float = DEFAULT_TIMEOUT_S,
    ) -> None:
        if not ipc_url:
            raise ValueError("ipc_url is required")
        if not worker_token:
            raise ValueError("worker_token is required")
        self.ipc_url = ipc_url
        self.worker_token = worker_token
        self.timeout_s = float(timeout_s)
        self._host, self._port = parse_ipc_url(ipc_url)

    def _rpc(self, method: str, params: dict[str, Any] | None = None, *, timeout_s: float | None = None) -> Any:
        request = {
            "id": 1,
            "method": method,
            "token": self.worker_token,
            "params": params or {},
        }
        payload = json.dumps(request, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n"
        timeout = self.timeout_s if timeout_s is None else float(timeout_s)
        try:
            with socket.create_connection((self._host, self._port), timeout=timeout) as sock:
                sock.settimeout(timeout)
                sock.sendall(payload)
                buffer = bytearray()
                while b"\n" not in buffer:
                    chunk = sock.recv(65536)
                    if not chunk:
                        break
                    buffer.extend(chunk)
        except OSError as exc:
            raise McpToolError(
                f"Manager IPC unavailable: {exc}",
                reason_code="ipc_unavailable",
                details={"url": self.ipc_url},
            ) from exc
        line = bytes(buffer).split(b"\n", 1)[0]
        if not line:
            raise McpToolError(
                "Manager IPC returned an empty response",
                reason_code="ipc_protocol_error",
            )
        try:
            response = json.loads(line.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise McpToolError(
                f"Manager IPC returned malformed JSON: {exc}",
                reason_code="ipc_protocol_error",
            ) from exc
        if not isinstance(response, dict):
            raise McpToolError("Manager IPC response is not an object", reason_code="ipc_protocol_error")
        if response.get("error"):
            error = response["error"]
            if isinstance(error, dict):
                raise McpToolError(
                    str(error.get("message", "Manager IPC error")),
                    reason_code=str(error.get("reason_code", "ipc_error")),
                    details={"data": error.get("data"), "details": error.get("details")},
                )
            raise McpToolError(str(error), reason_code="ipc_error")
        return response.get("result")

    def ping(self) -> dict[str, Any]:
        result = self._rpc("ping", {}, timeout_s=10.0)
        return result if isinstance(result, dict) else {"ok": True}

    def worker_info(self) -> dict[str, Any]:
        result = self._rpc("worker_info", {}, timeout_s=10.0)
        return result if isinstance(result, dict) else {}

    def execute(self, request: dict[str, Any]) -> dict[str, Any]:
        result = self._rpc("ctf_exec", request)
        if not isinstance(result, dict):
            raise McpToolError("Manager IPC execute result is not an object", reason_code="ipc_protocol_error")
        return result


def parse_ipc_url(url: str) -> tuple[str, int]:
    """Parse ``tcp://host:port`` (also accepts bare ``host:port``)."""

    value = url.strip()
    if value.startswith("tcp://"):
        value = value[len("tcp://") :]
    if "/" in value:
        value = value.split("/", 1)[0]
    if ":" not in value:
        raise ValueError(f"invalid IPC url (expected tcp://host:port): {url!r}")
    host, port_text = value.rsplit(":", 1)
    host = host.strip("[]")
    if not host:
        raise ValueError(f"invalid IPC url host: {url!r}")
    try:
        port = int(port_text)
    except ValueError as exc:
        raise ValueError(f"invalid IPC url port: {url!r}") from exc
    if not (1 <= port <= 65535):
        raise ValueError(f"invalid IPC url port: {url!r}")
    return host, port
