"""Small MCP stdio client used by tests and by local diagnostics.

This is not the Harness MCP client; it exists so Round 1 can exercise the
Manager control and Worker ``ctf-exec`` MCP servers deterministically without a
model call.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from collections import deque
from typing import Any, Mapping

from .protocol import INVALID_PARAMS, json_dumps


class McpClientError(Exception):
    pass


class McpClientTimeout(McpClientError):
    pass


class McpProcessExited(McpClientError):
    pass


class McpRemoteError(McpClientError):
    def __init__(self, message: str, *, code: int | None = None, data: Any = None):
        super().__init__(message)
        self.code = code
        self.data = data


class _Pending:
    __slots__ = ("event", "result", "error")

    def __init__(self) -> None:
        self.event = threading.Event()
        self.result: Any = None
        self.error: dict[str, Any] | None = None


class McpStdioClient:
    """Newline-delimited JSON-RPC 2.0 client over a child process' stdio."""

    def __init__(
        self,
        command: list[str],
        *,
        env: Mapping[str, str] | None = None,
        cwd: str | os.PathLike[str] | None = None,
        request_timeout: float = 60.0,
        stderr_path: str | None = None,
    ) -> None:
        if not command:
            raise ValueError("command must not be empty")
        self.command = [str(item) for item in command]
        self.env = dict(env) if env is not None else None
        self.cwd = str(cwd) if cwd is not None else None
        self.request_timeout = request_timeout
        self.stderr_path = stderr_path
        self._proc: subprocess.Popen | None = None
        self._reader: threading.Thread | None = None
        self._stderr_reader: threading.Thread | None = None
        self._write_lock = threading.Lock()
        self._pending: dict[int, _Pending] = {}
        self._pending_lock = threading.Lock()
        self._next_id = 1
        self._stderr_tail: deque[str] = deque(maxlen=200)
        self._stderr_bytes = 0
        self._exit_code: int | None = None
        self._closed = threading.Event()
        self._malformed_lines = 0

    # -- lifecycle ----------------------------------------------------

    @property
    def pid(self) -> int | None:
        """OS process id of the MCP child, once started (evidence/diagnostics)."""

        proc = self._proc
        return int(proc.pid) if proc is not None else None

    def start(self) -> None:
        if self._proc is not None:
            return
        self._proc = subprocess.Popen(
            self.command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=self.cwd,
            env=self.env,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )
        self._reader = threading.Thread(target=self._read_loop, name="mcp-client-reader", daemon=True)
        self._reader.start()
        self._stderr_reader = threading.Thread(
            target=self._stderr_loop, name="mcp-client-stderr", daemon=True
        )
        self._stderr_reader.start()

    def close(self, timeout: float = 10.0) -> None:
        proc = self._proc
        self._closed.set()
        if proc is not None:
            try:
                if proc.stdin and not proc.stdin.closed:
                    proc.stdin.close()
            except OSError:
                pass
            try:
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                try:
                    proc.kill()
                except OSError:
                    pass
                try:
                    proc.wait(timeout=timeout)
                except subprocess.TimeoutExpired:  # pragma: no cover
                    pass
            self._exit_code = proc.returncode
        self._fail_pending(McpProcessExited("MCP client closed"))
        if self._reader is not None:
            self._reader.join(timeout=timeout)
        if self._stderr_reader is not None:
            self._stderr_reader.join(timeout=timeout)

    @property
    def pid(self) -> int | None:
        return self._proc.pid if self._proc is not None else None

    @property
    def exit_code(self) -> int | None:
        return self._exit_code if self._exit_code is not None else (self._proc.returncode if self._proc else None)

    def diagnostics(self) -> dict[str, Any]:
        return {
            "pid": self.pid,
            "exit_code": self.exit_code,
            "closed": self._closed.is_set(),
            "malformed_lines": self._malformed_lines,
            "stderr_tail": "".join(self._stderr_tail),
            "pending_requests": len(self._pending),
        }

    # -- IO -----------------------------------------------------------

    def _read_loop(self) -> None:
        assert self._proc is not None and self._proc.stdout is not None
        for line in self._proc.stdout:
            if self._closed.is_set():
                break
            stripped = line.strip()
            if not stripped:
                continue
            try:
                message = json.loads(stripped)
            except (ValueError, TypeError):
                self._malformed_lines += 1
                continue
            if not isinstance(message, dict) or "id" not in message:
                continue
            rpc_id = message.get("id")
            try:
                pending = self._pending.pop(int(rpc_id), None)
            except (TypeError, ValueError):
                pending = None
            if pending is None:
                continue
            if "error" in message:
                pending.error = message["error"] if isinstance(message["error"], dict) else {"message": str(message["error"])}
            else:
                pending.result = message.get("result")
            pending.event.set()
        self._exit_code = self._proc.returncode if self._proc else None
        self._fail_pending(McpProcessExited("MCP server process exited"))

    def _stderr_loop(self) -> None:
        assert self._proc is not None and self._proc.stderr is not None
        for chunk in iter(lambda: self._proc.stderr.readline(), ""):
            if chunk:
                self._stderr_tail.append(chunk)
                self._stderr_bytes += len(chunk)
                if self.stderr_path:
                    try:
                        with open(self.stderr_path, "a", encoding="utf-8") as handle:
                            handle.write(chunk)
                    except OSError:
                        pass

    def _fail_pending(self, error: Exception) -> None:
        with self._pending_lock:
            pending_items = list(self._pending.values())
            self._pending.clear()
        for pending in pending_items:
            pending.error = {"code": -32000, "message": str(error)}
            pending.event.set()

    def _send(self, message: dict[str, Any]) -> None:
        if self._proc is None or self._proc.stdin is None:
            raise McpProcessExited("MCP client is not started")
        line = json_dumps(message)
        with self._write_lock:
            try:
                self._proc.stdin.write(line + "\n")
                self._proc.stdin.flush()
            except (BrokenPipeError, OSError) as exc:
                raise McpProcessExited(f"MCP server stdin is closed: {exc}") from exc

    def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        message: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            message["params"] = params
        self._send(message)

    def request(self, method: str, params: dict[str, Any] | None = None, *, timeout: float | None = None) -> Any:
        if self._proc is None:
            self.start()
        with self._pending_lock:
            rpc_id = self._next_id
            self._next_id += 1
            pending = _Pending()
            self._pending[rpc_id] = pending
        message: dict[str, Any] = {"jsonrpc": "2.0", "id": rpc_id, "method": method}
        if params is not None:
            message["params"] = params
        self._send(message)
        deadline = time.monotonic() + (timeout if timeout is not None else self.request_timeout)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                with self._pending_lock:
                    self._pending.pop(rpc_id, None)
                raise McpClientTimeout(f"no response to {method!r} within timeout")
            if pending.event.wait(min(remaining, 0.2)):
                break
            if self._proc.poll() is not None and not pending.event.is_set():
                # Give the reader thread a final chance to flush the response.
                if pending.event.wait(0.1):
                    break
                with self._pending_lock:
                    self._pending.pop(rpc_id, None)
                raise McpProcessExited(
                    f"MCP server exited (code {self._proc.returncode}) while waiting for {method!r}"
                )
        if pending.error is not None:
            raise McpRemoteError(
                str(pending.error.get("message", "remote error")),
                code=pending.error.get("code"),
                data=pending.error.get("data"),
            )
        return pending.result

    # -- MCP helpers --------------------------------------------------

    def initialize(self, *, client_info: dict[str, Any] | None = None) -> dict[str, Any]:
        try:
            discovery = self.request("server/discover", {}, timeout=5.0)
        except McpRemoteError:
            discovery = None
        params: dict[str, Any] = {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": client_info or {"name": "ctf-solver-test-client", "version": "0.1.1"},
        }
        result = self.request("initialize", params)
        self.notify("notifications/initialized", {})
        if isinstance(result, dict) and discovery is not None:
            result.setdefault("discovery", discovery)
        return result

    def list_tools(self) -> list[dict[str, Any]]:
        result = self.request("tools/list", {})
        tools = result.get("tools") if isinstance(result, dict) else None
        if not isinstance(tools, list):
            raise McpClientError("tools/list did not return a tools array")
        return tools

    def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> tuple[bool, Any]:
        """Return ``(is_error, parsed_payload_or_text)``."""

        result = self.request("tools/call", {"name": name, "arguments": arguments or {}})
        if not isinstance(result, dict):
            raise McpClientError("tools/call returned a non-object result")
        is_error = bool(result.get("isError"))
        content = result.get("content") or []
        text = ""
        for item in content:
            if isinstance(item, dict) and item.get("type") == "text":
                text = str(item.get("text", ""))
                break
        if not text:
            return is_error, result.get("structuredContent")
        try:
            return is_error, json.loads(text)
        except (ValueError, TypeError):
            return is_error, text


def python_module_command(module: str, *args: str) -> list[str]:
    return [sys.executable, "-m", module, *map(str, args)]
