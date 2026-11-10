"""Loopback TCP ND-JSON JSON-RPC endpoint used by Worker ``ctf-exec`` servers.

Each Worker session receives ``CTF_SOLVER_IPC_URL`` and a per-Worker bearer
token through its ACP ``session/new.mcpServers`` environment. Requests without a
valid token fail closed; the endpoint never executes anything by itself — it
delegates to the Manager's execution pipeline (Broker + Runtime).
"""

from __future__ import annotations

import json
import socket
import threading
from typing import Any, Protocol


class IpcHandler(Protocol):
    def ipc_worker_info(self, token: str) -> dict[str, Any]: ...

    def ipc_exec(self, token: str, params: dict[str, Any]) -> dict[str, Any]: ...


class ManagerIpcServer:
    def __init__(self, handler: IpcHandler, *, host: str = "127.0.0.1", port: int = 0) -> None:
        self.handler = handler
        self.host = host
        self._requested_port = int(port)
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._port = 0

    @property
    def port(self) -> int:
        return self._port

    @property
    def url(self) -> str:
        return f"tcp://{self.host}:{self._port}"

    def start(self) -> str:
        if self._sock is not None:
            return self.url
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self._requested_port))
        sock.listen(16)
        sock.settimeout(0.2)
        self._sock = sock
        self._port = int(sock.getsockname()[1])
        self._thread = threading.Thread(target=self._serve, name="manager-ipc", daemon=True)
        self._thread.start()
        return self.url

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        sock = self._sock
        self._sock = None
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            self._thread = None

    def _serve(self) -> None:
        while not self._stop.is_set() and self._sock is not None:
            try:
                conn, _address = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn,), name="manager-ipc-conn", daemon=True).start()

    def _handle(self, conn: socket.socket) -> None:
        with conn:
            try:
                conn.settimeout(30.0)
                buffer = bytearray()
                while b"\n" not in buffer:
                    chunk = conn.recv(65536)
                    if not chunk:
                        return
                    buffer.extend(chunk)
                    if len(buffer) > 8 * 1024 * 1024:
                        self._send(conn, self._error(None, "request too large", "invalid_request"))
                        return
                line = bytes(buffer).split(b"\n", 1)[0]
                try:
                    request = json.loads(line.decode("utf-8"))
                except (ValueError, UnicodeDecodeError) as exc:
                    self._send(conn, self._error(None, f"malformed JSON: {exc}", "ipc_protocol_error"))
                    return
                if not isinstance(request, dict):
                    self._send(conn, self._error(None, "request must be an object", "invalid_request"))
                    return
                response = self._dispatch(request)
                self._send(conn, response)
            except OSError:
                return

    @staticmethod
    def _send(conn: socket.socket, payload: dict[str, Any]) -> None:
        try:
            conn.sendall(json.dumps(payload, ensure_ascii=False).encode("utf-8") + b"\n")
        except OSError:
            pass

    @staticmethod
    def _error(rpc_id: Any, message: str, reason_code: str, details: Any = None) -> dict[str, Any]:
        error: dict[str, Any] = {"message": message, "reason_code": reason_code}
        if details is not None:
            error["details"] = details
        return {"id": rpc_id, "error": error}

    def _dispatch(self, request: dict[str, Any]) -> dict[str, Any]:
        rpc_id = request.get("id", 1)
        token = request.get("token")
        if not isinstance(token, str) or not token.strip():
            return self._error(rpc_id, "missing Worker token", "denied")
        method = request.get("method")
        params = request.get("params") or {}
        if not isinstance(params, dict):
            return self._error(rpc_id, "params must be an object", "invalid_request")
        try:
            if method == "ping":
                return {"id": rpc_id, "result": {"ok": True, "url": self.url}}
            if method == "worker_info":
                return {"id": rpc_id, "result": self.handler.ipc_worker_info(token)}
            if method == "ctf_exec":
                return {"id": rpc_id, "result": self.handler.ipc_exec(token, params)}
            return self._error(rpc_id, f"unknown method: {method!r}", "ipc_error")
        except Exception as exc:  # noqa: BLE001 - IPC must return structured errors
            reason_code = str(getattr(exc, "reason_code", "ipc_error"))
            details = getattr(exc, "details", None)
            return self._error(rpc_id, str(exc), reason_code, details)
