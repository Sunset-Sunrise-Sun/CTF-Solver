"""ND-JSON JSON-RPC 2.0 stdio transport for the managed ACP server process.

The transport is deliberately process-agnostic: it wraps an already-spawned
``subprocess.Popen`` whose stdio pipes are binary pipes, so tests can wrap a
fake server directly and the Manager can later wrap the audited
``dsh --profile acp`` server without changing framing code.

Framing facts implemented here (docs/INTERFACES.md section 3.1):

* one JSON-RPC 2.0 message per line, UTF-8, LF or CRLF terminated;
* a single reader thread that copes with partial reads and with several
  messages arriving in one chunk; message size is not capped in practice
  (a very large line is only rejected at ``max_line_bytes`` with a diagnostic);
* malformed JSON is reported as diagnostics and never kills the reader;
* responses are correlated by request id, so out-of-order responses (concurrent
  callers) and duplicate responses (server bug) are handled explicitly;
* timeouts raise :class:`AcpTimeout`; stdout EOF / process exit raises
  :class:`AcpProcessExited` for every pending and later request;
* server -> client requests are dispatched to registered handlers (e.g.
  ``session/request_permission``) and answered on the reader thread;
* stderr is drained on its own thread into a bounded in-memory tail and an
  optional append-only file; it is never mixed into stdout.

Only argv arrays are used: this module never invokes a shell.
"""

from __future__ import annotations

import json
import subprocess
import threading
from collections import deque
from concurrent.futures import Future
from concurrent.futures import TimeoutError as FutureTimeoutError
from pathlib import Path
from typing import Any, Callable, Mapping

from ..core.errors import (
    AcpProcessExited,
    AcpProtocolError,
    AcpRemoteError,
    AcpStateError,
    AcpTimeout,
    CtfSolverError,
)

JSONRPC_VERSION = "2.0"

#: Default bound for the in-memory stderr tail (bytes).
DEFAULT_STDERR_BUFFER_BYTES = 8192
#: A single framing line larger than this is dropped with a diagnostic instead
#: of growing the buffer without bound. 64 MiB is far above any ACP message.
DEFAULT_MAX_LINE_BYTES = 64 * 1024 * 1024
#: Number of malformed samples kept for diagnostics.
MAX_MALFORMED_SAMPLES = 5
#: Number of stderr samples kept for diagnostics (last partial lines).
MAX_STDERR_SAMPLES = 20

RequestHandler = Callable[[dict[str, Any]], Any]
NotificationHandler = Callable[[dict[str, Any]], None]
EofHandler = Callable[[], None]


class _PendingRequest:
    __slots__ = ("future", "method")

    def __init__(self, method: str) -> None:
        self.future: Future[Any] = Future()
        self.method = method


class JsonRpcStdioTransport:
    """Bidirectional ND-JSON JSON-RPC 2.0 transport over a child process' pipes.

    The owning caller is responsible for spawning and reaping the process; the
    transport only owns the pipes and the reader/drainer threads.
    """

    def __init__(
        self,
        process: subprocess.Popen[bytes],
        *,
        stderr_path: str | Path | None = None,
        stderr_buffer_bytes: int = DEFAULT_STDERR_BUFFER_BYTES,
        max_line_bytes: int = DEFAULT_MAX_LINE_BYTES,
    ) -> None:
        if process.stdin is None or process.stdout is None:
            raise AcpStateError(
                "ACP server process stdio pipes are not available; "
                "spawn it with stdin=PIPE and stdout=PIPE"
            )
        if stderr_buffer_bytes < 0:
            raise AcpStateError("stderr_buffer_bytes must be non-negative")
        self.process = process
        self._lock = threading.Lock()
        self._write_lock = threading.Lock()
        self._pending: dict[Any, _PendingRequest] = {}
        self._next_request_id = 0
        self.request_count = 0
        self.response_count = 0
        self.notification_count = 0
        self.server_request_count = 0
        self.malformed_lines = 0
        self.duplicate_responses = 0
        self.timed_out_requests = 0
        self._request_handlers: dict[str, RequestHandler] = {}
        self._notification_handlers: dict[str, NotificationHandler] = {}
        self._default_request_handler: RequestHandler | None = None
        self._eof_handler: EofHandler | None = None
        self._eof = threading.Event()
        self._closing = False
        self._closed = False
        self._stdin_closed = False
        self._malformed_samples: deque[str] = deque(maxlen=MAX_MALFORMED_SAMPLES)
        self._stderr_samples: deque[str] = deque(maxlen=MAX_STDERR_SAMPLES)
        self._stderr_buffer = bytearray()
        self._stderr_buffer_bytes = int(stderr_buffer_bytes)
        self._max_line_bytes = int(max_line_bytes)
        self._stderr_file = None
        self._stderr_path = Path(stderr_path) if stderr_path is not None else None
        if self._stderr_path is not None:
            self._stderr_path.parent.mkdir(parents=True, exist_ok=True)
            self._stderr_file = open(self._stderr_path, "ab", buffering=0)
        self._reader = threading.Thread(
            target=self._reader_loop,
            name="acp-stdout-reader",
            daemon=True,
        )
        self._stderr_reader = threading.Thread(
            target=self._stderr_loop,
            name="acp-stderr-reader",
            daemon=True,
        )
        self._reader.start()
        if process.stderr is not None:
            self._stderr_reader.start()

    # -- handler registration -------------------------------------------------

    def set_request_handler(self, method: str, handler: RequestHandler | None) -> None:
        """Register the handler for a server -> client request method."""

        with self._lock:
            if handler is None:
                self._request_handlers.pop(method, None)
            else:
                self._request_handlers[method] = handler

    def set_notification_handler(
        self, method: str, handler: NotificationHandler | None
    ) -> None:
        """Register the handler for a server -> client notification method."""

        with self._lock:
            if handler is None:
                self._notification_handlers.pop(method, None)
            else:
                self._notification_handlers[method] = handler

    def set_default_request_handler(self, handler: RequestHandler | None) -> None:
        """Fallback handler for unregistered server -> client requests."""

        with self._lock:
            self._default_request_handler = handler

    def set_eof_handler(self, handler: EofHandler | None) -> None:
        """Set a callback invoked once when the server stdout reaches EOF."""

        with self._lock:
            self._eof_handler = handler

    # -- public send surface --------------------------------------------------

    def send_request(
        self,
        method: str,
        params: Mapping[str, Any] | None = None,
        timeout_s: float = 30.0,
    ) -> Any:
        """Send a JSON-RPC request and block for its result.

        Raises :class:`AcpTimeout` when no response arrives within
        ``timeout_s`` (the late response is then ignored as an unknown id),
        :class:`AcpRemoteError` for a JSON-RPC error response and
        :class:`AcpProcessExited` when the process is gone.
        """

        if not isinstance(method, str) or not method:
            raise AcpStateError("JSON-RPC method must be a non-empty string")
        self._ensure_sendable()
        request_id = self._new_request_id()
        pending = _PendingRequest(method)
        with self._lock:
            self.request_count += 1
            self._pending[request_id] = pending
        message: dict[str, Any] = {
            "jsonrpc": JSONRPC_VERSION,
            "id": request_id,
            "method": method,
        }
        if params is not None:
            message["params"] = dict(params)
        try:
            self._send_message(message)
        except BaseException:
            with self._lock:
                self._pending.pop(request_id, None)
            raise
        try:
            return pending.future.result(timeout=timeout_s)
        except FutureTimeoutError:
            with self._lock:
                removed = self._pending.pop(request_id, None) is not None
                if removed:
                    self.timed_out_requests += 1
            raise AcpTimeout(
                f"ACP request {method!r} timed out after {timeout_s:.3f}s",
                details={
                    "method": method,
                    "request_id": request_id,
                    "timeout_s": timeout_s,
                },
            ) from None

    def send_notification(
        self, method: str, params: Mapping[str, Any] | None = None
    ) -> None:
        """Send a JSON-RPC notification (no id, no response expected)."""

        if not isinstance(method, str) or not method:
            raise AcpStateError("JSON-RPC method must be a non-empty string")
        self._ensure_sendable()
        message: dict[str, Any] = {"jsonrpc": JSONRPC_VERSION, "method": method}
        if params is not None:
            message["params"] = dict(params)
        self._send_message(message)

    #: ``notify`` is the name used by docs/INTERFACES.md section 3.1.
    notify = send_notification

    # -- public shutdown surface ----------------------------------------------

    def close_stdin(self) -> None:
        """Close the child stdin so a well-behaved server observes EOF."""

        with self._write_lock:
            self._closing = True
            if self._stdin_closed:
                return
            self._stdin_closed = True
            stdin = self.process.stdin
            if stdin is not None:
                try:
                    stdin.close()
                except (OSError, ValueError):
                    pass

    def shutdown(self, *, timeout_s: float = 2.0) -> None:
        """Stop the reader threads, close pipes and fail any pending request.

        Idempotent. The process is *not* reaped here; the owner (client) does
        that so exit codes are preserved in one place.
        """

        if self._closed:
            return
        self.close_stdin()
        reader = self._reader
        reader_alive = reader.is_alive()
        if reader_alive:
            reader.join(timeout=timeout_s)
            reader_alive = reader.is_alive()
        stderr_reader = self._stderr_reader
        stderr_alive = stderr_reader.is_alive()
        if stderr_alive:
            stderr_reader.join(timeout=timeout_s)
            stderr_alive = stderr_reader.is_alive()
        with self._write_lock:
            self._closed = True
        # Only close the read pipes once no reader thread can still touch them;
        # closing a BufferedReader another thread is blocked reading is unsafe
        # on Windows. The process owner reaps/kills the child, which closes the
        # remaining pipe ends anyway.
        streams: list[Any] = []
        if not reader_alive:
            streams.append(self.process.stdout)
        if not stderr_alive:
            streams.append(self.process.stderr)
        for stream in streams:
            if stream is None:
                continue
            try:
                stream.close()
            except (OSError, ValueError):
                pass
        if self._stderr_file is not None:
            try:
                self._stderr_file.close()
            except OSError:
                pass
            self._stderr_file = None
        self._fail_pending(
            AcpProcessExited(
                "ACP transport was shut down before the request completed",
                details={"pid": self.process.pid},
            )
        )

    # -- state inspection -----------------------------------------------------

    def is_process_alive(self) -> bool:
        try:
            return self.process.poll() is None
        except (OSError, ValueError):
            return False

    @property
    def eof(self) -> bool:
        return self._eof.is_set()

    def pending_count(self) -> int:
        with self._lock:
            return len(self._pending)

    def stderr_text(self) -> str:
        with self._lock:
            data = bytes(self._stderr_buffer)
        return data.decode("utf-8", errors="replace")

    def malformed_samples(self) -> list[str]:
        with self._lock:
            return list(self._malformed_samples)

    def diagnostics(self) -> dict[str, Any]:
        """Structured transport facts consumed by :meth:`AcpClient.diagnostics`."""

        with self._lock:
            pending = len(self._pending)
            malformed = self.malformed_lines
            samples = list(self._malformed_samples)
            stderr_bytes = len(self._stderr_buffer)
        try:
            exit_code = self.process.poll()
        except (OSError, ValueError):
            exit_code = None
        return {
            "pid": self.process.pid,
            "process_alive": exit_code is None,
            "exit_code": exit_code,
            "eof": self._eof.is_set(),
            "closed": self._closed,
            "pending_requests": pending,
            "request_count": self.request_count,
            "response_count": self.response_count,
            "notification_count": self.notification_count,
            "server_request_count": self.server_request_count,
            "malformed_lines": malformed,
            "malformed_samples": samples,
            "duplicate_responses": self.duplicate_responses,
            "timed_out_requests": self.timed_out_requests,
            "stderr_bytes": stderr_bytes,
            "stderr_tail": self.stderr_text(),
        }

    # -- internals ------------------------------------------------------------

    def _new_request_id(self) -> int:
        with self._lock:
            self._next_request_id += 1
            return self._next_request_id

    def _ensure_sendable(self) -> None:
        if self._closing or self._closed:
            raise AcpProcessExited(
                "ACP transport is closed",
                details={"pid": self.process.pid},
            )
        if self._eof.is_set() or not self.is_process_alive():
            raise AcpProcessExited(
                "ACP server process has exited",
                details={"pid": self.process.pid, "exit_code": self._poll_exit_code()},
            )

    def _poll_exit_code(self) -> int | None:
        try:
            return self.process.poll()
        except (OSError, ValueError):
            return None

    def _send_message(self, message: Mapping[str, Any]) -> None:
        try:
            line = (
                json.dumps(message, ensure_ascii=False, separators=(",", ":")).encode(
                    "utf-8"
                )
                + b"\n"
            )
        except (TypeError, ValueError) as exc:
            raise AcpProtocolError(f"outbound JSON-RPC message is not serialisable: {exc}") from exc
        with self._write_lock:
            if self._closing or self._closed or self._stdin_closed:
                raise AcpProcessExited(
                    "ACP transport stdin is closed",
                    details={"pid": self.process.pid},
                )
            stdin = self.process.stdin
            if stdin is None:
                raise AcpProcessExited("ACP server stdin pipe is unavailable")
            try:
                stdin.write(line)
                stdin.flush()
            except (BrokenPipeError, OSError, ValueError) as exc:
                raise AcpProcessExited(
                    f"cannot write to ACP server stdin: {exc}",
                    details={"pid": self.process.pid},
                ) from exc

    # -- reader ---------------------------------------------------------------

    def _reader_loop(self) -> None:
        stream = self.process.stdout
        buffer = bytearray()
        try:
            while True:
                try:
                    chunk = stream.read1(65536)  # type: ignore[union-attr]
                except (OSError, ValueError):
                    break
                if not chunk:
                    break
                buffer.extend(chunk)
                while True:
                    newline = buffer.find(b"\n")
                    if newline < 0:
                        break
                    raw = bytes(buffer[:newline])
                    del buffer[: newline + 1]
                    if raw.endswith(b"\r"):
                        raw = raw[:-1]
                    if not raw.strip():
                        continue
                    self._handle_raw_line(raw)
                if len(buffer) > self._max_line_bytes:
                    self._record_malformed(
                        f"stdout line exceeded {self._max_line_bytes} bytes and was dropped"
                    )
                    buffer.clear()
        finally:
            self._mark_eof()

    def _handle_raw_line(self, raw: bytes) -> None:
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            self._record_malformed(f"invalid UTF-8 on stdout: {exc}")
            return
        try:
            message = json.loads(text)
        except json.JSONDecodeError as exc:
            self._record_malformed(f"malformed JSON on stdout: {exc}: {text[:200]}")
            return
        if not isinstance(message, dict):
            self._record_malformed("JSON-RPC message must be a JSON object")
            return
        if "method" in message:
            self._handle_incoming(message)
            return
        if "id" in message and ("result" in message or "error" in message):
            self._handle_response(message)
            return
        self._record_malformed("message is neither a JSON-RPC request nor a response")

    def _handle_response(self, message: Mapping[str, Any]) -> None:
        response_id = message.get("id")
        with self._lock:
            pending = self._pending.pop(response_id, None) if _id_key(response_id) else None
            if pending is None:
                self.duplicate_responses += 1
            else:
                self.response_count += 1
        if pending is None:
            return
        if "error" in message:
            error = message.get("error")
            if isinstance(error, Mapping):
                code = error.get("code")
                text = str(error.get("message", "ACP server returned an error"))
                data = error.get("data")
            else:  # pragma: no cover - defensive shape check
                code = None
                text = "ACP server returned a malformed error response"
                data = error
            pending.future.set_exception(
                AcpRemoteError(
                    text,
                    code=int(code) if isinstance(code, int) else None,
                    data=data,
                    details={"method": pending.method, "request_id": response_id},
                )
            )
            return
        pending.future.set_result(message.get("result"))

    def _handle_incoming(self, message: Mapping[str, Any]) -> None:
        method = message.get("method")
        if not isinstance(method, str) or not method:
            self._record_malformed("JSON-RPC message has a non-string method")
            return
        params = message.get("params")
        if params is None:
            params = {}
        if not isinstance(params, Mapping):
            if "id" in message:
                self._send_response_error(
                    message.get("id"),
                    -32602,
                    f"params for {method!r} must be a JSON object",
                )
            else:
                self._record_malformed(f"notification {method!r} params must be an object")
            return
        params_dict = dict(params)
        if "id" not in message:
            with self._lock:
                self.notification_count += 1
                handler = self._notification_handlers.get(method)
            if handler is None:
                return
            try:
                handler(params_dict)
            except Exception:  # pragma: no cover - handler faults must not kill the reader
                self._record_malformed(f"notification handler for {method!r} raised")
            return
        with self._lock:
            self.server_request_count += 1
            handler = self._request_handlers.get(method)
            if handler is None:
                handler = self._default_request_handler
        request_id = message.get("id")
        if handler is None:
            self._send_response_error(
                request_id,
                -32601,
                f"unsupported server request method {method!r}",
            )
            return
        try:
            result = handler(params_dict)
        except CtfSolverError as exc:
            self._send_response_error(request_id, -32000, str(exc))
            return
        except Exception as exc:  # pragma: no cover - defensive
            self._send_response_error(
                request_id, -32603, f"server request handler failed: {exc}"
            )
            return
        if result is None:
            result = {}
        try:
            self._send_message(
                {"jsonrpc": JSONRPC_VERSION, "id": request_id, "result": result}
            )
        except (AcpProcessExited, AcpProtocolError):
            return

    def _send_response_error(self, request_id: Any, code: int, message: str) -> None:
        try:
            self._send_message(
                {
                    "jsonrpc": JSONRPC_VERSION,
                    "id": request_id,
                    "error": {"code": int(code), "message": message},
                }
            )
        except (AcpProcessExited, AcpProtocolError):
            return

    def _mark_eof(self) -> None:
        if self._eof.is_set():
            return
        self._eof.set()
        exit_code = self._poll_exit_code()
        self._fail_pending(
            AcpProcessExited(
                "ACP server closed stdout before responding",
                details={"pid": self.process.pid, "exit_code": exit_code},
            )
        )
        with self._lock:
            handler = self._eof_handler
        if handler is not None:
            try:
                handler()
            except Exception:  # pragma: no cover - EOF callbacks must not kill the thread
                pass

    def _fail_pending(self, error: BaseException) -> None:
        with self._lock:
            pending = list(self._pending.values())
            self._pending.clear()
        for request in pending:
            if not request.future.done():
                request.future.set_exception(error)

    def _record_malformed(self, description: str) -> None:
        with self._lock:
            self.malformed_lines += 1
            self._malformed_samples.append(description)

    # -- stderr ---------------------------------------------------------------

    def _stderr_loop(self) -> None:
        stream = self.process.stderr
        if stream is None:
            return
        while True:
            try:
                # ``read1`` returns whatever is available instead of blocking
                # for the full buffer (``read(n)`` would stall the drain until
                # EOF, leaving stderr undelivered mid-session).
                chunk = stream.read1(4096)  # type: ignore[union-attr]
            except (OSError, ValueError):
                break
            if not chunk:
                break
            self._append_stderr(chunk)

    def _append_stderr(self, chunk: bytes) -> None:
        with self._lock:
            self._stderr_buffer.extend(chunk)
            if len(self._stderr_buffer) > self._stderr_buffer_bytes:
                overflow = len(self._stderr_buffer) - self._stderr_buffer_bytes
                del self._stderr_buffer[:overflow]
            text = chunk.decode("utf-8", errors="replace")
            for line in text.splitlines():
                if line:
                    self._stderr_samples.append(line)
            stderr_file = self._stderr_file
        if stderr_file is not None:
            try:
                stderr_file.write(chunk)
            except (OSError, ValueError):  # pragma: no cover - parent closed the file
                pass

def _id_key(value: Any) -> bool:
    """JSON-RPC ids are strings or integers (never booleans/null)."""

    if isinstance(value, bool):
        return False
    return isinstance(value, (str, int))
