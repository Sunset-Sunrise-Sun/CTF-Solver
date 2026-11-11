"""Managed ACP client: process lifecycle, sessions and the Round 1 prompt gate.

``AcpClient`` implements :class:`ctf_solver.core.protocols.AcpSessionClient`
exactly. It owns one managed ACP server process (spawned with
``Popen(command, shell=False)``), performs the JSON-RPC ``initialize``
handshake (protocol version 1 only), and exposes the session surface the
Manager needs.

Deliberate Round 1 constraints implemented here:

* ``prompt`` raises :class:`ModelCallNotAuthorized` unless the caller explicitly
  constructed the client with ``allow_model_calls=True`` (ADR-020). The gate is
  client-side: the fake/real server is never contacted by a gated call.
* ``session/cancel`` is a notification, never an OS kill. The process stays
  alive; truthful cancellation/quiescence decisions stay with the Manager.
* lifecycle is an explicit state machine: ``stopped -> starting -> ready ->
  closing -> stopped`` plus ``failed``/``crashed``; a crash fails pending
  requests with :class:`AcpProcessExited` and preserves the exit code in
  :meth:`diagnostics`.
"""

from __future__ import annotations

import os
import subprocess
from typing import Any, Callable, Mapping

from ..core.errors import (
    AcpError,
    AcpProcessExited,
    AcpProtocolError,
    AcpStateError,
    AcpTimeout,
    CtfSolverError,
    ModelCallNotAuthorized,
    ValidationError,
)
from ..core.protocols import SystemClock
from . import models
from .transport import JsonRpcStdioTransport

STATE_STOPPED = "stopped"
STATE_STARTING = "starting"
STATE_READY = "ready"
STATE_CLOSING = "closing"
STATE_FAILED = "failed"
STATE_CRASHED = "crashed"

_LIFECYCLE_STATES = frozenset(
    {STATE_STOPPED, STATE_STARTING, STATE_READY, STATE_CLOSING, STATE_FAILED, STATE_CRASHED}
)


class AcpClient:
    """One managed ACP server process with independent Child sessions.

    The Manager may use one client for several Tasks; sessions are isolated by
    the server, not by OS process boundaries (shared failure domain documented
    in docs/ARCHITECTURE.md section 5).
    """

    def __init__(
        self,
        command: list[str],
        *,
        env: dict[str, str] | None = None,
        cwd: str | None = None,
        startup_timeout_s: float = 20.0,
        request_timeout_s: float = 30.0,
        stderr_path: str | None = None,
        allow_model_calls: bool = False,
    ) -> None:
        if not isinstance(command, (list, tuple)) or not command:
            raise ValidationError("ACP command must be a non-empty argv array")
        if not all(isinstance(part, str) and part for part in command):
            raise ValidationError("ACP command entries must be non-empty strings")
        if startup_timeout_s <= 0 or request_timeout_s <= 0:
            raise ValidationError("ACP timeouts must be positive")
        self._command = [str(part) for part in command]
        self._env = dict(env) if env is not None else None
        self._cwd = str(cwd) if cwd is not None else None
        self._startup_timeout_s = float(startup_timeout_s)
        self._request_timeout_s = float(request_timeout_s)
        self._stderr_path = str(stderr_path) if stderr_path is not None else None
        self._allow_model_calls = bool(allow_model_calls)
        self._clock = SystemClock()
        self.state = STATE_STOPPED
        self._process: subprocess.Popen[bytes] | None = None
        self._transport: JsonRpcStdioTransport | None = None
        self._protocol_info: models.InitializeInfo | None = None
        self._started_at: int | None = None
        self._exit_code: int | None = None
        self._last_error: str | None = None
        self._stop_done = False
        self._permission_handler: Callable[[dict[str, Any]], dict[str, Any]] | None = None
        self._session_update_handler: Callable[[dict[str, Any]], None] | None = None
        self._permission_requests = 0
        self._permission_handler_errors = 0
        self._session_updates = 0
        self._session_update_handler_errors = 0
        self._cancel_notifications = 0

    # -- lifecycle ------------------------------------------------------------

    def __enter__(self) -> "AcpClient":
        self.start()
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.stop()

    def start(self) -> None:
        """Spawn the ACP server and complete the ``initialize`` handshake."""

        if self.state in (STATE_STARTING, STATE_CLOSING, STATE_READY):
            raise AcpStateError(
                f"ACP client cannot start while state is {self.state!r}",
                details={"state": self.state},
            )
        self._reset_for_start()
        self.state = STATE_STARTING
        self._started_at = self._clock.now_ms()
        try:
            self._process = subprocess.Popen(
                self._command,
                shell=False,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=self._cwd,
                env=dict(self._env) if self._env is not None else None,
                close_fds=True,
            )
        except (OSError, ValueError) as exc:
            self.state = STATE_FAILED
            self._last_error = f"failed to spawn ACP server process: {exc}"
            raise AcpError(
                self._last_error,
                details={"command": list(self._command), "cwd": self._cwd},
            ) from exc
        try:
            self._transport = JsonRpcStdioTransport(
                self._process, stderr_path=self._stderr_path
            )
            self._transport.set_eof_handler(self._on_transport_eof)
            self._transport.set_request_handler(
                "session/request_permission", self._on_permission_request
            )
            self._transport.set_notification_handler(
                "session/update", self._on_session_update
            )
            result = self._transport.send_request(
                "initialize",
                models.build_initialize_params(),
                timeout_s=self._startup_timeout_s,
            )
            self._protocol_info = models.parse_initialize_result(result)
        except CtfSolverError as exc:
            self._last_error = str(exc)
            self.state = STATE_FAILED
            self._teardown_after_failed_start()
            raise
        except BaseException:
            self.state = STATE_FAILED
            self._teardown_after_failed_start()
            raise
        self.state = STATE_READY

    def stop(self, timeout_s: float = 10.0) -> None:
        """Gracefully stop the server, reap the process; safe to call twice."""

        if self._stop_done:
            return
        self._stop_done = True
        if self._process is None and self._transport is None:
            self.state = STATE_STOPPED
            return
        if self.state != STATE_CRASHED:
            self.state = STATE_CLOSING
        transport = self._transport
        process = self._process
        if transport is not None:
            try:
                transport.close_stdin()
            except (OSError, ValueError):  # pragma: no cover - defensive
                pass
        if process is not None:
            try:
                process.wait(timeout=timeout_s)
            except subprocess.TimeoutExpired:
                self._terminate_process(process)
            self._exit_code = process.returncode
        if transport is not None:
            transport.shutdown(timeout_s=min(max(timeout_s, 0.1), 2.0))
        self._transport = None
        self.state = STATE_STOPPED

    def is_alive(self) -> bool:
        process = self._process
        if process is None:
            return False
        try:
            return process.poll() is None
        except (OSError, ValueError):  # pragma: no cover - defensive
            return False

    # -- session surface ------------------------------------------------------

    def new_session(
        self, cwd: str, mcp_servers: list[dict[str, Any]] | None = None
    ) -> dict[str, Any]:
        """Call ``session/new``; ``cwd`` must be an absolute existing directory."""

        self._require_ready("session/new")
        cwd = models.validate_workspace_cwd(cwd)
        params = models.build_new_session_params(cwd, mcp_servers)
        result = self._request("session/new", params)
        info = models.parse_session_result(result, method="session/new")
        return info.raw

    def list_sessions(self, cwd: str | None = None) -> dict[str, Any]:
        self._require_ready("session/list")
        params = models.build_session_list_params(cwd)
        result = self._request("session/list", params)
        if not isinstance(result, Mapping):
            raise AcpProtocolError("ACP session/list result must be a JSON object")
        return dict(result)

    def resume_session(self, session_id: str, cwd: str) -> dict[str, Any]:
        self._require_ready("session/resume")
        session_id = models.validate_session_id(session_id)
        cwd = models.validate_workspace_cwd(cwd)
        result = self._request("session/resume", models.build_resume_params(session_id, cwd))
        info = models.parse_session_result(result, method="session/resume")
        return info.raw

    def close_session(self, session_id: str) -> None:
        self._require_ready("session/close")
        session_id = models.validate_session_id(session_id)
        self._request("session/close", {"sessionId": session_id})

    def cancel_session(self, session_id: str) -> None:
        """Send the ``session/cancel`` notification (never an OS kill)."""

        self._require_ready("session/cancel")
        session_id = models.validate_session_id(session_id)
        transport = self._transport
        if transport is None:  # pragma: no cover - _require_ready covers this
            raise AcpStateError("ACP transport is not available")
        try:
            transport.send_notification("session/cancel", {"sessionId": session_id})
        except AcpProcessExited as exc:
            self._note_request_failure(exc)
            raise
        self._cancel_notifications += 1

    def prompt(self, session_id: str, content: list[dict[str, Any]]) -> dict[str, Any]:
        """Round 1 gate: model calls require explicit ``allow_model_calls=True``."""

        if not self._allow_model_calls:
            raise ModelCallNotAuthorized(
                "Round 1 does not authorize ACP session/prompt or any model call "
                "(ADR-020); construct AcpClient with allow_model_calls=True only "
                "for a separately authorized synthetic test"
            )
        self._require_ready("session/prompt")
        session_id = models.validate_session_id(session_id)
        if not isinstance(content, (list, tuple)) or not all(
            isinstance(block, Mapping) for block in content
        ):
            raise ValidationError("prompt content must be a list of content-block objects")
        result = self._request(
            "session/prompt",
            {"sessionId": session_id, "prompt": [dict(block) for block in content]},
        )
        if not isinstance(result, Mapping):
            raise AcpProtocolError("ACP session/prompt result must be a JSON object")
        return dict(result)

    # -- handlers -------------------------------------------------------------

    def set_permission_handler(
        self, handler: Callable[[dict[str, Any]], dict[str, Any]] | None
    ) -> None:
        if handler is not None and not callable(handler):
            raise ValidationError("permission handler must be callable or None")
        self._permission_handler = handler

    def set_session_update_handler(
        self, handler: Callable[[dict[str, Any]], None] | None
    ) -> None:
        if handler is not None and not callable(handler):
            raise ValidationError("session update handler must be callable or None")
        self._session_update_handler = handler

    # -- diagnostics ----------------------------------------------------------

    def diagnostics(self) -> dict[str, Any]:
        """Structured lifecycle/counter facts for Manager observability."""

        transport = self._transport
        transport_diag = transport.diagnostics() if transport is not None else {}
        info = self._protocol_info
        process = self._process
        if process is not None:
            try:
                live_exit = process.poll()
            except (OSError, ValueError):  # pragma: no cover - defensive
                live_exit = self._exit_code
        else:
            live_exit = self._exit_code
        exit_code = self._exit_code if self._exit_code is not None else live_exit
        return {
            "state": self.state,
            "pid": process.pid if process is not None else None,
            "command": list(self._command),
            "protocol_version": info.protocol_version if info is not None else None,
            "pending_requests": transport_diag.get("pending_requests", 0),
            "last_error": self._last_error,
            "stderr_tail": transport_diag.get("stderr_tail", ""),
            "started_at": self._started_at,
            "request_count": transport_diag.get("request_count", 0),
            "response_count": transport_diag.get("response_count", 0),
            "malformed_lines": transport_diag.get("malformed_lines", 0),
            "exit_code": exit_code,
            "is_alive": self.is_alive(),
            "agent_info": dict(info.agent_info) if info is not None else None,
            "mcp_capabilities": dict(info.mcp_capabilities) if info is not None else None,
            "session_capabilities": (
                dict(info.session_capabilities) if info is not None else None
            ),
            "allow_model_calls": self._allow_model_calls,
            "permission_requests": self._permission_requests,
            "permission_handler_errors": self._permission_handler_errors,
            "session_updates": self._session_updates,
            "session_update_handler_errors": self._session_update_handler_errors,
            "cancel_notifications": self._cancel_notifications,
            "duplicate_responses": transport_diag.get("duplicate_responses", 0),
            "timed_out_requests": transport_diag.get("timed_out_requests", 0),
            "eof": transport_diag.get("eof", False),
            "stderr_bytes": transport_diag.get("stderr_bytes", 0),
        }

    # -- internals ------------------------------------------------------------

    def _reset_for_start(self) -> None:
        self._state_check()
        self._process = None
        self._transport = None
        self._protocol_info = None
        self._exit_code = None
        self._last_error = None
        self._stop_done = False
        self._permission_requests = 0
        self._permission_handler_errors = 0
        self._session_updates = 0
        self._session_update_handler_errors = 0
        self._cancel_notifications = 0

    def _state_check(self) -> None:
        if self.state not in _LIFECYCLE_STATES:  # pragma: no cover - defensive
            raise AcpStateError(f"invalid ACP client state {self.state!r}")

    def _require_ready(self, operation: str) -> None:
        if self.state == STATE_CRASHED:
            raise AcpProcessExited(
                "ACP server process is not running; the client crashed",
                details={
                    "state": self.state,
                    "operation": operation,
                    "exit_code": self.diagnostics()["exit_code"],
                    "last_error": self._last_error,
                },
            )
        if self.state != STATE_READY:
            raise AcpStateError(
                f"ACP client is {self.state!r}; {operation} requires 'ready'",
                details={"state": self.state, "operation": operation},
            )

    def _request(self, method: str, params: Mapping[str, Any]) -> Any:
        transport = self._transport
        if transport is None:
            raise AcpStateError(f"ACP client is {self.state!r}; no transport available")
        try:
            return transport.send_request(
                method, params, timeout_s=self._request_timeout_s
            )
        except (AcpTimeout, AcpProcessExited, AcpProtocolError) as exc:
            self._note_request_failure(exc)
            raise

    def _note_request_failure(self, exc: CtfSolverError) -> None:
        self._last_error = str(exc)
        if isinstance(exc, AcpProcessExited) and self.state in (
            STATE_READY,
            STATE_STARTING,
        ):
            self.state = STATE_CRASHED

    def _on_transport_eof(self) -> None:
        if self.state in (STATE_READY, STATE_STARTING):
            self.state = STATE_CRASHED
            process = self._process
            exit_code = None
            if process is not None:
                try:
                    exit_code = process.poll()
                except (OSError, ValueError):  # pragma: no cover - defensive
                    exit_code = None
            self._last_error = (
                "ACP server process exited unexpectedly"
                + (f" with exit code {exit_code}" if exit_code is not None else "")
            )

    def _on_permission_request(self, params: dict[str, Any]) -> dict[str, Any]:
        self._permission_requests += 1
        handler = self._permission_handler
        if handler is None:
            return models.permission_cancelled()
        try:
            response = handler(params)
        except Exception:
            self._permission_handler_errors += 1
            return models.permission_cancelled()
        if not isinstance(response, Mapping):
            self._permission_handler_errors += 1
            return models.permission_cancelled()
        payload = dict(response)
        outcome = payload.get("outcome")
        if not isinstance(outcome, Mapping):
            self._permission_handler_errors += 1
            return models.permission_cancelled()
        return payload

    def _on_session_update(self, params: dict[str, Any]) -> None:
        self._session_updates += 1
        handler = self._session_update_handler
        if handler is None:
            return
        try:
            handler(params)
        except Exception:  # pragma: no cover - handler faults stay isolated
            self._session_update_handler_errors += 1

    def _teardown_after_failed_start(self) -> None:
        process = self._process
        if process is not None:
            try:
                process.wait(timeout=1.0)
            except subprocess.TimeoutExpired:
                self._terminate_process(process)
            self._exit_code = process.returncode
        transport = self._transport
        if transport is not None:
            transport.shutdown(timeout_s=1.0)
        self._transport = None

    def _terminate_process(self, process: subprocess.Popen[bytes]) -> None:
        try:
            process.terminate()
        except (OSError, ValueError):  # pragma: no cover - defensive
            pass
        try:
            process.wait(timeout=2.0)
            return
        except subprocess.TimeoutExpired:
            pass
        try:
            process.kill()
        except (OSError, ValueError):  # pragma: no cover - defensive
            pass
        try:
            process.wait(timeout=2.0)
        except subprocess.TimeoutExpired:  # pragma: no cover - hard failure
            self._last_error = "ACP server process could not be reaped"
