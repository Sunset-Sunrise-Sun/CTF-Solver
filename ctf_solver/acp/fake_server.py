"""Deterministic fake ACP server used by the Round 1 tests.

Run as ``python -m ctf_solver.acp.fake_server --scenario <name>`` and speak
ND-JSON JSON-RPC 2.0 on stdio, exactly like the audited ``dsh --profile acp``
server does (docs/INTERFACES.md section 3.3).

Supported ACP methods
---------------------
``initialize`` (protocol version 1 plus capabilities), ``session/new``
(absolute existing cwd required, optional ``mcpServers``), ``session/list``
(newest-first, **excludes active sessions**), ``session/close``,
``session/resume`` (canonical cwd match), ``session/cancel`` (notification,
never an OS kill) and ``session/prompt`` (deterministic synthetic result; the
*client* Round 1 gate is what blocks real use).

Scenarios
---------
``normal``            well-behaved server.
``slow``              every response delayed by ``--delay`` (default 0.45s).
``malformed``         emits a non-JSON line before each response.
``crash-after-init``  replies to ``initialize`` then exits with code 7.
``exit-on-cancel``    exits with code 5 when a ``session/cancel`` notification
                      arrives (to prove the transport detects unexpected exit).
``permission-request``asks the client ``session/request_permission`` during
                      ``session/prompt`` (only ``allow-once``/``reject-once``
                      options) and records the client's answer.
``partial-flush``     writes every frame in tiny chunks so the client must
                      handle partial reads.
``crash-on-request``  exits with code 9 when a ``session/list`` request arrives.

Debug methods (``debug/echo``, ``debug/sleep``, ``debug/delay_echo``,
``debug/big``, ``debug/notify``, ``debug/burst``, ``debug/dup``,
``debug/crash``, ``debug/garbage``, ``debug/crlf``, ``debug/stderr``,
``debug/exit``) exist only so transport-level tests can drive framing,
correlation, size, stderr and exit behaviour deterministically. They are not
part of the ACP contract.

Output options
--------------
``--session-log DIR``  writes a realistic multi-frame zstd
                       ``session.v4.jsonl.zstd`` (and ``<session id>.zstd``) for
                       every ``session/new`` using ``tests.support`` fixtures,
                       so the evidence pipeline can ingest a real
                       client-produced log without a Harness run.
``--record DIR``       appends one JSON line to ``<DIR>/session-new.jsonl`` per
                       ``session/new`` **after replying**, with ``sessionId``,
                       ``cwd`` and the exact ``mcpServers`` array from the
                       request (including each server's args/env). It is
                       append-only JSONL: one ``json.dumps`` line + newline,
                       written under the server's record lock and flushed, so
                       a concurrent reader never sees a partial line.
``--log-dir DIR``      appends server-side observability events to
                       ``<DIR>/server-events.jsonl`` (session lifecycle,
                       cancellations, permission requests/decisions, prompts).

The fake server makes no model calls, no network access and runs no challenge
code; everything is synthetic.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping

from . import models

_PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _now_ms() -> int:
    return int(time.time() * 1000)


class RpcError(Exception):
    """A JSON-RPC error raised by a fake-server handler."""

    def __init__(self, code: int, message: str, data: Any = None) -> None:
        super().__init__(message)
        self.code = int(code)
        self.message = message
        self.data = data


class _NoResponse:
    """Sentinel: the handler wrote its own response."""


_NO_RESPONSE = _NoResponse()


@dataclass
class _Session:
    session_id: str
    cwd: str
    mcp_servers: list[dict[str, Any]]
    created_order: int
    created_at: int
    active: bool = True
    cancel_requested: bool = False
    config_options: list[dict[str, Any]] = field(default_factory=list)


def _canonical_cwd(path: str) -> str:
    return os.path.normcase(os.path.realpath(os.path.abspath(path)))


def _config_options() -> list[dict[str, Any]]:
    """Synthetic but ACP-shaped config options (kept by the client verbatim)."""

    return [
        {
            "id": "model",
            "name": "Model",
            "type": "select",
            "currentValue": "fake-model",
            "options": [
                {"value": "fake-model", "name": "Fake Synthetic Model"},
                {"value": "fake-model-mini", "name": "Fake Synthetic Model Mini"},
            ],
        },
        {
            "id": "mode",
            "name": "Session mode",
            "type": "select",
            "currentValue": "code",
            "options": [
                {"value": "code", "name": "Code"},
                {"value": "ask", "name": "Ask"},
            ],
        },
    ]


class FakeAcpServer:
    """In-process implementation of the fake ACP server (also CLI entry)."""

    def __init__(
        self,
        *,
        scenario: str = "normal",
        log_dir: str | Path | None = None,
        record_dir: str | Path | None = None,
        session_log_dir: str | Path | None = None,
        delay: float = 0.0,
        stdin: Any = None,
        stdout: Any = None,
    ) -> None:
        self.scenario = scenario
        self._log_dir = Path(log_dir) if log_dir is not None else None
        self._record_dir = Path(record_dir) if record_dir is not None else None
        self._session_log_dir = (
            Path(session_log_dir) if session_log_dir is not None else None
        )
        self._delay = float(delay)
        if scenario == "slow" and self._delay <= 0:
            self._delay = 0.45
        self._stdin = stdin if stdin is not None else sys.stdin.buffer
        self._stdout = stdout if stdout is not None else sys.stdout.buffer
        self._write_lock = threading.Lock()
        self._record_lock = threading.Lock()
        self._sessions: dict[str, _Session] = {}
        self._session_order = 0
        self._server_request_seq = 1_000_000
        self._prompt_count = 0
        self._handlers: dict[str, Callable[[Any, dict[str, Any]], Any]] = {
            "initialize": self._method_initialize,
            "session/new": self._method_session_new,
            "session/list": self._method_session_list,
            "session/close": self._method_session_close,
            "session/resume": self._method_session_resume,
            "session/prompt": self._method_session_prompt,
            "debug/echo": self._method_debug_echo,
            "debug/sleep": self._method_debug_sleep,
            "debug/delay_echo": self._method_debug_delay_echo,
            "debug/big": self._method_debug_big,
            "debug/notify": self._method_debug_notify,
            "debug/burst": self._method_debug_burst,
            "debug/dup": self._method_debug_dup,
            "debug/crash": self._method_debug_crash,
            "debug/garbage": self._method_debug_garbage,
            "debug/crlf": self._method_debug_crlf,
            "debug/stderr": self._method_debug_stderr,
            "debug/exit": self._method_debug_exit,
        }

    # -- run loop -------------------------------------------------------------

    def run(self) -> int:
        self._stderr_banner()
        try:
            while True:
                try:
                    line = self._stdin.readline()
                except (OSError, ValueError):
                    break
                if not line:
                    break
                if not line.strip():
                    continue
                self._handle_raw_line(line)
        finally:
            self._record_event({"event": "server_exit", "time": _now_ms()})
        return 0

    def _handle_raw_line(self, line: bytes) -> None:
        try:
            text = line.decode("utf-8")
        except UnicodeDecodeError as exc:
            self._record_event({"event": "malformed_input", "error": str(exc)})
            return
        try:
            message = json.loads(text)
        except json.JSONDecodeError as exc:
            self._record_event({"event": "malformed_input", "error": str(exc)})
            return
        self._handle_message(message)

    def _handle_message(self, message: Any) -> None:
        if not isinstance(message, dict):
            self._record_event({"event": "malformed_input", "error": "not an object"})
            return
        if "method" not in message:
            # A response from the client to a server -> client request is read
            # synchronously by the requesting handler; anything else is noise.
            self._record_event(
                {
                    "event": "client_message_without_method",
                    "message": message,
                }
            )
            return
        method = message.get("method")
        if not isinstance(method, str) or not method:
            self._record_event({"event": "malformed_input", "error": "bad method"})
            return
        params = message.get("params")
        if params is None:
            params = {}
        if not isinstance(params, dict):
            if "id" in message:
                self._respond_error(
                    message.get("id"),
                    models.INVALID_PARAMS,
                    f"params for {method!r} must be a JSON object",
                )
            return
        if "id" in message:
            self._handle_request(message.get("id"), method, params)
        else:
            self._handle_notification(method, params)

    def _handle_request(self, request_id: Any, method: str, params: dict[str, Any]) -> None:
        if self.scenario == "crash-on-request" and method == "session/list":
            self._flush()
            os._exit(9)
        handler = self._handlers.get(method)
        if handler is None:
            self._respond_error(
                request_id,
                models.METHOD_NOT_FOUND,
                f"method not found: {method}",
            )
            return
        try:
            result = handler(request_id, params)
        except RpcError as exc:
            self._respond_error(request_id, exc.code, exc.message, exc.data)
            return
        except Exception as exc:  # pragma: no cover - defensive
            self._respond_error(
                request_id,
                models.INTERNAL_ERROR,
                f"fake server internal error: {exc}",
            )
            return
        if isinstance(result, _NoResponse):
            pass
        else:
            if result is None:
                result = {}
            self._respond(request_id, result)
        self._post_response(method, result)

    def _handle_notification(self, method: str, params: dict[str, Any]) -> None:
        if method == "session/cancel":
            session_id = params.get("sessionId")
            session = self._sessions.get(session_id) if isinstance(session_id, str) else None
            if session is not None:
                session.cancel_requested = True
            self._record_event(
                {"event": "cancel", "sessionId": session_id, "time": _now_ms()}
            )
            if self.scenario == "exit-on-cancel":
                self._flush()
                os._exit(5)
            return
        self._record_event({"event": "notification", "method": method})

    # -- ACP handlers ---------------------------------------------------------

    def _method_initialize(self, request_id: Any, params: dict[str, Any]) -> dict[str, Any]:
        client_version = params.get("protocolVersion")
        self._record_event(
            {
                "event": "initialize",
                "clientProtocolVersion": client_version,
                "clientInfo": params.get("clientInfo"),
                "time": _now_ms(),
            }
        )
        return {
            "protocolVersion": models.PROTOCOL_VERSION,
            "agentCapabilities": {
                "loadSession": True,
                "mcpCapabilities": {"http": False, "sse": False},
                "sessionCapabilities": {
                    "new": True,
                    "list": True,
                    "resume": True,
                    "close": True,
                },
                "promptCapabilities": {
                    "image": False,
                    "audio": False,
                    "embeddedContext": False,
                },
            },
            "agentInfo": {
                "name": "ctf-solver-fake-acp",
                "version": "0.1.0",
                "synthetic": True,
            },
            "authMethods": [],
        }

    def _method_session_new(self, request_id: Any, params: dict[str, Any]) -> dict[str, Any]:
        cwd = params.get("cwd")
        if not isinstance(cwd, str) or not cwd.strip():
            raise RpcError(models.INVALID_PARAMS, "session/new requires a cwd string")
        if not os.path.isabs(cwd):
            raise RpcError(
                models.INVALID_PARAMS, f"session/new cwd must be absolute: {cwd!r}"
            )
        if not os.path.isdir(cwd):
            raise RpcError(
                models.INVALID_PARAMS,
                f"session/new cwd does not exist or is not a directory: {cwd!r}",
            )
        mcp_servers = params.get("mcpServers")
        if mcp_servers is None:
            mcp_servers = []
        if not isinstance(mcp_servers, list) or not all(
            isinstance(item, Mapping) for item in mcp_servers
        ):
            raise RpcError(
                models.INVALID_PARAMS, "session/new mcpServers must be an array of objects"
            )
        self._session_order += 1
        session_id = f"sess-{self._session_order:04d}-{uuid.uuid4().hex[:8]}"
        session = _Session(
            session_id=session_id,
            cwd=cwd,
            mcp_servers=[dict(item) for item in mcp_servers],
            created_order=self._session_order,
            created_at=_now_ms(),
            config_options=_config_options(),
        )
        self._sessions[session_id] = session
        self._write_session_log(session)
        self._record_event(
            {
                "event": "session_new",
                "sessionId": session_id,
                "cwd": cwd,
                "mcpServerCount": len(session.mcp_servers),
                "time": _now_ms(),
            }
        )
        return {
            "sessionId": session_id,
            "configOptions": session.config_options,
            "modes": {
                "availableModes": [
                    {"id": "code", "name": "Code"},
                    {"id": "ask", "name": "Ask"},
                ],
                "currentModeId": "code",
            },
        }

    def _method_session_list(self, request_id: Any, params: dict[str, Any]) -> dict[str, Any]:
        cwd_filter = params.get("cwd")
        if cwd_filter is not None and not isinstance(cwd_filter, str):
            raise RpcError(models.INVALID_PARAMS, "session/list cwd must be a string")
        inactive = [session for session in self._sessions.values() if not session.active]
        if cwd_filter is not None:
            wanted = _canonical_cwd(cwd_filter)
            inactive = [
                session for session in inactive if _canonical_cwd(session.cwd) == wanted
            ]
        inactive.sort(key=lambda session: session.created_order, reverse=True)
        return {
            "sessions": [
                {
                    "sessionId": session.session_id,
                    "cwd": session.cwd,
                    "title": f"synthetic session {session.session_id}",
                    "updatedAt": session.created_at,
                }
                for session in inactive
            ]
        }

    def _require_session(
        self, params: dict[str, Any], *, must_be_active: bool
    ) -> _Session:
        session_id = params.get("sessionId")
        if not isinstance(session_id, str) or not session_id.strip():
            raise RpcError(
                models.INVALID_PARAMS, "session request requires a sessionId string"
            )
        session = self._sessions.get(session_id)
        if session is None:
            raise RpcError(
                models.SESSION_NOT_FOUND,
                f"unknown session {session_id!r}",
                data={"sessionId": session_id},
            )
        if must_be_active and not session.active:
            raise RpcError(
                models.SESSION_NOT_FOUND,
                f"session {session_id!r} is closed",
                data={"sessionId": session_id},
            )
        return session

    def _method_session_close(self, request_id: Any, params: dict[str, Any]) -> dict[str, Any]:
        session = self._require_session(params, must_be_active=False)
        session.active = False
        self._record_event(
            {"event": "session_close", "sessionId": session.session_id, "time": _now_ms()}
        )
        return {}

    def _method_session_resume(self, request_id: Any, params: dict[str, Any]) -> dict[str, Any]:
        session_id = params.get("sessionId")
        cwd = params.get("cwd")
        if not isinstance(cwd, str) or not cwd.strip():
            raise RpcError(models.INVALID_PARAMS, "session/resume requires a cwd string")
        if not os.path.isabs(cwd):
            raise RpcError(
                models.INVALID_PARAMS, f"session/resume cwd must be absolute: {cwd!r}"
            )
        session = self._sessions.get(session_id) if isinstance(session_id, str) else None
        if session is None:
            raise RpcError(
                models.SESSION_NOT_FOUND,
                f"unknown session {session_id!r}",
                data={"sessionId": session_id},
            )
        if session.active:
            raise RpcError(
                models.SESSION_BUSY,
                f"session {session_id!r} is already active; close it before resuming",
                data={"sessionId": session_id},
            )
        if _canonical_cwd(session.cwd) != _canonical_cwd(cwd):
            raise RpcError(
                models.INVALID_PARAMS,
                f"session cwd mismatch: session belongs to {session.cwd!r}, "
                f"resume requested for {cwd!r}",
                data={"sessionId": session_id, "sessionCwd": session.cwd},
            )
        session.active = True
        session.cancel_requested = False
        self._record_event(
            {"event": "session_resume", "sessionId": session.session_id, "time": _now_ms()}
        )
        return {
            "sessionId": session.session_id,
            "configOptions": session.config_options,
            "modes": {"currentModeId": "code"},
        }

    def _method_session_prompt(self, request_id: Any, params: dict[str, Any]) -> dict[str, Any]:
        session = self._require_session(params, must_be_active=True)
        prompt = params.get("prompt")
        if not isinstance(prompt, list) or not all(isinstance(block, Mapping) for block in prompt):
            raise RpcError(
                models.INVALID_PARAMS, "session/prompt requires a prompt array of objects"
            )
        self._prompt_count += 1
        self._record_event(
            {
                "event": "prompt",
                "sessionId": session.session_id,
                "blockCount": len(prompt),
                "promptIndex": self._prompt_count,
                "time": _now_ms(),
            }
        )
        # A real server streams session updates during a turn; emit one so the
        # client's notification handler (and event interleaving) is exercised.
        self._emit(
            {
                "jsonrpc": "2.0",
                "method": "session/update",
                "params": {
                    "sessionId": session.session_id,
                    "update": {
                        "sessionUpdate": "agent_message_chunk",
                        "content": {"type": "text", "text": "synthetic turn chunk"},
                    },
                },
            }
        )
        result: dict[str, Any] = {
            "stopReason": "end_turn",
            "synthetic": True,
            "promptIndex": self._prompt_count,
            "agentMessage": {
                "role": "assistant",
                "content": [
                    {
                        "type": "text",
                        "text": (
                            "synthetic fake-acp response; no model call was made "
                            f"(session {session.session_id})"
                        ),
                    }
                ],
            },
        }
        if self.scenario == "permission-request":
            outcome = self._ask_permission(session)
            result["permissionOutcome"] = outcome
        return result

    def _ask_permission(self, session: _Session) -> dict[str, Any]:
        self._server_request_seq += 1
        server_request_id = self._server_request_seq
        request_params = models.build_permission_request_params(
            session_id=session.session_id
        )
        self._record_event(
            {
                "event": "permission_request",
                "sessionId": session.session_id,
                "options": request_params["options"],
                "time": _now_ms(),
            }
        )
        self._emit(
            {
                "jsonrpc": "2.0",
                "id": server_request_id,
                "method": "session/request_permission",
                "params": request_params,
            }
        )
        response = self._read_client_response(server_request_id)
        if response is None:
            # Client went away while we waited; let the run loop observe EOF.
            raise RpcError(models.INTERNAL_ERROR, "client closed while answering permission")
        if "error" in response:
            error = response.get("error")
            message = error.get("message") if isinstance(error, Mapping) else str(error)
            self._record_event(
                {
                    "event": "permission_decision",
                    "sessionId": session.session_id,
                    "outcome": {"outcome": "error", "message": message},
                    "time": _now_ms(),
                }
            )
            return {"outcome": "error", "message": message}
        try:
            outcome = models.permission_outcome(response.get("result"))
        except Exception as exc:
            self._record_event(
                {
                    "event": "permission_decision",
                    "sessionId": session.session_id,
                    "outcome": {"outcome": "invalid", "error": str(exc)},
                    "time": _now_ms(),
                }
            )
            return {"outcome": "invalid", "error": str(exc)}
        self._record_event(
            {
                "event": "permission_decision",
                "sessionId": session.session_id,
                "outcome": outcome,
                "time": _now_ms(),
            }
        )
        return outcome

    def _read_client_response(self, request_id: int) -> dict[str, Any] | None:
        """Synchronously wait for the client's answer to a server request."""

        while True:
            try:
                line = self._stdin.readline()
            except (OSError, ValueError):
                return None
            if not line:
                return None
            if not line.strip():
                continue
            try:
                message = json.loads(line.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                self._record_event({"event": "malformed_input", "error": str(exc)})
                continue
            if (
                isinstance(message, dict)
                and "method" not in message
                and message.get("id") == request_id
            ):
                return message
            self._handle_message(message)

    # -- debug handlers (transport tests only) -------------------------------

    def _method_debug_echo(self, request_id: Any, params: dict[str, Any]) -> Any:
        return {"echo": params}

    def _method_debug_sleep(self, request_id: Any, params: dict[str, Any]) -> Any:
        seconds = float(params.get("seconds", 0.5))
        echo = params.get("echo")

        def respond_later() -> None:
            time.sleep(max(0.0, seconds))
            self._respond(request_id, {"slept": seconds, "echo": echo})

        threading.Thread(target=respond_later, daemon=True).start()
        return _NO_RESPONSE

    def _method_debug_delay_echo(self, request_id: Any, params: dict[str, Any]) -> Any:
        delay = float(params.get("delay", 0.0))
        value = params.get("value")

        def respond_later() -> None:
            time.sleep(max(0.0, delay))
            self._respond(request_id, {"value": value, "delay": delay})

        threading.Thread(target=respond_later, daemon=True).start()
        return _NO_RESPONSE

    def _method_debug_big(self, request_id: Any, params: dict[str, Any]) -> Any:
        size = int(params.get("size", 0))
        if size < 0 or size > 16 * 1024 * 1024:
            raise RpcError(models.INVALID_PARAMS, "size must be within [0, 16 MiB]")
        return {"size": size, "data": "x" * size}

    def _method_debug_notify(self, request_id: Any, params: dict[str, Any]) -> dict[str, Any]:
        self._emit(
            {
                "jsonrpc": "2.0",
                "method": "session/update",
                "params": {
                    "sessionId": params.get("sessionId", "sess-synthetic"),
                    "update": {
                        "sessionUpdate": "agent_message_chunk",
                        "content": {"type": "text", "text": "synthetic notification"},
                    },
                },
            }
        )
        return {"notified": True}
    
    def _method_debug_burst(self, request_id: Any, params: dict[str, Any]) -> Any:
        notification = {
            "jsonrpc": "2.0",
            "method": "session/update",
            "params": {
                "sessionId": params.get("sessionId", "sess-synthetic"),
                "update": {"sessionUpdate": "agent_message_chunk"},
            },
        }
        response = {"jsonrpc": "2.0", "id": request_id, "result": {"burst": True}}
        payload = (
            json.dumps(notification, separators=(",", ":")).encode("utf-8")
            + b"\n"
            + json.dumps(response, separators=(",", ":")).encode("utf-8")
            + b"\n"
        )
        self._emit_raw(payload)
        return _NO_RESPONSE

    def _method_debug_dup(self, request_id: Any, params: dict[str, Any]) -> Any:
        response = {"jsonrpc": "2.0", "id": request_id, "result": {"duplicate": True}}
        self._emit(response)
        self._emit(response)
        return _NO_RESPONSE

    def _method_debug_crash(self, request_id: Any, params: dict[str, Any]) -> Any:
        self._flush()
        os._exit(9)

    def _method_debug_garbage(self, request_id: Any, params: dict[str, Any]) -> dict[str, Any]:
        self._emit_raw(b"this-is-not-json {{{\n")
        return {"afterGarbage": True}

    def _method_debug_crlf(self, request_id: Any, params: dict[str, Any]) -> Any:
        self._emit(
            {"jsonrpc": "2.0", "id": request_id, "result": {"crlf": True}},
            crlf=True,
        )
        return _NO_RESPONSE

    def _method_debug_stderr(self, request_id: Any, params: dict[str, Any]) -> dict[str, Any]:
        size = int(params.get("size", 1024))
        if size < 0 or size > 4 * 1024 * 1024:
            raise RpcError(models.INVALID_PARAMS, "stderr size must be within [0, 4 MiB]")
        chunk = b"stderr-marker synthetic diagnostics\n"
        payload = (chunk * ((size // len(chunk)) + 1))[:size]
        try:
            sys.stderr.buffer.write(payload)
            sys.stderr.buffer.flush()
        except (OSError, ValueError):
            pass
        return {"stderrBytes": len(payload)}

    def _method_debug_exit(self, request_id: Any, params: dict[str, Any]) -> Any:
        code = int(params.get("code", 0))
        self._flush()
        os._exit(code)

    # -- output ---------------------------------------------------------------

    def _respond(self, request_id: Any, result: Any) -> None:
        if self._delay > 0:
            time.sleep(self._delay)
        if self.scenario == "malformed":
            self._emit_raw(b"this-is-not-json\n")
        self._emit({"jsonrpc": "2.0", "id": request_id, "result": result})

    def _respond_error(
        self, request_id: Any, code: int, message: str, data: Any = None
    ) -> None:
        if self._delay > 0:
            time.sleep(self._delay)
        if self.scenario == "malformed":
            self._emit_raw(b"this-is-not-json\n")
        error: dict[str, Any] = {"code": int(code), "message": message}
        if data is not None:
            error["data"] = data
        self._emit({"jsonrpc": "2.0", "id": request_id, "error": error})

    def _emit(self, message: Mapping[str, Any], *, crlf: bool = False) -> None:
        try:
            line = json.dumps(message, ensure_ascii=False, separators=(",", ":")).encode(
                "utf-8"
            )
        except (TypeError, ValueError):  # pragma: no cover - defensive
            line = json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": message.get("id"),
                    "error": {"code": models.INTERNAL_ERROR, "message": "unserialisable"},
                },
                separators=(",", ":"),
            ).encode("utf-8")
        self._emit_raw(line + (b"\r\n" if crlf else b"\n"))

    def _emit_raw(self, payload: bytes) -> None:
        with self._write_lock:
            if self.scenario == "partial-flush":
                for start in range(0, len(payload), 7):
                    try:
                        self._stdout.write(payload[start : start + 7])
                        self._stdout.flush()
                    except (OSError, ValueError):
                        return
                    time.sleep(0.001)
                return
            try:
                self._stdout.write(payload)
                self._stdout.flush()
            except (OSError, ValueError):
                pass

    def _flush(self) -> None:
        with self._write_lock:
            try:
                self._stdout.flush()
            except (OSError, ValueError):
                pass

    def _stderr_banner(self) -> None:
        try:
            sys.stderr.buffer.write(
                f"[fake-acp] scenario={self.scenario} pid={os.getpid()}\n".encode("utf-8")
            )
            sys.stderr.buffer.flush()
        except (OSError, ValueError):  # pragma: no cover - stderr not captured
            pass

    # -- recording ------------------------------------------------------------

    def _post_response(self, method: str, result: Any) -> None:
        if method == "session/new" and isinstance(result, Mapping):
            session_id = result.get("sessionId")
            session = self._sessions.get(session_id) if isinstance(session_id, str) else None
            if session is not None:
                # docs/INTERFACES.md section 3.3 / Lead integration requirement:
                # append the exact mcpServers array after the reply was sent.
                self._append_session_new_record(session)
        if method == "initialize" and self.scenario == "crash-after-init":
            self._flush()
            os._exit(7)
        if method == "session/list" and self.scenario == "crash-on-request":
            self._flush()
            os._exit(9)

    def _append_session_new_record(self, session: _Session) -> None:
        if self._record_dir is None:
            return
        entry = {
            "sessionId": session.session_id,
            "cwd": session.cwd,
            "mcpServers": session.mcp_servers,
            "createdAt": session.created_at,
        }
        line = json.dumps(entry, ensure_ascii=False, separators=(",", ":")) + "\n"
        with self._record_lock:
            try:
                self._record_dir.mkdir(parents=True, exist_ok=True)
                with open(
                    self._record_dir / "session-new.jsonl",
                    "a",
                    encoding="utf-8",
                    newline="\n",
                ) as handle:
                    handle.write(line)
                    handle.flush()
            except OSError:  # pragma: no cover - recording must not break the server
                pass

    def _record_event(self, event: Mapping[str, Any]) -> None:
        if self._log_dir is None:
            return
        line = json.dumps(dict(event), ensure_ascii=False, separators=(",", ":")) + "\n"
        with self._record_lock:
            try:
                self._log_dir.mkdir(parents=True, exist_ok=True)
                with open(
                    self._log_dir / "server-events.jsonl",
                    "a",
                    encoding="utf-8",
                    newline="\n",
                ) as handle:
                    handle.write(line)
                    handle.flush()
            except OSError:  # pragma: no cover - observability must not break the server
                pass

    # -- session log fixtures -------------------------------------------------

    def _write_session_log(self, session: _Session) -> None:
        if self._session_log_dir is None:
            return
        data = self._build_session_log_bytes(session)
        if data is None:
            self._record_event(
                {"event": "session_log_skipped", "sessionId": session.session_id}
            )
            return
        try:
            self._session_log_dir.mkdir(parents=True, exist_ok=True)
            (self._session_log_dir / "session.v4.jsonl.zstd").write_bytes(data)
            (self._session_log_dir / f"{session.session_id}.zstd").write_bytes(data)
        except OSError:  # pragma: no cover - fixture writing must not break the server
            return
        self._record_event(
            {
                "event": "session_log_written",
                "sessionId": session.session_id,
                "bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
        )

    def _build_session_log_bytes(self, session: _Session) -> bytes | None:
        """Build a realistic multi-frame zstd session log from shared fixtures.

        The fake server intentionally imports the shared ``tests.support``
        builders so other modules can test ingestion against exactly the same
        synthetic event shapes used everywhere else. When the repository root
        is not importable a minimal built-in record set is used instead.
        """

        records: list[dict[str, Any]] | None = None
        build = None
        try:
            from tests.support.session_events import standard_session
            from tests.support.zstd_fixtures import build_session_log

            records = standard_session(
                session_id=session.session_id,
                include_approval=True,
                include_delivery_accept=True,
            )
            build = build_session_log
        except ImportError:  # pragma: no cover - only when run outside the repo
            records = self._fallback_session_records(session.session_id)
            build = _fallback_build_session_log
        if records is not None:
            for record in records:
                if isinstance(record, dict):
                    data = record.get("data")
                    if isinstance(data, dict):
                        meta = data.get("meta")
                        if isinstance(meta, dict) and "cwd" in meta:
                            meta["cwd"] = session.cwd
                        if record.get("type") == "session":
                            data["cwd"] = session.cwd
        try:
            return build(records, frames=6)  # type: ignore[misc]
        except Exception:  # pragma: no cover - compression backend failure
            return None

    @staticmethod
    def _fallback_session_records(session_id: str) -> list[dict[str, Any]]:
        base = 1_700_000_000_000
        return [
            {
                "type": "session",
                "seq": 0,
                "time": base,
                "data": {"id": session_id, "version": 4, "cwd": "synthetic"},
            },
            {"type": "turn/start", "seq": 1, "time": base + 1, "data": {"turn": 1}},
            {"type": "turn/end", "seq": 2, "time": base + 2, "data": {"turn": 1}},
        ]


def _fallback_build_session_log(records: list[dict[str, Any]], *, frames: int = 6) -> bytes:
    """Compress JSONL records without the shared test helper."""

    payload = (
        "\n".join(json.dumps(record, ensure_ascii=False, separators=(",", ":")) for record in records)
        + "\n"
    ).encode("utf-8")
    chunks: list[bytes] = []
    count = max(1, int(frames))
    size = len(payload)
    boundaries = [round(size * index / count) for index in range(count + 1)]
    for index in range(count):
        start, end = boundaries[index], boundaries[index + 1]
        if end > start:
            chunks.append(payload[start:end])
    try:
        import zstandard

        compressor = zstandard.ZstdCompressor(level=3)
        return b"".join(compressor.compress(chunk) for chunk in chunks)
    except ImportError:  # pragma: no cover - Python >= 3.14 stdlib fallback
        from compression import zstd

        return b"".join(zstd.compress(chunk) for chunk in chunks)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m ctf_solver.acp.fake_server",
        description="Deterministic fake ACP server (ND-JSON JSON-RPC 2.0 over stdio).",
    )
    parser.add_argument(
        "--scenario",
        choices=(
            "normal",
            "slow",
            "malformed",
            "crash-after-init",
            "exit-on-cancel",
            "permission-request",
            "partial-flush",
            "crash-on-request",
        ),
        default="normal",
    )
    parser.add_argument(
        "--log-dir",
        default=None,
        help="append server-events.jsonl observability records to this directory",
    )
    parser.add_argument(
        "--record",
        default=None,
        help=(
            "append session-new.jsonl records (sessionId/cwd/mcpServers) to this "
            "directory after every session/new reply"
        ),
    )
    parser.add_argument(
        "--session-log",
        default=None,
        help="write a synthetic multi-frame session.v4.jsonl.zstd per session here",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.0,
        help="response delay in seconds (slow scenario default: 0.45)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    server = FakeAcpServer(
        scenario=args.scenario,
        log_dir=args.log_dir,
        record_dir=args.record,
        session_log_dir=args.session_log,
        delay=args.delay,
    )
    try:
        return server.run()
    except KeyboardInterrupt:  # pragma: no cover - interactive only
        return 130


if __name__ == "__main__":
    sys.exit(main())
