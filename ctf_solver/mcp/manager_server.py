"""Manager control MCP server (main-conversation side).

Exposes the Manager control API as MCP tools over stdio. In Round 1 this server
is exercised by deterministic tests with a fake MCP client; genuine
main-conversation invocation via `/ctf-solver` requires a supported
project-scoped integration and is a Round 2 acceptance item (see
``docs/ROUND_1_ARCHITECTURE_NOTES.md``).

Run::

    python -m ctf_solver.mcp.manager_server --root . \
        [--acp-command "<command string>"] [--capture-mode desktop|fake]
"""

from __future__ import annotations

import argparse
import shlex
import sys
from typing import Any, Callable

from ..core.config import SolverConfig, discover_acp_command
from ..core.protocols import ManagerControl
from .protocol import McpServer, McpTool, McpToolError


def _jsonable(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    to_dict = getattr(value, "to_dict", None)
    if callable(to_dict):
        return _jsonable(to_dict())
    return str(value)


def _wrap(handler: Callable[..., Any]) -> Callable[[dict[str, Any]], Any]:
    def call(arguments: dict[str, Any]) -> Any:
        try:
            return _jsonable(handler(**arguments))
        except TypeError as exc:
            raise McpToolError(f"invalid arguments: {exc}", reason_code="invalid_params") from exc
        except Exception as exc:  # noqa: BLE001 - domain errors become tool errors
            reason = getattr(exc, "reason_code", "manager_error")
            details = getattr(exc, "details", {})
            raise McpToolError(str(exc), reason_code=str(reason), details=details) from exc

    return call


def _schema(properties: dict[str, Any], required: list[str], description: str) -> dict[str, Any]:
    return {
        "type": "object",
        "description": description,
        "properties": properties,
        "required": required,
        "additionalProperties": False,
    }


def build_manager_tools(manager: ManagerControl) -> list[McpTool]:
    """Build the MCP tool list for a Manager control implementation."""

    tools = [
        McpTool(
            name="ctf_task_create",
            description=(
                "Create a new CTF Task for one challenge. One Task maps to one independent ACP "
                "Worker session and workspace. Additional Tasks beyond two active Tasks queue FIFO."
            ),
            input_schema=_schema(
                {
                    "title": {"type": "string", "description": "Challenge title/name."},
                    "category": {
                        "type": "string",
                        "enum": ["web", "misc", "crypto", "reverse", "pwn"],
                        "description": "Challenge category.",
                    },
                    "conversation_id": {
                        "type": "string",
                        "description": "Stable identifier for the current conversation.",
                    },
                    "source": {"type": "string", "description": "Challenge source/competition."},
                    "scope_profile": {
                        "type": "string",
                        "description": "Competition/scope profile name, e.g. synthetic-local.",
                    },
                    "notes": {"type": "string"},
                    "supplied_files": {
                        "type": "array",
                        "items": {"type": "string"},
                        "maxItems": 100,
                        "description": (
                            "Challenge files to import, given as paths relative to the project "
                            "challenge-uploads intake directory (never absolute host paths)."
                        ),
                    },
                },
                ["title", "category", "conversation_id"],
                "Create a Task, import supplied challenge files under Manager control and enqueue it.",
            ),
            handler=_wrap(manager.create_task),
        ),
        McpTool(
            name="ctf_task_list",
            description="List Tasks, optionally filtered by status or conversation.",
            input_schema=_schema(
                {
                    "status": {"type": "string"},
                    "conversation_id": {"type": "string"},
                },
                [],
                "List durable Tasks.",
            ),
            handler=_wrap(lambda status=None, conversation_id=None: manager.list_tasks(status=status, conversation_id=conversation_id)),
        ),
        McpTool(
            name="ctf_task_status",
            description=(
                "Get full Task status: lifecycle, worker/session/workspace mapping, queue position, "
                "approvals, target grants, executions, evidence chain head and screenshots."
            ),
            input_schema=_schema(
                {"task_id": {"type": "string"}}, ["task_id"], "Task status lookup."
            ),
            handler=_wrap(manager.get_task_status),
        ),
        McpTool(
            name="ctf_task_continue",
            description=(
                "Continue the active Task. Round 1 records the continuation and never issues "
                "session/prompt or a model call (model-mediated continuation is a Round 2 gate)."
            ),
            input_schema=_schema(
                {
                    "task_id": {"type": "string"},
                    "message": {"type": "string", "description": "User continuation message."},
                },
                ["task_id"],
                "Continue an existing non-terminal Task.",
            ),
            handler=_wrap(lambda task_id, message="": manager.continue_task(task_id, message)),
        ),
        McpTool(
            name="ctf_task_pause",
            description="Pause a running Task (sends ACP cancel; it is not an OS process kill).",
            input_schema=_schema(
                {
                    "task_id": {"type": "string"},
                    "reason": {"type": "string"},
                },
                ["task_id"],
                "Request a pause.",
            ),
            handler=_wrap(lambda task_id, reason="": manager.pause_task(task_id, reason)),
        ),
        McpTool(
            name="ctf_task_cancel",
            description=(
                "Request Task cancellation. The Task first becomes cancel_requested and only "
                "becomes cancelled after quiescence is confirmed; ACP cancel is not an OS kill."
            ),
            input_schema=_schema(
                {
                    "task_id": {"type": "string"},
                    "reason": {"type": "string"},
                },
                ["task_id"],
                "Request cancellation.",
            ),
            handler=_wrap(lambda task_id, reason="": manager.cancel_task(task_id, reason)),
        ),
        McpTool(
            name="ctf_task_complete",
            description=(
                "Submit a completion request for an active Task. The Manager verifies the "
                "lifecycle preconditions (no unfinished execution, no pending approval, "
                "session-log evidence ingested, intact evidence chain), closes the ACP "
                "session, then persists the completed terminal state. Completion cannot "
                "bypass these checks; a failed session close keeps the Task and its slot."
            ),
            input_schema=_schema(
                {
                    "task_id": {"type": "string"},
                    "result_state": {
                        "type": "string",
                        "description": (
                            "Concrete outcome token (e.g. solved_flag_candidate, no_flag, "
                            "partial_analysis); 'unknown' is rejected."
                        ),
                    },
                    "note": {"type": "string"},
                },
                ["task_id", "result_state"],
                "Complete an active Task through the Manager lifecycle.",
            ),
            handler=_wrap(
                lambda task_id, result_state, note="": manager.complete_task(
                    task_id, result_state=result_state, note=note
                )
            ),
        ),
        McpTool(
            name="ctf_approval_request",
            description=(
                "Request a Task-scoped human approval for a sensitive proposed action "
                "(untrusted code, software installation, remote target access)."
            ),
            input_schema=_schema(
                {
                    "task_id": {"type": "string"},
                    "action_kind": {
                        "type": "string",
                        "enum": ["untrusted_code", "software_install", "remote_target", "tool_action"],
                    },
                    "details": {"type": "object", "description": "Exact proposed action details."},
                    "ttl_s": {"type": "integer", "description": "Optional approval TTL in seconds."},
                },
                ["task_id", "action_kind"],
                "Create a pending approval request.",
            ),
            handler=_wrap(
                lambda task_id, action_kind, details=None, ttl_s=None: manager.request_approval(
                    task_id, action_kind=action_kind, details=details or {}, ttl_s=ttl_s
                )
            ),
        ),
        McpTool(
            name="ctf_approval_list",
            description=(
                "List approvals, optionally for one Task. Approval decisions are made only by a "
                "human through the local interactive console CLI; there is no MCP approval tool."
            ),
            input_schema=_schema({"task_id": {"type": "string"}}, [], "List approvals."),
            handler=_wrap(lambda task_id=None: manager.list_approvals(task_id=task_id)),
        ),
        McpTool(
            name="ctf_grant_revoke",
            description="Revoke a Task-scoped network grant.",
            input_schema=_schema({"grant_id": {"type": "string"}}, ["grant_id"], "Revoke a grant."),
            handler=_wrap(manager.revoke_grant),
        ),
        McpTool(
            name="ctf_grant_list",
            description="List network grants, optionally for one Task.",
            input_schema=_schema({"task_id": {"type": "string"}}, [], "List grants."),
            handler=_wrap(lambda task_id=None: manager.list_grants(task_id=task_id)),
        ),
        McpTool(
            name="ctf_flag_candidate",
            description=(
                "Record a candidate Flag with its verification source. This never submits a Flag; "
                "the user confirms and submits it."
            ),
            input_schema=_schema(
                {
                    "task_id": {"type": "string"},
                    "flag": {"type": "string"},
                    "source": {"type": "string"},
                },
                ["task_id", "flag", "source"],
                "Record a candidate Flag (no submission).",
            ),
            handler=_wrap(
                lambda task_id, flag, source: manager.record_candidate_flag(task_id, flag=flag, source=source)
            ),
        ),
        McpTool(
            name="ctf_screenshot_capture",
            description=(
                "Explicitly capture a screenshot for a Task/Step and bind it to "
                "Task/Worker/Step/session/time. Blank or failed captures are recorded honestly."
            ),
            input_schema=_schema(
                {
                    "task_id": {"type": "string"},
                    "step_id": {"type": "string"},
                    "scope": {"type": "string", "description": "Capture scope, e.g. desktop."},
                },
                ["task_id"],
                "Capture one explicit screenshot.",
            ),
            handler=_wrap(
                lambda task_id, step_id=None, scope="desktop": manager.take_screenshot(
                    task_id, step_id=step_id, scope=scope
                )
            ),
        ),
        McpTool(
            name="ctf_session_ingest",
            description=(
                "Ingest this Task's real Harness session.v4 jsonl.zstd log into the evidence chain "
                "(multi-frame decode, call/result correlation, idempotent). The log is located by the "
                "Manager from its own Task/Worker/session registry; callers cannot pass a file path."
            ),
            input_schema=_schema(
                {
                    "task_id": {"type": "string"},
                    "worker_id": {
                        "type": "string",
                        "description": "Optional expected Worker id; must match the Task's Worker.",
                    },
                },
                ["task_id"],
                "Ingest the Task's registered session log.",
            ),
            handler=_wrap(
                lambda task_id, worker_id=None: manager.ingest_session_log(
                    task_id, worker_id=worker_id
                )
            ),
        ),
        McpTool(
            name="ctf_events_export",
            description="Deterministically export committed evidence records to events.jsonl.",
            input_schema=_schema({"task_id": {"type": "string"}}, ["task_id"], "Export events."),
            handler=_wrap(manager.export_events),
        ),
        McpTool(
            name="ctf_writeup_build",
            description="Generate the chronological Markdown Writeup from committed evidence.",
            input_schema=_schema({"task_id": {"type": "string"}}, ["task_id"], "Build Writeup."),
            handler=_wrap(manager.build_writeup),
        ),
        McpTool(
            name="ctf_evidence_zip",
            description=(
                "Produce the evidence ZIP with selected original outputs, screenshots, "
                "writeup.md and manifest.sha256."
            ),
            input_schema=_schema({"task_id": {"type": "string"}}, ["task_id"], "Build evidence ZIP."),
            handler=_wrap(manager.export_evidence_zip),
        ),
        McpTool(
            name="ctf_runtime_status",
            description=(
                "Report Manager runtime status: ACP client diagnostics, active/queued Tasks, "
                "IPC endpoint, DB path, evidence chain head, and Round 1 integration limits."
            ),
            input_schema=_schema({}, [], "Manager runtime status."),
            handler=_wrap(manager.runtime_status),
        ),
    ]
    return tools


def build_server(manager: ManagerControl) -> McpServer:
    return McpServer(
        name="ctf-solver-manager",
        version="0.1.0",
        instructions=(
            "CTF-Solver Manager control surface. The Core Skill /ctf-solver enters CTF mode and "
            "uses these tools to create, continue, pause, cancel and retrieve Tasks. Sensitive "
            "actions require Task-scoped human approval; target access requires a Task-scoped "
            "grant; the user confirms and submits Flags."
        ),
        tools=build_manager_tools(manager),
        max_workers=4,
    )


def _parse_acp_command(text: str | None) -> list[str] | None:
    """Parse an explicit, complete ACP server command.

    The default (``--acp-command`` omitted) is intentionally ``None`` so the
    wiring layer discovers the audited Harness launcher and builds the exact
    verified argv ``dsh --profile acp`` (including the ``--profile acp``
    arguments). A caller-provided command is treated as complete and is not
    rewritten, which is what fake-ACP integration tests need.
    """

    if not text or not str(text).strip():
        return None
    return shlex.split(str(text), posix=False)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="CTF-Solver Manager control MCP server")
    parser.add_argument("--root", default=".", help="Project root (runtime data stays here, outside Git)")
    parser.add_argument(
        "--acp-command",
        default=None,
        help=(
            "Complete ACP server command string (used by tests/fake ACP). Omit to use the "
            "audited Harness launcher as 'dsh --profile acp'."
        ),
    )
    parser.add_argument("--capture-mode", default="desktop", choices=["desktop", "real-window", "fake"])
    parser.add_argument("--max-workers", type=int, default=2)
    parser.add_argument(
        "--dsh-home",
        default="",
        help=(
            "Explicit Harness DSH_HOME for the managed ACP server. Default: project-local "
            "isolated .ctf-solver-data/dsh-home; the live ~/.dsh is used only when this is "
            "explicitly set after owner authorization."
        ),
    )
    parser.add_argument(
        "--session-log-root",
        default="",
        help=(
            "Override the Harness session-log root used for registry-based ingestion. "
            "Default: <dsh-home>/sessions. Tests may point this at a fake ACP log tree."
        ),
    )
    parser.add_argument(
        "--intake-dir",
        default="",
        help=(
            "Challenge-file intake directory (default <root>/challenge-uploads). Only files "
            "below this directory can be imported; no arbitrary host paths are read."
        ),
    )
    args = parser.parse_args(argv)

    from ..wiring import default_isolated_dsh_home

    dsh_home = args.dsh_home or default_isolated_dsh_home(args.root)
    extra: dict[str, str] = {"dsh_home": str(dsh_home)}
    if args.session_log_root:
        extra["session_log_root"] = str(args.session_log_root)
    if args.intake_dir:
        extra["intake_dir"] = str(args.intake_dir)
    config = SolverConfig(
        root=args.root,
        acp_command=_parse_acp_command(args.acp_command),
        max_active_workers=max(1, min(2, args.max_workers)),
        capture_mode=args.capture_mode,
        extra=extra,
    )
    from ..wiring import build_manager_service  # deferred: other modules may still be in progress

    service = build_manager_service(config)
    try:
        service.start()
        return build_server(service).serve()
    finally:
        service.shutdown()


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main(sys.argv[1:]))
