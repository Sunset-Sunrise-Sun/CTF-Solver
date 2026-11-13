"""Command line entry points for CTF-Solver v0.1.1.

Sub-commands are imported lazily so a partially-integrated module never breaks
the whole CLI, and so `python -m ctf_solver ...` works from the repository root
without installing the package.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any


def _cmd_preflight(args: argparse.Namespace) -> int:
    from .preflight.doctor import main as preflight_main

    argv = ["--root", args.root]
    if args.json:
        argv += ["--json", args.json]
    if args.text:
        argv += ["--text", args.text]
    if getattr(args, "quiet", False):
        argv.append("--quiet")
    return preflight_main(argv)


def _cmd_manager(args: argparse.Namespace) -> int:
    from .mcp.manager_server import main as manager_main

    if args.action != "serve":
        print(f"unknown manager action: {args.action}", file=sys.stderr)
        return 2
    argv = ["--root", args.root, "--capture-mode", args.capture_mode]
    if getattr(args, "target_window_pid", 0):
        argv += ["--target-window-pid", str(args.target_window_pid)]
    if getattr(args, "lead_sessions_root", ""):
        argv += ["--lead-sessions-root", args.lead_sessions_root]
    if getattr(args, "session_log_root", ""):
        argv += ["--session-log-root", args.session_log_root]
    return manager_main(argv)


def _cmd_worker_mcp(_args: argparse.Namespace) -> int:
    from .mcp.exec_server import main as exec_main

    return exec_main([])


def _cmd_fake_acp(args: argparse.Namespace) -> int:
    from .acp import fake_server

    main = getattr(fake_server, "main", None)
    if main is None:
        print("acp.fake_server has no main() entry point", file=sys.stderr)
        return 2
    return main(args.remaining)


def _cmd_skills(args: argparse.Namespace) -> int:
    from pathlib import Path

    from .preflight.doctor import _skill_report  # noqa: PLC2701 - shared report helper

    report = _skill_report(Path(args.root))
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["ok"] else 1


def _cmd_evidence(args: argparse.Namespace) -> int:
    if args.action == "decode":
        from pathlib import Path

        from .evidence.zstd_frames import decode_all, parse_json_lines

        data = Path(args.path).read_bytes()
        report = decode_all(data)
        # Frames are chunks of one JSON-Lines stream; a line may span frame
        # boundaries, so parse the concatenated payload, not each frame alone.
        payload = b"".join(
            frame.payload for frame in report.frames if getattr(frame, "payload", None)
        )
        records, line_gaps = parse_json_lines(payload)
        summary = {
            "path": str(Path(args.path).resolve()),
            "size": len(data),
            "frames": len(report.frames),
            "complete": report.complete,
            "frame_errors": [gap.to_dict() for gap in report.gaps],
            "line_gaps": [gap.to_dict() for gap in line_gaps],
            "decoded_records": len(records),
            "first_types": [record.get("type") for record in records[:10]],
        }
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        return 0 if report.complete and not line_gaps else 1
    if args.action == "verify-chain":
        from .evidence.store import EvidenceStore

        store = EvidenceStore(
            __import__("os").path.join(args.root, ".ctf-solver-data", "manager.sqlite"),
            __import__("os").path.join(args.root, ".ctf-solver-data", "cas", "sha256"),
        )
        status = store.chain_status()
        print(json.dumps(status.to_dict(), ensure_ascii=False, indent=2))
        return 0 if status.ok else 1
    print(f"unknown evidence action: {args.action}", file=sys.stderr)
    return 2


def _cmd_task(args: argparse.Namespace) -> int:
    from .core.config import SolverConfig
    from .wiring import build_manager_service, default_isolated_dsh_home

    # Round 1 defaults to a project-local isolated DSH_HOME so local Task
    # commands never write session/profile state into the live ~/.dsh.
    dsh_home = args.dsh_home or default_isolated_dsh_home(args.root)
    extra: dict[str, str] = {"dsh_home": str(dsh_home)}
    if args.intake_dir:
        extra["intake_dir"] = str(args.intake_dir)
    if getattr(args, "lead_sessions_root", ""):
        extra["lead_sessions_root"] = str(args.lead_sessions_root)
    config = SolverConfig(root=args.root, capture_mode="fake", extra=extra)
    service = build_manager_service(config)
    try:
        try:
            status = service.start()
            if not status.get("acp", {}).get("ready"):
                detail = status.get("acp", {}).get("error") or "unknown ACP startup error"
                print(
                    f"CTF-Solver Manager startup failed: ACP unavailable: {detail}",
                    file=sys.stderr,
                )
                if args.action == "create":
                    return 1
            if args.action == "create":
                task = service.create_task(
                    title=args.title,
                    category=args.category,
                    conversation_id=args.conversation_id,
                    source=args.source or "",
                    scope_profile=args.scope_profile or "",
                    notes=args.notes or "",
                    supplied_files=list(args.supplied_file or []),
                    lead_session_id=getattr(args, "lead_session_id", "") or None,
                )
                print(json.dumps(task.to_dict(), ensure_ascii=False, indent=2))
                return 0
            if args.action == "list":
                tasks = service.list_tasks()
                print(json.dumps([task.to_dict() for task in tasks], ensure_ascii=False, indent=2))
                return 0
            if args.action == "status":
                print(json.dumps(service.get_task_status(args.task_id), ensure_ascii=False, indent=2))
                return 0
            print(f"unknown task action: {args.action}", file=sys.stderr)
            return 2
        except Exception as exc:  # noqa: BLE001 - CLI reports domain failures
            print(f"task operation failed: {type(exc).__name__}: {exc}", file=sys.stderr)
            return 1
    finally:
        service.shutdown()


def _cmd_approval(args: argparse.Namespace) -> int:
    from .core.config import SolverConfig
    from .core.protocols import SystemClock
    from .security.confirmation import ConsoleConfirmationChannel
    from .wiring import build_security_service

    config = SolverConfig(root=args.root)
    service, store, evidence = build_security_service(config)
    try:
        if args.action == "list":
            records = service.list_approvals(task_id=args.task_id or None)
            print(json.dumps([record.to_dict() for record in records], ensure_ascii=False, indent=2))
            return 0
        if args.action in {"confirm", "reject"}:
            if not args.approval_id:
                print("--approval-id is required for confirm/reject", file=sys.stderr)
                return 2
            channel = ConsoleConfirmationChannel(SystemClock())
            record = service.confirm_approval(
                args.approval_id,
                channel=channel,
                reject=(args.action == "reject"),
                note=args.note or "",
            )
            print(json.dumps(record.to_dict(), ensure_ascii=False, indent=2))
            return 0
        print(f"unknown approval action: {args.action}", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001 - CLI reports domain failures
        print(f"approval operation failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    finally:
        try:
            evidence.close()
        except Exception:  # noqa: BLE001
            pass
        store.close()


def _cmd_grant(args: argparse.Namespace) -> int:
    from .core.config import SolverConfig
    from .wiring import build_security_service

    config = SolverConfig(root=args.root)
    service, store, evidence = build_security_service(config)
    try:
        if args.action == "list":
            records = service.list_grants(task_id=args.task_id or None)
            print(json.dumps([record.to_dict() for record in records], ensure_ascii=False, indent=2))
            return 0
        if args.action == "create":
            if not args.approval_id:
                print("--approval-id is required to create a grant", file=sys.stderr)
                return 2
            record = service.create_grant_from_approval(
                args.approval_id,
                competition_profile=args.competition_profile,
                host=args.host,
                port=args.port,
                protocol=args.protocol,
                method=args.method,
                path_prefix=args.path_prefix,
                ttl_s=args.ttl_s,
                max_calls=args.max_calls,
            )
            print(json.dumps(record.to_dict(), ensure_ascii=False, indent=2))
            return 0
        if args.action == "revoke":
            if not args.grant_id:
                print("--grant-id is required to revoke", file=sys.stderr)
                return 2
            record = service.revoke_grant(args.grant_id)
            print(json.dumps(record.to_dict(), ensure_ascii=False, indent=2))
            return 0
        print(f"unknown grant action: {args.action}", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001
        print(f"grant operation failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    finally:
        try:
            evidence.close()
        except Exception:  # noqa: BLE001
            pass
        store.close()


def _cmd_version(_args: argparse.Namespace) -> int:
    from . import __version__

    print(f"ctf-solver {__version__}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ctf-solver",
        description=(
            "CTF-Solver v0.1.1: DeepSeek Harness extension, not a standalone CTF platform; "
            "Manager/ACP/Worker runtime, typed ctf-exec, scoped approvals, evidence and "
            "delivery. CLI/headless first; main-conversation Manager MCP registration and "
            "model-driven Workers are not enabled."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    preflight = sub.add_parser("preflight", help="Read-only first-run environment report")
    preflight.add_argument("--root", default=".")
    preflight.add_argument("--json", default=None, help="Write the JSON report to this path")
    preflight.add_argument("--text", default=None, help="Write the human-readable report to this path")
    preflight.add_argument("--quiet", action="store_true", help="Do not print the human-readable report")
    preflight.set_defaults(func=_cmd_preflight)

    manager = sub.add_parser("manager", help="Manager control MCP server (stdio)")
    manager.add_argument("action", choices=["serve"])
    manager.add_argument("--root", default=".")
    manager.add_argument(
        "--capture-mode",
        default="real-window",
        choices=["real-window", "desktop", "fake", "fake-blank"],
        help=(
            "Screenshot capture mode: real-window (default; requires --target-window-pid), "
            "desktop (Worker legacy compatibility) or fake/fake-blank (deterministic tests)."
        ),
    )
    manager.add_argument(
        "--target-window-pid",
        type=int,
        default=0,
        help=(
            "Explicit target window PID for real-window capture (required unless "
            "--capture-mode is desktop/fake)."
        ),
    )
    manager.add_argument(
        "--lead-sessions-root",
        default="",
        help=(
            "Live DSH sessions root used only for Lead-session evidence (e.g. the Lead's "
            "real ~/.dsh/sessions). Never derived from --dsh-home."
        ),
    )
    manager.add_argument(
        "--session-log-root",
        default="",
        help="Override the managed Worker Harness session-log root (default <dsh-home>/sessions).",
    )
    manager.set_defaults(func=_cmd_manager)

    worker = sub.add_parser("worker-mcp", help="Worker-scoped ctf-exec MCP server (stdio)")
    worker.set_defaults(func=_cmd_worker_mcp)

    fake = sub.add_parser("fake-acp", help="Deterministic fake ACP server (tests only)")
    fake.add_argument("remaining", nargs=argparse.REMAINDER)
    fake.set_defaults(func=_cmd_fake_acp)

    skills = sub.add_parser("skills", help="Report project-level Skill files")
    skills.add_argument("--root", default=".")
    skills.set_defaults(func=_cmd_skills)

    evidence = sub.add_parser("evidence", help="Evidence helpers")
    evidence.add_argument("action", choices=["decode", "verify-chain"])
    evidence.add_argument("path", nargs="?")
    evidence.add_argument("--root", default=".")
    evidence.set_defaults(func=_cmd_evidence)

    task = sub.add_parser("task", help="Local Task operations (starts the Manager wiring)")
    task.add_argument("action", choices=["create", "list", "status"])
    task.add_argument("--root", default=".")
    task.add_argument("--title", default="Synthetic challenge")
    task.add_argument("--category", default="misc", choices=["web", "misc", "crypto", "reverse", "pwn"])
    task.add_argument("--conversation-id", default="local-conversation")
    task.add_argument("--source", default="")
    task.add_argument("--scope-profile", default="synthetic-local")
    task.add_argument("--notes", default="")
    task.add_argument("--task-id", default="")
    task.add_argument(
        "--supplied-file",
        action="append",
        default=[],
        help=(
            "Challenge file to import, relative to the intake dir (default "
            "<root>/challenge-uploads). Repeatable. Absolute host paths are rejected."
        ),
    )
    task.add_argument(
        "--intake-dir",
        default="",
        help="Override the challenge-file intake directory (default <root>/challenge-uploads).",
    )
    task.add_argument(
        "--dsh-home",
        default="",
        help=(
            "Explicit Harness DSH_HOME for the managed ACP server. Default: project-local "
            "isolated .ctf-solver-data/dsh-home (never the live ~/.dsh unless explicitly given)."
        ),
    )
    task.add_argument(
        "--lead-session-id",
        default="",
        help=(
            "Lead Harness session id to bound to the new Task (read from $env:DSH_SESSION_ID "
            "by the Lead conversation). The Manager verifies the id, its log header and cwd "
            "before binding; evidence is ingested from that Lead session log."
        ),
    )
    task.add_argument(
        "--lead-sessions-root",
        default="",
        help=(
            "Live DSH sessions root used to verify the Lead session id (e.g. "
            "C:/Users/<user>/.dsh/sessions). Never derived from --dsh-home."
        ),
    )
    task.set_defaults(func=_cmd_task)

    approval = sub.add_parser(
        "approval",
        help="Human approval console (list / confirm / reject). Decisions require an interactive TTY.",
    )
    approval.add_argument("action", choices=["list", "confirm", "reject"])
    approval.add_argument("--root", default=".")
    approval.add_argument("--approval-id", default="")
    approval.add_argument("--task-id", default="")
    approval.add_argument("--note", default="")
    approval.set_defaults(func=_cmd_approval)

    grant = sub.add_parser(
        "grant",
        help="Task-scoped network grants (create requires a human-confirmed approval; list / revoke).",
    )
    grant.add_argument("action", choices=["create", "list", "revoke"])
    grant.add_argument("--root", default=".")
    grant.add_argument("--approval-id", default="")
    grant.add_argument("--grant-id", default="")
    grant.add_argument("--task-id", default="")
    grant.add_argument("--competition-profile", default="synthetic-local")
    grant.add_argument("--host", default="127.0.0.1")
    grant.add_argument("--port", type=int, default=31337)
    grant.add_argument("--protocol", default="tcp")
    grant.add_argument("--method", default="GET")
    grant.add_argument("--path-prefix", default="/")
    grant.add_argument(
        "--ttl-s",
        type=int,
        default=None,
        help="Optional compatibility check: must equal the human-approved grant TTL, which is read from the approval payload.",
    )
    grant.add_argument(
        "--max-calls",
        type=int,
        default=None,
        help="Optional compatibility check: must equal the human-approved call budget, which is read from the approval payload.",
    )
    grant.set_defaults(func=_cmd_grant)

    version = sub.add_parser("version", help="Print version")
    version.set_defaults(func=_cmd_version)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    # Release-UAT remediation F4: domain failures (e.g. a missing screenshot
    # target PID) are reported as a concise CLI error instead of a raw traceback.
    from .core.errors import CtfSolverError

    try:
        return int(args.func(args))
    except CtfSolverError as exc:
        print(f"ctf-solver error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
