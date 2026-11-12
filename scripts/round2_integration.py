"""Round 2 real-Harness integration evidence run (zero model calls).

This script drives the real, locally installed Harness ACP server
(``dsh --profile acp``) with an isolated temporary ``DSH_HOME`` and verifies:

* real ACP lifecycle + two active Workers + a third FIFO Task + promotion;
* per-session Worker MCP mounting (the ctf-exec MCP server is started by the
  real ACP server for each session; it records a handshake file);
* a direct MCP ``tools/call`` against the Worker-scoped ctf-exec server;
* registry-based ingestion of the real Harness multi-frame session log;
* a real project-owned window screenshot via PrintWindow flag 2;
* restart recovery without duplicate sessions;
* a synthetic end-to-end challenge producing Markdown Writeup + evidence ZIP
  with an independently verified manifest;
* the session-log privacy mechanism in an isolated DSH_HOME (no model call).

It never sends ``session/prompt``, never calls a model, never contacts a target
and never executes challenge-provided code. Worker tool calls are simulated by
the script through the same typed MCP interface a model-driven Worker would use;
this is stated in the generated evidence.

Usage:
    python scripts/round2_integration.py [--keep-runtime] [--json-out PATH]
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))
EVIDENCE = REPO / "round2-evidence"
RAW = EVIDENCE / "raw"
END_TO_END = EVIDENCE / "end-to-end"
RUNTIME = REPO / ".ctf-solver-data"
TASKS = REPO / "tasks"
INTAKE = REPO / "challenge-uploads"

PASS: list[dict] = []
FAIL: list[dict] = []
NOTES: list[str] = []
LOGS: list[str] = []


def log(message: str) -> None:
    line = f"[{datetime.now(timezone.utc).strftime('%H:%M:%S')}] {message}"
    print(line, flush=True)
    LOGS.append(line)


def check(name: str, condition: bool, detail: str = "") -> bool:
    (PASS if condition else FAIL).append({"name": name, "detail": detail})
    log(("PASS " if condition else "FAIL ") + name + (f" — {detail}" if detail else ""))
    return condition


def run_window_probe(text: str) -> tuple[subprocess.Popen, dict]:
    proc = subprocess.Popen(
        [sys.executable, str(REPO / "scripts" / "window_probe.py"), "--text", text],
        cwd=str(REPO),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    assert proc.stdout is not None
    line = proc.stdout.readline()
    if not line:
        raise RuntimeError("window probe did not report readiness")
    info = json.loads(line)
    info["process_pid"] = info.get("process_pid") or proc.pid
    log(f"window probe ready: {info}")
    return proc, info


def decode_session_log_records(path: Path) -> tuple[list[dict], dict]:
    from ctf_solver.evidence.zstd_frames import decode_all, parse_json_lines

    data = path.read_bytes()
    report = decode_all(data)
    payload = b"".join(
        frame.payload for frame in report.frames if getattr(frame, "payload", None)
    )
    records, gaps = parse_json_lines(payload)
    return records, {
        "size": len(data),
        "frames": len(report.frames),
        "complete": report.complete,
        "records": len(records),
        "line_gaps": len(gaps),
    }


def start_exec_mcp_client(ipc_url: str, token: str):
    from ctf_solver.mcp.client import McpStdioClient
    from tests.support.proc import child_env

    env = child_env(CTF_SOLVER_IPC_URL=ipc_url, CTF_SOLVER_WORKER_TOKEN=token)
    client = McpStdioClient(
        [sys.executable, "-m", "ctf_solver.mcp.exec_server"],
        env=env,
        cwd=str(REPO),
        request_timeout=90.0,
    )
    client.start()
    client.initialize()
    return client


def direct_exec(client, task, worker, step_id: str, tool: str, argv: list[str], **extra) -> dict:
    arguments = {
        "task_id": task.task_id,
        "worker_id": worker.worker_id,
        "step_id": step_id,
        "tool_name": tool,
        "argv": argv,
        "cwd": task.workspace_path,
    }
    arguments.update(extra)
    is_error, payload = client.call_tool("ctf_exec", arguments)
    if is_error:
        raise RuntimeError(f"ctf_exec tool error: {payload}")
    return payload


def _process_ancestor_pids(pid: int) -> set[int]:
    """Return the process ancestor chain (best effort, read-only)."""

    script = (
        "Get-CimInstance Win32_Process | "
        "Select-Object ProcessId,ParentProcessId | ConvertTo-Json -Compress"
    )
    try:
        completed = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
        )
    except Exception:  # noqa: BLE001
        return set()
    try:
        rows = json.loads(completed.stdout or "[]")
    except ValueError:
        return set()
    if isinstance(rows, dict):
        rows = [rows]
    parents = {int(row["ProcessId"]): int(row["ParentProcessId"]) for row in rows}
    chain: set[int] = set()
    current = int(pid)
    for _ in range(16):
        parent = parents.get(current)
        if parent is None or parent in chain:
            break
        chain.add(parent)
        current = parent
    return chain


def write_privacy_mechanism_evidence(acp_command: list[str], dsh_home: str) -> dict:
    """Verify the *actual* Manager ACP argv and its effective isolated config.

    Evidence A: the command reported by the live Manager ACP client contains
    ``--profile acp --patch <absolute project patch>``.
    Evidence B: running that same launcher argv (plus ``--dump-config``) in the
    same isolated DSH_HOME composes a profile where the delivery plugin is
    disabled. This is configuration proof, NOT the external-delivery canary
    (which remains BLOCKED without a model request).
    """

    from ctf_solver.core.config import SolverConfig

    config = SolverConfig(root=REPO, extra={"dsh_home": dsh_home})
    patch_path = config.privacy_patch_path
    command = list(acp_command)
    evidence_a = {
        "manager_argv": command,
        "profile_args_present": "--profile" in command and "acp" in command,
        "patch_arg_present": "--patch" in command,
        "patch_path": command[command.index("--patch") + 1] if "--patch" in command else None,
        "patch_is_absolute": bool(
            "--patch" in command and Path(command[command.index("--patch") + 1]).is_absolute()
        ),
        "patch_is_project_file": bool(
            "--patch" in command
            and Path(command[command.index("--patch") + 1]).resolve() == patch_path.resolve()
        ),
    }
    dump = RAW / "round2-privacy-gate-dump-config.txt"
    err = RAW / "round2-privacy-gate-stderr.txt"
    env = dict(os.environ)
    env["DSH_HOME"] = str(dsh_home)
    completed = subprocess.run(
        [*command, "--dump-config"],
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
    )
    dump.write_text(completed.stdout, encoding="utf-8")
    err.write_text(completed.stderr, encoding="utf-8")
    composed = "- id: session-log-deepseek" in completed.stdout and "enabled: false" in completed.stdout
    result = {
        "evidence_a_manager_argv": evidence_a,
        "evidence_b": {
            "exit_code": completed.returncode,
            "composed_config_disables_delivery": composed,
            "dump_config_stdout_sha256": __import__("hashlib").sha256(
                completed.stdout.encode("utf-8")
            ).hexdigest(),
        },
        "isolated_home": str(dsh_home),
        "negative_outbound_canary": "BLOCKED: requires a model request; no model call is authorized",
        "can_be_called_delivery_verified": False,
    }
    (RAW / "round2-privacy-gate-result.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return result


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keep-runtime", action="store_true")
    parser.add_argument("--json-out", default=str(RAW / "round2-integration-summary.json"))
    args = parser.parse_args(argv)

    RAW.mkdir(parents=True, exist_ok=True)
    END_TO_END.mkdir(parents=True, exist_ok=True)

    from ctf_solver.core.config import SolverConfig
    from ctf_solver.delivery.bundle import EvidenceBundleBuilder
    from ctf_solver.core.protocols import SystemClock
    from ctf_solver.manager.service import ManagerService
    from ctf_solver.wiring import build_manager_service, default_acp_factory

    probe = None
    service = None
    service2 = None
    exec_clients: list = []
    summary: dict = {"started_at": datetime.now(timezone.utc).isoformat(), "steps": {}}
    try:
        if RUNTIME.exists():
            shutil.rmtree(RUNTIME, ignore_errors=True)
        INTAKE.mkdir(parents=True, exist_ok=True)
        for task_dir in TASKS.glob("t-*"):
            shutil.rmtree(task_dir, ignore_errors=True)

        probe, probe_info = run_window_probe("CTF-Solver Round 2 synthetic evidence")
        probe_pid = int(probe_info["process_pid"])

        config = SolverConfig(
            root=REPO,
            capture_mode="real-window",
            target_window_pid=probe_pid,
            extra={
                "dsh_home": str(RUNTIME / "r2-dsh-home"),
                "mcp_handshake_dir": str(RUNTIME / "r2-handshakes"),
                "intake_dir": str(INTAKE),
            },
        )
        config.ensure_runtime_dirs()
        service = build_manager_service(config)
        status = service.start()
        check("real ACP client ready", status["acp"]["ready"] is True, json.dumps(status["acp"]["diagnostics"])[:300])
        acp_command = list(status["acp"]["diagnostics"].get("command") or [])
        check("ACP launch uses --profile acp", "--profile" in acp_command and "acp" in acp_command, str(acp_command))
        check(
            "Manager ACP argv composes abs project privacy patch",
            "--patch" in acp_command
            and Path(acp_command[acp_command.index("--patch") + 1]).is_absolute()
            and Path(acp_command[acp_command.index("--patch") + 1]).resolve()
            == config.privacy_patch_path.resolve(),
            str(acp_command),
        )
        summary["steps"]["start"] = status

        # --- real sessions + FIFO -------------------------------------------------
        t1 = service.create_task(title="Round2 real-ACP task A", category="misc", conversation_id="conv-r2")
        t2 = service.create_task(title="Round2 real-ACP task B", category="web", conversation_id="conv-r2")
        t3 = service.create_task(title="Round2 FIFO task C", category="crypto", conversation_id="conv-r2")
        check("two Workers active and third queued", [t1.status.value, t2.status.value, t3.status.value] == ["running", "running", "queued"], f"{t1.status.value},{t2.status.value},{t3.status.value}")
        check("distinct real ACP sessions", len({t1.acp_session_id, t2.acp_session_id}) == 2, f"{t1.acp_session_id} / {t2.acp_session_id}")
        check("distinct workspaces", t1.workspace_path != t2.workspace_path)

        # per-session MCP handshake files written by the real ACP-spawned exec servers
        handshake_dir = Path(config.extra["mcp_handshake_dir"])
        deadline = time.time() + 45
        while time.time() < deadline:
            if all((handshake_dir / f"{task.task_id}.json").is_file() for task in (t1, t2)):
                break
            time.sleep(0.5)
        handshakes = {}
        for task in (t1, t2):
            path = handshake_dir / f"{task.task_id}.json"
            handshakes[task.task_id] = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else None
        check(
            "real ACP-spawned MCP child completed initialize + tools/list",
            all(
                handshakes[task.task_id]
                and handshakes[task.task_id].get("initialize_received") is True
                and handshakes[task.task_id].get("tools_list_received") is True
                and handshakes[task.task_id].get("tool_names") == ["ctf_exec"]
                for task in (t1, t2)
            ),
            json.dumps({k: v for k, v in handshakes.items() if v}, ensure_ascii=False)[:600],
        )
        worker1 = service.store.get_worker_for_task(t1.task_id)
        worker2 = service.store.get_worker_for_task(t2.task_id)
        import hashlib

        expected = hashlib.sha256(worker1.worker_token.encode("utf-8")).hexdigest()
        check("MCP handshake identity matches Worker token", handshakes[t1.task_id]["worker_token_sha256"] == expected)
        check("MCP handshake records owning Task id", handshakes[t1.task_id].get("task_id") == t1.task_id)
        check("MCP handshake protocol version recorded", bool(handshakes[t1.task_id].get("protocol_version")))
        acp_pid = int(status["acp"]["diagnostics"].get("pid") or 0)
        handshake_pid = int(handshakes[t1.task_id]["pid"])
        ancestors = _process_ancestor_pids(handshake_pid)
        check(
            "handshake PID descends from the ACP server process",
            acp_pid > 0 and (acp_pid == handshake_pid or acp_pid in ancestors),
            json.dumps({"handshake_pid": handshake_pid, "acp_pid": acp_pid, "ancestors": sorted(ancestors)[:10]}),
        )

        # --- direct MCP tools/call (same interface a model Worker uses) ----------
        synthetic = Path(t1.workspace_path) / "synthetic.txt"
        synthetic.write_text("synthetic content for round2 integration\n", encoding="utf-8")
        exec_client = start_exec_mcp_client(service.ipc_url, worker1.worker_token)
        exec_clients.append(exec_client)
        result = direct_exec(exec_client, t1, worker1, "step-hash-1", "internal.file_hash", ["synthetic.txt"])
        from ctf_solver.core.canonical import file_sha256

        digest = file_sha256(synthetic)
        parsed_preview = json.loads(result["stdout_preview"])
        check("direct MCP tools/call executes typed trusted tool", result["status"] == "completed" and parsed_preview.get("sha256") == digest, result["status"])
        denied = direct_exec(
            exec_client, t1, worker1, "step-denied-1", "tool.remote_probe", ["example.invalid"],
            network_target={"host": "example.invalid", "port": 80, "protocol": "tcp", "method": "GET"},
        )
        check("denied typed execution fails closed", denied["status"] in {"denied", "blocked"} and bool(denied["reason_code"]), denied["reason_code"])

        # --- real Harness session log ingestion (registry-derived) ----------------
        worker_dir_hint = service.config.session_log_root
        log_files = sorted(worker_dir_hint.rglob("session.v4.jsonl.zstd"))
        check("real Harness wrote session log(s)", bool(log_files), f"{len(log_files)} file(s) under {worker_dir_hint}")
        ingest = service.ingest_session_log(t1.task_id)
        check("real session log ingested via registry", ingest.get("frames", 0) >= 1, json.dumps({k: ingest.get(k) for k in ("frames", "decoded_records", "appended", "gaps")}))
        ingest2 = service.ingest_session_log(t1.task_id)
        check("session log ingestion idempotent", ingest2.get("appended") == 0, str(ingest2.get("appended")))

        # skill catalog discovery inside the real Harness session log (may require a turn)
        skill_hits = {}
        for name in ("ctf-solver", "ctf-web", "ctf-misc", "ctf-crypto", "ctf-reverse", "ctf-pwn"):
            count = 0
            for log_file in log_files:
                try:
                    records, _ = decode_session_log_records(log_file)
                except Exception:  # noqa: BLE001
                    continue
                count += sum(1 for record in records if name in json.dumps(record, ensure_ascii=False))
            skill_hits[name] = count
        summary["steps"]["skill_catalog_occurrences_in_real_session_logs"] = skill_hits
        check(
            "project-level Skills appear in real Harness session logs",
            all(skill_hits[name] > 0 for name in ("ctf-solver", "ctf-web", "ctf-misc", "ctf-crypto", "ctf-reverse", "ctf-pwn")),
            json.dumps(skill_hits),
        ) if all(skill_hits.values()) else NOTES.append(
            "Skill catalog strings were not found in the real ACP session logs (no model turn); "
            "live discovery evidence remains the current interactive session log from Round 1 + format checks."
        )

        # --- real window screenshot ----------------------------------------------
        shot = service.take_screenshot(t1.task_id, step_id="step-hash-1", scope="window")
        check("real project-owned window screenshot captured", shot.status.value == "ok" and bool(shot.sha256) and shot.width and shot.width > 100, f"status={shot.status.value} size={shot.width}x{shot.height} sha={shot.sha256}")
        if shot.sha256:
            check("screenshot bytes stored in CAS", service.evidence.verify_artifact(shot.sha256) if hasattr(service.evidence, "verify_artifact") else service.evidence.cas.verify(shot.sha256))

        # --- candidate flag + deliverables for task A -----------------------------
        service.record_candidate_flag(t1.task_id, flag="flag{synthetic_round2_real_acp}", source="synthetic-fixture")
        writeup_info = service.build_writeup(t1.task_id)
        zip_info = service.export_evidence_zip(t1.task_id)
        check("Writeup generated", Path(writeup_info.path).is_file() and Path(writeup_info.path).stat().st_size > 500)
        check("evidence ZIP generated", Path(zip_info.path).is_file() and Path(zip_info.path).stat().st_size > 1000)
        verify = EvidenceBundleBuilder.verify_zip(zip_info.path, RUNTIME / "r2-zip-verify")
        check("evidence ZIP manifest independently verified", verify["ok"], json.dumps(verify["problems"])[:400])

        # --- FIFO promotion -------------------------------------------------------
        cancelled = service.cancel_task(t2.task_id, reason="round2 integration FIFO evidence")
        check("cancel confirms quiescence", cancelled["status"] == "cancelled" and cancelled["quiescent"] is True)
        promoted = service.get_task(t3.task_id)
        check("FIFO task promoted to running", promoted.status.value == "running", promoted.status.value)
        handshake3 = handshake_dir / f"{t3.task_id}.json"
        deadline = time.time() + 30
        while time.time() < deadline and not handshake3.is_file():
            time.sleep(0.3)
        check("promoted task received its own ACP session + MCP mount", handshake3.is_file())

        # free a slot for the synthetic end-to-end task
        service.cancel_task(t1.task_id, reason="round2 evidence complete for task A")

        # --- synthetic end-to-end challenge (normal completion lifecycle) --------
        intake_file = INTAKE / "round2_synthetic_challenge.txt"
        intake_file.write_text(
            "CTF-SOLVER ROUND 2 SYNTHETIC CHALLENGE\n"
            "Category: misc\n"
            "This is a synthetic local challenge used for evidence only.\n"
            "Clue: search this file for the marker prefix and recover the candidate flag.\n"
            "candidate: flag{synthetic_round2_e2e}\n",
            encoding="utf-8",
        )
        e2e = service.create_task(
            title="Synthetic Round 2 end-to-end challenge",
            category="misc",
            conversation_id="conv-r2",
            source="synthetic-local",
            scope_profile="synthetic-local",
            notes="Synthetic local challenge for Round 2 end-to-end evidence.",
            supplied_files=["round2_synthetic_challenge.txt"],
        )
        check("synthetic challenge task created with imported input", e2e.status.value == "running" and bool(e2e.acp_session_id))
        e2e_worker = service.store.get_worker_for_task(e2e.task_id)
        exec_client2 = start_exec_mcp_client(service.ipc_url, e2e_worker.worker_token)
        exec_clients.append(exec_client2)
        independent_mcp_pid = exec_client2.pid
        e2e_input = Path(e2e.workspace_path) / "inputs" / "round2_synthetic_challenge.txt"
        check("imported challenge file exists in isolated Task workspace", e2e_input.is_file())
        hash_result = direct_exec(exec_client2, e2e, e2e_worker, "e2e-hash", "internal.file_hash", ["inputs/round2_synthetic_challenge.txt"])
        search_result = direct_exec(
            exec_client2, e2e, e2e_worker, "e2e-search", "internal.text_search",
            ["flag{", "inputs/round2_synthetic_challenge.txt"],
        )
        preview = search_result.get("stdout_preview", "")
        check("typed tools produced real evidence", hash_result["status"] == "completed" and "flag{" in preview, preview[:160])
        candidate = "flag{synthetic_round2_e2e}"
        check("candidate flag recovered from real tool output", candidate in preview)
        handshake_e2e_path = handshake_dir / f"{e2e.task_id}.json"
        deadline = time.time() + 30
        while time.time() < deadline and not handshake_e2e_path.is_file():
            time.sleep(0.3)
        handshake_e2e = (
            json.loads(handshake_e2e_path.read_text(encoding="utf-8"))
            if handshake_e2e_path.is_file()
            else {}
        )
        check(
            "E2E ACP-spawned MCP child initialized and listed tools",
            handshake_e2e.get("initialize_received") is True
            and handshake_e2e.get("tools_list_received") is True
            and handshake_e2e.get("tool_names") == ["ctf_exec"],
            json.dumps(handshake_e2e, ensure_ascii=False)[:400],
        )
        check(
            "E2E independent MCP tools/call process differs from ACP-spawned child",
            bool(independent_mcp_pid) and independent_mcp_pid != handshake_e2e.get("pid"),
            json.dumps({"independent_mcp_pid": independent_mcp_pid, "acp_child_pid": handshake_e2e.get("pid")}),
        )
        NOTES.append(
            "tools/call for the synthetic E2E was executed by an independent MCP stdio "
            "process (ctf-exec identity from the real Worker token), while initialize/"
            "tools-list evidence comes from the actual ACP-spawned child. Under the "
            "zero-model-call gate, same-child tools/call is NOT VERIFIED."
        )
        banner, banner_info = run_window_probe("Round 2 E2E | " + candidate)
        try:
            service.capturer.set_target_pid(int(banner_info["process_pid"]))
            e2e_shot = service.take_screenshot(e2e.task_id, step_id="e2e-search", scope="window")
            check("E2E screenshot of synthetic program window", e2e_shot.status.value == "ok" and bool(e2e_shot.sha256), f"{e2e_shot.status.value} {e2e_shot.width}x{e2e_shot.height}")
            service.record_candidate_flag(e2e.task_id, flag=candidate, source="internal.text_search output")
            ingest_e2e = service.ingest_session_log(e2e.task_id)
            check("E2E real session log ingested before completion", int(ingest_e2e.get("frames", 0)) >= 1, json.dumps(ingest_e2e)[:300])
            completion = service.complete_task(
                e2e.task_id, result_state="solved_flag_candidate", note="synthetic E2E completed"
            )
            check(
                "E2E Task reaches completed terminal state",
                completion["status"] == "completed"
                and completion["session_closed"] is True
                and completion["slot_released"] is True
                and completion["result_state"] == "solved_flag_candidate",
                json.dumps(completion)[:400],
            )
            completed_task = service.get_task(e2e.task_id)
            check(
                "E2E completed Task has real ended_at and concrete result_state",
                completed_task.status.value == "completed"
                and bool(completed_task.ended_at)
                and completed_task.result_state == "solved_flag_candidate",
                json.dumps({"status": completed_task.status.value, "ended_at": completed_task.ended_at, "result_state": completed_task.result_state}),
            )
            e2e_writeup = service.build_writeup(e2e.task_id)
            e2e_zip = service.export_evidence_zip(e2e.task_id)
            writeup_text = Path(e2e_writeup.path).read_text(encoding="utf-8")
            check(
                "E2E Writeup shows completed status and concrete result_state",
                "- Status: `completed`" in writeup_text
                and "- Result state: `solved_flag_candidate`" in writeup_text
                and "Result state: `unknown`" not in writeup_text
                and "Status: `running`" not in writeup_text,
                writeup_text[:400],
            )
            verify_e2e = EvidenceBundleBuilder.verify_zip(e2e_zip.path, RUNTIME / "r2-e2e-zip-verify")
            check("E2E evidence ZIP verifies", verify_e2e["ok"], json.dumps(verify_e2e["problems"])[:300])
            import zipfile

            with zipfile.ZipFile(e2e_zip.path) as archive:
                names = archive.namelist()
            check(
                "E2E ZIP contains final Writeup + manifest",
                any(name.endswith("writeup.md") for name in names)
                and any("manifest" in name.lower() for name in names),
                json.dumps(names)[:400],
            )
            # copy deliverables into the committed evidence directory
            shutil.copy2(e2e_writeup.path, END_TO_END / "writeup.md")
            shutil.copy2(e2e_zip.path, END_TO_END / "evidence.zip")
            shutil.copy2(intake_file, END_TO_END / "synthetic_challenge_input.txt")
            if e2e_shot.sha256:
                try:
                    shot_bytes = service.evidence.cas.get_bytes(e2e_shot.sha256)
                    (END_TO_END / "screenshot.png").write_bytes(shot_bytes)
                except Exception as exc:  # noqa: BLE001
                    NOTES.append(f"could not export screenshot bytes: {exc}")
            summary["e2e"] = {
                "task_id": e2e.task_id,
                "final_status": completed_task.status.value,
                "result_state": completed_task.result_state,
                "ended_at": completed_task.ended_at,
                "writeup": str(END_TO_END / "writeup.md"),
                "zip": str(END_TO_END / "evidence.zip"),
                "candidate_flag": candidate,
                "screenshot_sha256": e2e_shot.sha256,
                "acp_child_pid": handshake_e2e.get("pid"),
                "independent_mcp_pid": independent_mcp_pid,
                "note": (
                    "Worker tool calls were executed through the typed MCP ctf_exec "
                    "interface by an independent MCP process; no model call. ACP-spawned "
                    "child initialize/tools-list is separately verified; same-child "
                    "tools/call is NOT VERIFIED under the zero-model-call gate."
                ),
            }
        finally:
            banner.terminate()
            try:
                banner.wait(timeout=10)
            except subprocess.TimeoutExpired:
                banner.kill()
            banner.stdout.close() if banner.stdout else None
            banner.stderr.close() if banner.stderr else None

        # --- restart recovery without duplicate sessions --------------------------
        # Normal E2E completion already happened above; only the still-running FIFO
        # task may be marked interrupted by the restart.
        active_before = [t for t in (promoted,) if service.get_task(t.task_id).status.value == "running"]
        session_ids_before = {t.task_id: service.get_task(t.task_id).acp_session_id for t in active_before}
        completed_before_restart = service.get_task(e2e.task_id).status.value
        service.shutdown()
        service = None
        service2 = build_manager_service(config)
        service2.capturer = service.capturer if service else service2.capturer
        status2 = service2.start()
        recovered = {t.task_id: service2.get_task(t.task_id).status.value for t in active_before}
        check(
            "restart recovery marks active tasks interrupted (never completed)",
            all(value == "interrupted" for value in recovered.values()),
            json.dumps(recovered),
        )
        duplicate_created = False
        for task in active_before:
            current = service2.get_task(task.task_id)
            if current.acp_session_id != session_ids_before[task.task_id]:
                duplicate_created = True
        check("restart recovery creates no duplicate sessions", not duplicate_created)
        check("interrupted tasks are not reported complete", all(service2.get_task(t.task_id).status.value != "completed" for t in active_before))
        check(
            "restart keeps completed E2E Task completed (not interrupted)",
            completed_before_restart == "completed"
            and service2.get_task(e2e.task_id).status.value == "completed",
            json.dumps({"before": completed_before_restart, "after": service2.get_task(e2e.task_id).status.value}),
        )

        # privacy mechanism evidence (actual Manager argv + isolated effective config;
        # the external-delivery canary remains BLOCKED without a model request)
        privacy = write_privacy_mechanism_evidence(acp_command, config.extra["dsh_home"])
        check(
            "Manager ACP argv evidence A: --profile acp --patch <abs project patch>",
            privacy["evidence_a_manager_argv"]["profile_args_present"]
            and privacy["evidence_a_manager_argv"]["patch_arg_present"]
            and privacy["evidence_a_manager_argv"]["patch_is_absolute"]
            and privacy["evidence_a_manager_argv"]["patch_is_project_file"],
            json.dumps(privacy["evidence_a_manager_argv"])[:400],
        )
        check(
            "isolated effective config evidence B disables session-log delivery",
            privacy["evidence_b"]["exit_code"] == 0
            and privacy["evidence_b"]["composed_config_disables_delivery"] is True,
            json.dumps(privacy["evidence_b"]),
        )
        NOTES.append(privacy["negative_outbound_canary"])

        summary["steps"]["fifo"] = {
            "t1": t1.task_id, "t2": t2.task_id, "t3": t3.task_id,
            "cancelled_t2": cancelled["status"], "promoted_t3": promoted.status.value,
        }
        summary["steps"]["session_logs"] = {"count": len(log_files), "root": str(worker_dir_hint)}
        summary["steps"]["privacy_gate"] = privacy
        summary["steps"]["restart_recovery"] = recovered
        summary["steps"]["acp_child_mcp_mount"] = {
            key: {k: value for k, value in handshake.items() if k != "worker_token_sha256"}
            for key, handshake in handshakes.items()
            if handshake
        }
        summary["steps"]["completion"] = {
            "e2e_status": service2.get_task(e2e.task_id).status.value,
            "result_state": service2.get_task(e2e.task_id).result_state,
            "ended_at": service2.get_task(e2e.task_id).ended_at,
            "independent_mcp_tools_call": independent_mcp_pid,
            "acp_spawned_child_pid": handshake_e2e.get("pid"),
            "same_child_tools_call": "NOT VERIFIED (zero-model-call gate)",
        }
        summary["passed"] = [item["name"] for item in PASS]
        summary["failed"] = FAIL
        summary["notes"] = NOTES
        summary["finished_at"] = datetime.now(timezone.utc).isoformat()
        summary["model_calls"] = 0
        summary["session_prompt_calls"] = 0
        summary["real_ctf_targets"] = 0
        Path(args.json_out).write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        (RAW / "round2-integration.log").write_text("\n".join(LOGS) + "\n", encoding="utf-8")
        log(f"PASS={len(PASS)} FAIL={len(FAIL)}; summary -> {args.json_out}")
        return 0 if not FAIL else 1
    except Exception:
        summary["failed"] = FAIL + [{"name": "unhandled_exception", "detail": traceback.format_exc()[-3000:]}]
        summary["passed"] = [item["name"] for item in PASS]
        summary["notes"] = NOTES
        Path(args.json_out).write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        (RAW / "round2-integration.log").write_text("\n".join(LOGS) + "\n" + traceback.format_exc(), encoding="utf-8")
        traceback.print_exc()
        return 2
    finally:
        for client in exec_clients:
            try:
                client.close()
            except Exception:  # noqa: BLE001
                pass
        for svc in (service2, service):
            if svc is not None:
                try:
                    svc.close()
                except Exception:  # noqa: BLE001
                    try:
                        svc.shutdown()
                    except Exception:  # noqa: BLE001
                        pass
        if probe is not None:
            try:
                probe.terminate()
                probe.wait(timeout=10)
            except Exception:  # noqa: BLE001
                try:
                    probe.kill()
                except Exception:  # noqa: BLE001
                    pass
            for stream in (probe.stdout, probe.stderr):
                try:
                    if stream:
                        stream.close()
                except Exception:  # noqa: BLE001
                    pass
        if not args.keep_runtime:
            # Runtime data is git-ignored; remove it so the repository stays clean.
            try:
                for task_dir in TASKS.glob("t-*"):
                    shutil.rmtree(task_dir, ignore_errors=True)
                shutil.rmtree(RUNTIME, ignore_errors=True)
                for path in INTAKE.glob("*"):
                    shutil.rmtree(path, ignore_errors=True) if path.is_dir() else path.unlink(missing_ok=True)
            except OSError:
                pass


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
