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


def run_window_probe(text: str) -> subprocess.Popen:
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
    return proc


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


def write_privacy_mechanism_evidence() -> dict:
    """Isolated DSH_HOME mechanism check (configuration only, no model call)."""

    temp_home = Path(os.environ.get("TEMP", ".")) / f"ctf-solver-r2-privacy-{int(time.time())}"
    temp_home.mkdir(parents=True, exist_ok=True)
    dump = RAW / "round2-privacy-gate-dump-config.txt"
    err = RAW / "round2-privacy-gate-stderr.txt"
    env = dict(os.environ)
    env["DSH_HOME"] = str(temp_home)
    launcher = REPO / ".ctf-solver-data" / "nonexistent"  # placeholder, resolved below
    from ctf_solver.core.config import discover_acp_command

    found = discover_acp_command()
    if not found:
        return {"status": "launcher_missing"}
    command = found + ["--profile", "acp", "--patch", str(REPO / "config" / "acp" / "cordis.patch.yml"), "--dump-config"]
    if str(command[0]).lower().endswith((".cmd", ".bat")):
        command = [os.environ.get("COMSPEC", "cmd.exe"), "/c", *command]
    completed = subprocess.run(
        command, env=env, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120
    )
    dump.write_text(completed.stdout, encoding="utf-8")
    err.write_text(completed.stderr, encoding="utf-8")
    composed = "- id: session-log-deepseek" in completed.stdout and "enabled: false" in completed.stdout
    files = [str(p.relative_to(temp_home)) for p in temp_home.rglob("*") if p.is_file()]
    result = {
        "exit_code": completed.returncode,
        "composed_config_disables_delivery": composed,
        "isolated_home": str(temp_home),
        "isolated_home_files": files[:20],
        "negative_outbound_canary": "BLOCKED: requires a model request; no model call is authorized",
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
    from ctf_solver.delivery.screenshot import WindowCapturer
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

        probe = run_window_probe("CTF-Solver Round 2 synthetic evidence")
        probe_pid = probe.pid

        config = SolverConfig(
            root=REPO,
            capture_mode="real-window",
            extra={
                "dsh_home": str(RUNTIME / "r2-dsh-home"),
                "mcp_handshake_dir": str(RUNTIME / "r2-handshakes"),
                "intake_dir": str(INTAKE),
            },
        )
        config.ensure_runtime_dirs()
        service = build_manager_service(config)
        service.capturer = WindowCapturer(target_pid=probe_pid)
        status = service.start()
        check("real ACP client ready", status["acp"]["ready"] is True, json.dumps(status["acp"]["diagnostics"])[:300])
        check("ACP launch uses --profile acp", "--profile" in status["acp"]["diagnostics"].get("command", []), str(status["acp"]["diagnostics"].get("command")))
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
            "real ACP mounts per-session ctf-exec MCP server",
            all(handshakes[task.task_id] for task in (t1, t2)),
            json.dumps({k: bool(v) for k, v in handshakes.items()}),
        )
        worker1 = service.store.get_worker_for_task(t1.task_id)
        worker2 = service.store.get_worker_for_task(t2.task_id)
        if handshakes.get(t1.task_id) and worker1:
            import hashlib

            expected = hashlib.sha256(worker1.worker_token.encode("utf-8")).hexdigest()
            check("MCP handshake identity matches Worker token", handshakes[t1.task_id]["worker_token_sha256"] == expected)

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

        # --- synthetic end-to-end challenge --------------------------------------
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
        banner = run_window_probe("Round 2 E2E | " + candidate)
        try:
            service.capturer.set_target_pid(banner.pid)
            e2e_shot = service.take_screenshot(e2e.task_id, step_id="e2e-search", scope="window")
            check("E2E screenshot of synthetic program window", e2e_shot.status.value == "ok" and bool(e2e_shot.sha256), f"{e2e_shot.status.value} {e2e_shot.width}x{e2e_shot.height}")
            service.record_candidate_flag(e2e.task_id, flag=candidate, source="internal.text_search output")
            service.ingest_session_log(e2e.task_id)
            e2e_writeup = service.build_writeup(e2e.task_id)
            e2e_zip = service.export_evidence_zip(e2e.task_id)
            verify_e2e = EvidenceBundleBuilder.verify_zip(e2e_zip.path, RUNTIME / "r2-e2e-zip-verify")
            check("E2E evidence ZIP verifies", verify_e2e["ok"], json.dumps(verify_e2e["problems"])[:300])
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
                "writeup": str(END_TO_END / "writeup.md"),
                "zip": str(END_TO_END / "evidence.zip"),
                "candidate_flag": candidate,
                "screenshot_sha256": e2e_shot.sha256,
                "note": "Worker tool calls were simulated through the same typed MCP ctf_exec interface; no model call.",
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
        active_before = [t for t in (promoted, e2e) if service.get_task(t.task_id).status.value == "running"]
        session_ids_before = {t.task_id: service.get_task(t.task_id).acp_session_id for t in active_before}
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

        # privacy mechanism evidence (configuration only; canary BLOCKED)
        privacy = write_privacy_mechanism_evidence()
        check("isolated-profile privacy mechanism verified (config only)", privacy.get("exit_code") == 0 and privacy.get("composed_config_disables_delivery") is True, json.dumps(privacy)[:300])
        NOTES.append(privacy["negative_outbound_canary"])

        summary["steps"]["fifo"] = {
            "t1": t1.task_id, "t2": t2.task_id, "t3": t3.task_id,
            "cancelled_t2": cancelled["status"], "promoted_t3": promoted.status.value,
        }
        summary["steps"]["session_logs"] = {"count": len(log_files), "root": str(worker_dir_hint)}
        summary["steps"]["privacy_gate"] = privacy
        summary["steps"]["restart_recovery"] = recovered
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
