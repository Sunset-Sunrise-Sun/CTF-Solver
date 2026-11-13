# CTF-Solver — Local Operation (v0.1.1)

This document describes the actual CLI and local operation modes of the v0.1.1
installation-hardening candidate. It distinguishes:

- **source checkout mode**: run from a Git checkout / extracted source tree;
- **installed wheel mode**: install the wheel into a venv and run from any directory.

The two modes use the **same package-resource privacy patch**
(`ctf_solver/resources/acp/cordis.patch.yml`). The former repository-level
`config/acp/cordis.patch.yml` is intentionally removed as a second source of truth. Do not
edit the live global Harness profile.

Python: `>=3.11`; accepted/tested on Python 3.14.7 Windows. Python 3.14+ has standard-library
`compression.zstd`; Python 3.11–3.13 requires the optional `zstandard` package for multi-frame
session-log ingestion (otherwise evidence ingestion fails closed). See `INSTALL.md`.

## 1. Read-only preflight / doctor

```powershell
python -m ctf_solver preflight
python -m ctf_solver preflight --json .\preflight.json --text .\preflight.txt
python -m ctf_solver skills
```

The preflight reports OS/runtime facts, the audited ACP launcher, available/missing tools,
Skill format, the session-log privacy gate and isolation status. It never installs, configures
or starts anything. It also resolves the package-resource privacy patch and never reads a
second copy.

`skills` reports the six project Skills in `<root>/.dsh/skills`; missing Skills return exit 1
with an honest `ok:false` report.

## 2. Manager control MCP server

```powershell
python -m ctf_solver manager serve --root . --capture-mode desktop
```

The public `manager serve` CLI accepts `--root`, `--capture-mode`, `--target-window-pid`,
`--lead-sessions-root` and `--session-log-root`. There is no public `--acp-command`,
`--max-workers` or `--dsh-home` flag on this wrapper.
For advanced/test deployment, the module entry point
`python -m ctf_solver.mcp.manager_server` exposes its own arguments (`--root`,
`--capture-mode`, `--max-workers`, `--dsh-home`, `--session-log-root`, `--intake-dir`), but
this is a module-level entry, not the public `ctf-solver manager serve` CLI.

- Speaks MCP over stdio (newline-delimited JSON-RPC 2.0); stdout is protocol-only, logs go
  to stderr.
- Starts the loopback IPC endpoint used by Worker `ctf-exec` servers, then the managed ACP
  client, then recovers durable state.
- By default the managed ACP server uses a **project-local isolated** `DSH_HOME`
  (`.ctf-solver-data/dsh-home`, git-ignored), never the live `~/.dsh` unless the owner
  explicitly authorizes a real Harness home.
- The Manager control MCP exposes exactly **18** tools: `ctf_task_create`, `ctf_task_list`,
  `ctf_task_status`, `ctf_task_continue`, `ctf_task_pause`, `ctf_task_cancel`,
  `ctf_task_complete`, `ctf_approval_request`, `ctf_approval_list`, `ctf_grant_list`,
  `ctf_grant_revoke`, `ctf_flag_candidate`, `ctf_screenshot_capture`, `ctf_session_ingest`,
  `ctf_events_export`, `ctf_writeup_build`, `ctf_evidence_zip`, `ctf_runtime_status`.
  Approval decisions and grant creation are human-only and are deliberately **not** MCP tools.
- The Manager never exposes `session/prompt`; `ctf_task_continue` records the continuation
  and reports model-call suppression. Model-driven Workers remain blocked by ADR-020.

### ACP failure behavior

ACP is mandatory for starting a Worker. When the privacy patch is missing, the launcher is
absent, or ACP startup fails, `task create` / MCP `ctf_task_create` fail explicitly with
`reason_code=acp_unavailable` and **do not persist a Task**. If ACP exits after a Task was
created, the Task is marked `interrupted`, the Worker `crashed`, and the failure is recorded
in diagnostics/evidence. Legitimate FIFO queuing (two active Workers, third Task waiting) is
unchanged.

## 3. Worker `ctf-exec` MCP server

In normal operation the Manager injects this server into each Task's
`session/new.mcpServers` with a per-Worker token. To exercise it manually against a running
Manager IPC endpoint:

```powershell
$env:CTF_SOLVER_IPC_URL = "tcp://127.0.0.1:<port-from-ctf_runtime_status>"
$env:CTF_SOLVER_WORKER_TOKEN = "<per-Worker token>"
python -m ctf_solver worker-mcp
```

The server exposes exactly one typed tool, `ctf_exec`. Identity comes from the environment,
never from tool arguments; missing/invalid token fails closed.

## 4. Local Task operations (single process)

```powershell
python -m ctf_solver task create --root . --title "Synthetic misc" --category misc `
    --conversation-id local --supplied-file challenge.zip
python -m ctf_solver task list --root .
python -m ctf_solver task status --root . --task-id <task-id>
```

These start the real wiring (Manager + ACP client + Broker/Runtime + SQLite/CAS) and shut it
down afterwards. They make no model calls. Challenge files must be relative to
`<root>/challenge-uploads`; absolute host paths are rejected.

## 4b. Human approval console and target grants

Approval decisions and network grants are human-only and are not MCP tools. They require a
real interactive TTY; MCP/agent/pipe contexts fail closed:

```powershell
python -m ctf_solver approval list --root .
python -m ctf_solver approval confirm --root . --approval-id <approval-id>
python -m ctf_solver approval reject --root . --approval-id <approval-id> --note "not authorized"

python -m ctf_solver grant create --root . --approval-id <approval-id> `
    --competition-profile synthetic-local --host 127.0.0.1 --port 31337 `
    --protocol tcp --method GET --ttl-s 600 --max-calls 5
python -m ctf_solver grant list --root .
python -m ctf_solver grant revoke --root . --grant-id <grant-id>
```

Replay, expiry, cross-Task use, digest mismatch and double consumption fail closed.

## 5. Evidence helpers

```powershell
python -m ctf_solver evidence decode .\path\to\session.v4.jsonl.zstd
python -m ctf_solver evidence verify-chain --root .
```

On Python 3.14+ zstd uses the standard-library backend; on Python 3.11–3.13 install the
optional `zstandard` package first, otherwise ingestion is blocked with a clear diagnostic.

## 6. Tests and wheel build

```powershell
# Full deterministic suite (fake ACP/MCP; real ACP smoke opt-in)
python -m pytest tests -q -p no:cacheprovider

# Include the zero-model-call real Harness ACP smoke test
$env:CTF_SOLVER_ENABLE_REAL_ACP = '1'
python -m pytest tests -q -p no:cacheprovider

# Real-Harness integration evidence (zero model calls)
python scripts/round2_integration.py

# Wheel build (in-tree stdlib PEP 517 backend; no installation)
python scripts/build_wheel.py
```

Run the full suite from a **Git checkout**, not a ZIP-extracted tree: one JUnit evidence test
reads Git-tracked files, and the source ZIP intentionally has no `.git` history. The release
ZIP is for inspection/installation; the wheel is the recommended installation artifact.

## 7. Runtime data layout (outside Git)

| Path | Purpose |
|---|---|
| `.ctf-solver-data/manager.sqlite` | authoritative Task/Worker/approval/grant/execution state + evidence chain |
| `.ctf-solver-data/cas/sha256/` | content-addressed raw logs, stdout/stderr, screenshots |
| `.ctf-solver-data/sessions/` | reserved local session artefacts |
| `tasks/<task_id>/work/` | per-Task Worker workspace |
| `tasks/<task_id>/evidence/events.jsonl` | deterministic derived export |
| `tasks/<task_id>/evidence/manifest.sha256` | bundle manifest |
| `tasks/<task_id>/writeup.md` | chronological Markdown Writeup |
| `tasks/<task_id>/evidence.zip` | evidence bundle with manifest |

These paths are git-ignored. Never commit real challenge data, logs, screenshots or databases.

## 8. Session-log privacy gate

The canonical patch is the Python package resource
`ctf_solver/resources/acp/cordis.patch.yml`; it disables `dsh-session-log-deepseek` in a
dedicated profile. It must be applied only through the Manager's protected ACP launch or an
isolated temporary `DSH_HOME`, never to the live global Harness profile.

```powershell
# Resolve the exact package-resource path used by the Manager
python -c "from ctf_solver.core.config import SolverConfig; print(SolverConfig().privacy_patch_path)"

$env:DSH_HOME = "<temporary-empty-directory>"
& cmd /c '"C:\...\resources\runtime\cli\bin\dsh.cmd" --profile acp --patch "<path printed above>" --dump-config'
```

The negative outbound-delivery canary test requires a model request and remains **BLOCKED**
under the zero-model-call gate.

## 9. Current boundaries

- Main-conversation `/ctf-solver` → Manager MCP project-level entrypoint: **CONNECTED** in the
  tested environment via the project-scoped Workspace MCP Bridge (`.dsh/mcp.servers.yml`)
  plus `--lead-sessions-root`; see `docs/LEAD_SESSION_EVIDENCE.md`.
- Model-driven Workers / `session/prompt`: **BLOCKED** by ADR-020.
- Tier 2 OS isolation, real targets and challenge-code execution: **BLOCKED / NOT VERIFIED**.
- Real physical-console TTY approval: **NOT VERIFIED**.
- Same-child ACP-spawned `tools/call`: **NOT VERIFIED** under the zero-model-call gate.
- Skills being discovered by Harness is **not** registration of the Manager MCP.
- Manager MCP registration is project-scoped (`<workspace>/.dsh/mcp.servers.yml`), loaded by
  the Workspace MCP Bridge for sessions whose cwd is that workspace. Do not edit global
  profiles to fake a registration; report BLOCKED when the bridge is absent.
- Lead-session evidence: a Task may bind one Lead session (`lead_session_id`, verified by the
  Manager) and ingest that session log from the configured live `lead_sessions_root`; the
  evidence window is the whole bound session. `ctf_session_ingest` never accepts a path or an
  arbitrary session id. `notes` (intake) and `completion_note` (outcome) are separate fields.
- Lead-bound process screenshots use the configured target window only
  (`--capture-mode real-window --target-window-pid <TARGET_WINDOW_PID>`); `desktop` scope is
  refused for Lead Tasks, capture failure never falls back to the desktop, and screenshots
  are attributed to the Lead session (`worker_id` null). There is no automatic window
  discovery.
- Delivery is a privacy-filtered view: the Writeup, `events.jsonl` and evidence ZIP exclude
  model reasoning, raw passthrough prompts, full Skill bodies and raw session logs. The
  append-only evidence chain and raw CAS bytes remain local and unmodified.
