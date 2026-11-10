# CTF-Solver — Local Operation (Round 1 candidate)

All commands run from the repository root (`D:\CTF-SOLVER`). No installation step is
required: the package lives at the repository root and all runtime data stays outside
Git. Python 3.14.7 and pytest 9.1.1 are already installed on this machine; `zstandard`
is also present (the code can fall back to the standard-library `compression.zstd`).

## 1. Read-only preflight / doctor

```powershell
python -m ctf_solver preflight
python -m ctf_solver preflight --json .\preflight.json --text .\preflight.txt
python -m ctf_solver skills
```

The preflight reports OS/runtime facts, the audited ACP launcher, available/missing tools
and Python modules, Skill format (UTF-8 without BOM, frontmatter), the session-log
privacy gate state, and isolation status. It never installs, configures, or starts
anything; "missing" and "not verified" are reported separately.

## 2. Manager control MCP server

```powershell
python -m ctf_solver manager serve --root . --capture-mode desktop
```

- Speaks MCP over stdio (newline-delimited JSON-RPC 2.0); stdout carries protocol
  messages only. Logs go to stderr.
- Starts the loopback IPC endpoint used by Worker `ctf-exec` servers, then the managed
  ACP client, then recovers durable state.
- By default the managed ACP server uses a **project-local isolated** `DSH_HOME`
  (`.ctf-solver-data/dsh-home`, git-ignored), so it does not write profile or session
  state into the live `~/.dsh`. Pass `--dsh-home <path>` only when the owner has
  explicitly authorized using a real Harness home (Round 2 integration decision).
- Exposes tools: `ctf_task_create`, `ctf_task_list`, `ctf_task_status`,
  `ctf_task_continue`, `ctf_task_pause`, `ctf_task_cancel`, `ctf_approval_request`,
  `ctf_approval_decide`, `ctf_approval_list`, `ctf_grant_create`, `ctf_grant_revoke`,
  `ctf_grant_list`, `ctf_flag_candidate`, `ctf_screenshot_capture`,
  `ctf_session_ingest`, `ctf_events_export`, `ctf_writeup_build`, `ctf_evidence_zip`,
  `ctf_runtime_status`.
- The default ACP launcher is discovered from the audited Harness installation; use
  `--acp-command "<exact command>"` to override (tests use
  `python -m ctf_solver.acp.fake_server`). A `.cmd` launcher is wrapped in
  `cmd.exe /c`; it is never spawned through a shell string.
- Round 1 does not authorize `session/prompt`; `ctf_task_continue` records the
  continuation and returns `model_call_suppressed: true`.

## 3. Worker `ctf-exec` MCP server

In normal operation the Manager injects this server into each Task's
`session/new.mcpServers` with a per-Worker token. To exercise it manually against a
running Manager IPC endpoint:

```powershell
$env:CTF_SOLVER_IPC_URL = "tcp://127.0.0.1:<port-from-ctf_runtime_status>"
$env:CTF_SOLVER_WORKER_TOKEN = "<per-Worker token>"
python -m ctf_solver worker-mcp
```

The server exposes exactly one typed tool, `ctf_exec` (tool id + argv array + Task/
Worker/Step identity + cwd + input hashes + outputs + optional approval/grant + timeout).
Identity comes from the environment, never from tool arguments; invalid or missing
tokens fail closed.

## 4. Local Task operations (single process, for smoke checks)

```powershell
# challenge files must first be placed under <root>/challenge-uploads/ (git-ignored);
# supplied paths are relative to that intake root, never absolute host paths
python -m ctf_solver task create --root . --title "Synthetic misc" --category misc `
    --supplied-file challenge.zip --supplied-file notes/readme.txt
python -m ctf_solver task list --root .
python -m ctf_solver task status --root . --task-id <task-id>
```

These start the real wiring (Manager + ACP client + Broker/Runtime + SQLite/CAS) and
shut it down afterwards. They do not make model calls. The managed ACP server uses the
project-local isolated `DSH_HOME` by default.

## 4b. Human approval console and target grants (Round 2)

Approval decisions and network grants are **human-only** and are never exposed as MCP
tools. They require an interactive local console (a real TTY; MCP/agent/pipe contexts
fail closed):

```powershell
# list pending/decided approvals
python -m ctf_solver approval list --root .

# a human reviews the displayed action summary + digest prefix and types CONFIRM/REJECT
python -m ctf_solver approval confirm --root . --approval-id <approval-id>
python -m ctf_solver approval reject  --root . --approval-id <approval-id> --note "not authorized"

# create a Task-scoped network grant ONLY from a confirmed remote_target approval
python -m ctf_solver grant create --root . --approval-id <approval-id> `
    --competition-profile synthetic-local --host 127.0.0.1 --port 31337 `
    --protocol tcp --method GET --ttl-s 600 --max-calls 5
python -m ctf_solver grant list --root .
python -m ctf_solver grant revoke --root . --grant-id <grant-id>
```

The model can call `ctf_approval_request` (request only), `ctf_approval_list`,
`ctf_grant_list` and `ctf_grant_revoke`. There is no MCP path to approve a request or
create a grant. Replay, expiry, cross-Task use, digest mismatch and double consumption
fail closed.

## 5. Evidence helpers

```powershell
# Decode a Harness session.v4.jsonl.zstd (all concatenated zstd frames)
python -m ctf_solver evidence decode .\path\to\session.v4.jsonl.zstd

# Verify the SQLite append-only evidence hash chain for a local data root
python -m ctf_solver evidence verify-chain --root .
```

## 6. Tests

```powershell
# Full deterministic suite (fake ACP/MCP; real ACP smoke opt-in)
python -m pytest tests -q -p no:cacheprovider

# Include the zero-model-call real Harness ACP smoke test
$env:CTF_SOLVER_ENABLE_REAL_ACP = '1'
python -m pytest tests -q -p no:cacheprovider

# Round 2 real-Harness integration evidence (30 checks, no model calls)
python scripts/round2_integration.py
# Read-only Harness entrypoint / project-scope analysis + Skill discovery evidence
python scripts/round2_harness_analysis.py
# Wheel build (in-tree stdlib PEP 517 backend; no installation)
python scripts/build_wheel.py
# Fresh-clone verification (strict committed HEAD; run after a commit)
python scripts/fresh_clone_check.py
```

- Tests are offline and deterministic. They use fake ACP/MCP servers, synthetic
  fixtures and tmp directories; they do not contact real CTF targets, install software,
  change Harness global configuration, or start WSL/Docker.
- The real ACP smoke test creates an isolated temporary `DSH_HOME` and makes no model
  call. It is opt-in so the default suite never touches the Harness installation.
- Raw test logs from the Round 1 run are under `round1-evidence/raw/`.

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
| `exports/`, `captures/` | reserved local outputs |

These paths are git-ignored; never commit real challenge data, logs, screenshots or
databases.

## 8. Session-log privacy gate

`config/acp/cordis.patch.yml` is a project-owned sample that disables
`dsh-session-log-deepseek` for a dedicated profile. It must be applied only to an
isolated temporary `DSH_HOME` in this development cycle, never to the live global
Harness profile:

```powershell
$env:DSH_HOME = "<temporary-empty-directory>"
& cmd /c '"C:\...\resources\runtime\cli\bin\dsh.cmd" --profile acp --patch "D:\CTF-SOLVER\config\acp\cordis.patch.yml" --dump-config'
```

Round 1 verified this mechanism composes the plugin with `enabled: false` in an isolated
home. The negative outbound-delivery canary test (which requires a model request) is
BLOCKED in Round 1. Do not process real CTF content until Round 2 proves it.

## 9. Known Round 1 limitations

See `docs/ROUND_1_ARCHITECTURE_NOTES.md`: main-conversation entrypoint to Manager tools
is BLOCKED, session-log negative delivery test is BLOCKED, model-mediated Workers,
live in-flight cancel/permission round trips, and real desktop capture are NOT VERIFIED.
