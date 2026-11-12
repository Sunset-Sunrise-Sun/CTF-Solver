# CTF-Solver v0.1.1 Installation Guide

CTF-Solver is a semi-autonomous CTF solving extension for DeepSeek Harness. It is not a
standalone CTF platform and does not introduce a second model loop.

This guide covers the **v0.1.1 installation-hardening release**. It is written from the
actual CLI and the final installation acceptance tests; do not assume unlisted features.

## 1. Requirements

- **Python:** project metadata requires `>=3.11`; the accepted/tested runtime is
  **Python 3.14.7 on Windows 11**.
- **Runtime dependencies:** none. The wheel declares no third-party runtime dependency.
- **zstd evidence support:**
  - Python **3.14+** has the standard-library `compression.zstd` backend; no extra package is needed.
  - Python **3.11–3.13** needs the optional `zstandard` package for multi-frame session-log
    decode/ingest. If neither backend is available, evidence ingestion fails closed with
    `UnsupportedCompressionError`; it does not silently drop frames.
  - Tests that generate multi-frame zstd fixtures also need `zstandard` on Python <3.14.
- **DeepSeek Harness:** required for real ACP/Manager/Worker operation. ACP is launched
  with `--profile acp --patch <absolute package-resource patch>`; this release never edits
  the live global Harness profile.
- **License:** the project is proprietary and has no open-source license. Do not
  redistribute it outside the authorized project/team context.

## 2. Install from the official release wheel (recommended)

Download the wheel and (optionally) `SHA256SUMS.txt` from the release.

```powershell
py -3.14 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install .\ctf_solver-0.1.1-py3-none-any.whl
```

If `py -3.14` is unavailable, use the Python 3.11+ interpreter you intend to use:
`python -m venv .venv`. The wheel itself does not need a package index.

Verify the installation from a directory **outside** the source checkout:

```powershell
python -m ctf_solver version
# ctf-solver 0.1.1

python -m ctf_solver --help
python -m ctf_solver preflight --root .\ctf-solver-root
```

The installed wheel contains the privacy patch as a package resource at
`ctf_solver/resources/acp/cordis.patch.yml`, so it works outside the repository root. The
old repository-level `config/acp/cordis.patch.yml` is no longer a second source of truth.
You can verify the resolved path after installation:

```powershell
python -c "from ctf_solver.core.config import SolverConfig; print(SolverConfig().privacy_patch_path)"
```

If this path does not exist, Manager ACP startup fails closed with an explicit
`ConfigError`; it never launches an unprotected ACP Worker.

## 3. Source checkout mode

The source ZIP/tree is for inspection, tests and development. It contains no `.git`
history and uses the same package-resource privacy patch as the wheel.

```powershell
Expand-Archive .\CTF-Solver-0.1.1-source.zip -DestinationPath .\CTF-Solver-0.1.1
Set-Location .\CTF-Solver-0.1.1
python -m ctf_solver version
```

For a full test run, use a Git checkout rather than the ZIP, because a few tests inspect
Git-tracked evidence:

```powershell
python -m pip install pytest
python -m pytest tests -q -p no:cacheprovider
```

Optionally install the source tree with the in-tree stdlib-only PEP 517 backend:

```powershell
python -m pip install .
```

For installation acceptance, prefer the wheel.

## 4. CLI quick reference (verified surface)

All commands below exist in the released CLI. Use an explicit `--root` for project state.

```powershell
# Read-only environment report and project Skills report
python -m ctf_solver preflight --root .\ctf-solver-root
python -m ctf_solver skills

# Local Task operations
python -m ctf_solver task create --root .\ctf-solver-root `
    --title "Synthetic misc" --category misc --conversation-id local
python -m ctf_solver task list   --root .\ctf-solver-root
python -m ctf_solver task status --root .\ctf-solver-root --task-id <task-id>

# Human approval console; decisions require a real interactive TTY
python -m ctf_solver approval list   --root .\ctf-solver-root
python -m ctf_solver approval confirm --root .\ctf-solver-root --approval-id <approval-id>
python -m ctf_solver approval reject  --root .\ctf-solver-root --approval-id <approval-id> --note "not authorized"

# Task-scoped network grants (creation requires a human-confirmed approval)
python -m ctf_solver grant list   --root .\ctf-solver-root
python -m ctf_solver grant create --root .\ctf-solver-root --approval-id <approval-id> ...
python -m ctf_solver grant revoke --root .\ctf-solver-root --grant-id <grant-id>

# Evidence helpers
python -m ctf_solver evidence verify-chain --root .\ctf-solver-root
python -m ctf_solver evidence decode <path-to-session.v4.jsonl.zstd>

# MCP stdio servers
python -m ctf_solver manager serve --root .\ctf-solver-root --capture-mode desktop
python -m ctf_solver worker-mcp
```

`manager serve` and `worker-mcp` are stdio MCP servers; run them through their host/client,
not as interactive commands. The **main-conversation `/ctf-solver` → Manager MCP
project-level entrypoint is NOT implemented** (see section 7).

### ACP startup failures are explicit

`task create` and MCP `ctf_task_create` now fail with `reason_code=acp_unavailable` when
ACP cannot start; no Task is persisted. A Task is queued only when the Manager is healthy
and the two-Worker concurrency limit is full. If ACP crashes after a Task was created, the
Task becomes `interrupted`, the Worker is marked `crashed`, and the diagnostics/evidence
record the failure.

There is **no public `--acp-command` flag**. The only supported override is the test-only
`CTF_SOLVER_TEST_ACP_COMMAND` boundary used by the test suite; it still receives the
mandatory `--profile acp --patch <absolute patch>` arguments. Do not configure a custom
unprotected ACP command in production.

## 5. Manager/Worker deployment

`python -m ctf_solver manager serve` starts:
- the loopback Manager IPC endpoint;
- the managed ACP client (`dsh --profile acp --patch <absolute package patch>`);
- durable SQLite/CAS/evidence state under `--root`.

By default the managed ACP server uses a project-local isolated `DSH_HOME` under
`.ctf-solver-data/dsh-home` and does not write to the live `~/.dsh`. The Manager declares
at most two active Workers; additional Tasks remain FIFO-queued.

The Manager control MCP exposes exactly **18** tools: `ctf_task_create`,
`ctf_task_list`, `ctf_task_status`, `ctf_task_continue`, `ctf_task_pause`,
`ctf_task_cancel`, `ctf_task_complete`, `ctf_approval_request`, `ctf_approval_list`,
`ctf_grant_list`, `ctf_grant_revoke`, `ctf_flag_candidate`, `ctf_screenshot_capture`,
`ctf_session_ingest`, `ctf_events_export`, `ctf_writeup_build`, `ctf_evidence_zip`,
`ctf_runtime_status`. Approval decisions and grant creation are human-only and are not
MCP tools.

## 6. Install the six Skills into a Harness project workspace (Windows)

**Wheel installation only installs the CTF-Solver program.** The six Skills are product
files that must be placed in the Harness project workspace; the wheel does not copy them
into your project automatically.

### 6.1 Download and extract the source ZIP

Download **both** the wheel and `CTF-Solver-0.1.1-source.zip` from the same GitHub Release.
The source ZIP contains the complete source tree, including `.dsh\skills\`.

```powershell
$Download = "$env:USERPROFILE\Downloads"
$Release  = Join-Path $Download "CTF-Solver-0.1.1"
New-Item -ItemType Directory -Force -Path $Release | Out-Null
Expand-Archive -LiteralPath (Join-Path $Download "CTF-Solver-0.1.1-source.zip") `
    -DestinationPath $Release -Force

# The source ZIP has no top-level wrapper directory: .dsh is directly under $Release.
Get-ChildItem (Join-Path $Release ".dsh\skills") -Directory |
    Select-Object -ExpandProperty Name
# Expected: ctf-solver ctf-web ctf-misc ctf-crypto ctf-reverse ctf-pwn
```

### 6.2 Copy Skills safely into a project workspace

Choose the **project workspace** you open in DeepSeek Harness. Its project root is the
nearest ancestor containing `.git`; if there is no `.git`, the workspace cwd itself is the
project root. Create `<project root>\.dsh\skills\` and copy only the six named folders.
Do **not** delete or replace the whole `.dsh` directory: it may contain other Skills or
project configuration.

```powershell
$Project = "D:\work\my-harness-project"       # <-- change to your project workspace
$Source  = Join-Path $Release ".dsh\skills"
$Target  = Join-Path $Project ".dsh\skills"
New-Item -ItemType Directory -Force -Path $Target | Out-Null

$Skills = @("ctf-solver", "ctf-web", "ctf-misc", "ctf-crypto", "ctf-reverse", "ctf-pwn")
foreach ($Name in $Skills) {
    $Src = Join-Path $Source $Name
    $Dst = Join-Path $Target $Name
    if (-not (Test-Path -LiteralPath (Join-Path $Src "SKILL.md"))) {
        throw "missing expected Skill: $Src"
    }
    if (Test-Path -LiteralPath $Dst) {
        # Preserve any existing same-name Skill before replacing it.
        $Backup = "$Dst.backup-$(Get-Date -Format yyyyMMddHHmmss)"
        Copy-Item -LiteralPath $Dst -Destination $Backup -Recurse -Force
        Remove-Item -LiteralPath $Dst -Recurse -Force
        Write-Host "backed up existing $Name -> $Backup"
    }
    Copy-Item -LiteralPath $Src -Destination $Dst -Recurse -Force
}
```

This copies only the six named folders and leaves any other `.dsh` content untouched. If a
same-name folder already exists, a timestamped `.backup-*` copy is created first.

### 6.3 Verify with the actual CLI

Run from the wheel's venv (or use `python -m ctf_solver skills` if the console script is not
on `PATH`):

```powershell
ctf-solver skills --root "D:\work\my-harness-project"
```

Expected: exit code 0, JSON `"ok": true`, all six expected names under `"found"`, and
`"missing": []`. A missing directory or malformed `SKILL.md` returns exit code 1 with a
specific problem.

### 6.4 Verify project Skills in DeepSeek Harness

Open the same project workspace in DeepSeek Harness. The `dsh-skill-filesystem` provider
discovers `<project root>/.dsh/skills` at rank 100 (`project-dsh`); this is project-local
and requires **no** global Harness configuration. The six `SKILL.md` files should appear as
project Skills. This was verified by a real-provider A/B run where a workspace with the six
Skills found 6 and two empty workspaces found 0.

**Important distinction:** discovering Skills does not by itself register the Manager MCP
server. Registration is provided by the project-scoped Workspace MCP Bridge described in
section 6.5; the six Skills and the Manager/Worker CLI/MCP surfaces are separate pieces.
Completing only this Skills step must not be interpreted as "Manager MCP is connected".

### 6.5 Connect the Lead conversation to the Manager (project-scoped MCP bridge)

This is an environment step, not a product install. It requires the project-scoped
Workspace MCP Bridge plugin `@momojie-s/dsh-workspace-mcp` to be installed in the running
Harness profile (installed in the tested environment with `dsh plugin --profile desktop add
<tgz>`; see the installation acceptance report). If the plugin is absent, report the
integration BLOCKED — do not edit global profiles to fake registration.

Create `<workspace>/.dsh/mcp.servers.yml` (project-scoped, only sessions whose cwd is this
workspace see it):

```yaml
servers:
  ctf-solver:
    transport: stdio
    command: "<venv>/Scripts/python.exe"
    args:
      - "-m"
      - "ctf_solver"
      - "manager"
      - "serve"
      - "--root"
      - "<workspace>"
      - "--lead-sessions-root"
      - "<DSH_HOME>/sessions"
      - "--capture-mode"
      - "desktop"
```

- `--lead-sessions-root` is the **live** Harness sessions root (`<DSH_HOME>/sessions`, e.g.
  `C:/Users/<user>/.dsh/sessions`). It is deliberately separate from the Manager's isolated
  `--dsh-home`; the Manager never creates it and never reads Worker logs from it.
- The running Harness hot-loads the changed config; the Manager MCP tools appear as
  `mcp__ctf-solver__*` (18 tools).
- The Lead conversation reads its own session id from the native shell
  (`$env:DSH_SESSION_ID`) and passes it as `ctf_task_create(lead_session_id=...)`. The Manager
  verifies the id, the single session log, the log header `id` and the header `cwd` before
  binding it one time; evidence ingestion then resolves only the Manager-registered binding.
- `ctf_session_ingest` never accepts a path or an arbitrary session id.
- Process screenshots require the real target window: add
  `--capture-mode real-window --target-window-pid <TARGET_WINDOW_PID>` (the PID of the
  process that owns the challenge/program window). `real-window` refuses to build a
  capturer without a positive PID, never falls back to the desktop, and Lead-bound Tasks
  reject an explicit `scope=desktop`. There is no automatic window discovery.
- Delivery privacy: the Writeup, `events.jsonl` and the evidence ZIP share one policy that
  excludes model reasoning, `passthrough` prompts, full Skill bodies and raw session logs.
  Raw logs remain in the local CAS; the ZIP manifest and chain stay verifiable locally.

## 7. Current acceptance boundary — read before use

- The main-conversation `/ctf-solver` → Manager MCP entrypoint is **connected in the tested
  environment** through the project-scoped Workspace MCP Bridge plus a `--lead-sessions-root`
  configuration. The Lead-session binding/evidence-ingestion path is implemented and verified;
  it is NOT a global/profile registration and must not be faked on an environment without the
  bridge.
- Model-driven Workers and `session/prompt` are **not open**.
- Tier 2 OS isolation, real competition targets, and challenge-code execution have **not
  passed acceptance**. Do not run untrusted challenge binaries, scripts, macros, exploit
  payloads or installers on the host.
- Real physical-console TTY confirmation is **NOT VERIFIED**.
- Same-child ACP-spawned `tools/call` is **NOT VERIFIED** under the zero-model-call gate.
- Skills being discovered by Harness does **not** mean the Manager MCP has been
  automatically registered with the running session; the project-scoped bridge configuration
  in section 6.5 is what registers it.
- A Lead session can be bound to one Task in this round (single-assignment binding). The
  ingested evidence window is the whole bound Lead session, not a per-Task slice; do not
  claim per-Task window filtering.
- Human approval decisions and network-grant creation are local-console/TTY-only and are
  deliberately **not** MCP tools; an agent or MCP caller can request an approval but cannot
  decide it. A network grant is Task/target-scoped and cannot be widened. Real competition
  target access and challenge-code execution remain unaccepted in this release.
- The project is proprietary and no open-source license has been granted; do not assume
  open-source redistribution rights.

- Lead-bound process screenshots require a configured real target window
  (`real-window` + `--target-window-pid`); `desktop` capture is refused for Lead Tasks and
  there is no automatic window discovery or desktop fallback. Worker-only Tasks keep the
  legacy desktop capturer when configured.
- Delivered artifacts are a privacy-filtered view, not the raw session log: reasoning,
  raw passthrough prompts and full Skill bodies are excluded, and the raw log stays in the
  local CAS. Tool arguments/outputs and target-window screenshots can still contain
  sensitive business content; review before sharing.

Do not use this release for real CTF content until those boundaries are separately
accepted.

## 8. Test status (v0.1.1 release + Lead-session evidence Round 1)

The final v0.1.1 regression is recorded in the v0.1.1 acceptance report in the source/release
materials. The Lead-session evidence round adds regression tests for the schema 1.1→1.2
migration, one-time Lead binding, Lead log resolution/identity checks, `source`-selected
ingestion, completion auto-ingest, notes/completion-note separation, Writeup step/screenshot
binding and ZIP internal verification; the final counts and raw outputs are recorded under
`lead-session-evidence/`. The release is tested on the original Windows + Python 3.14.7
environment, with both system Python and an isolated venv.

## 9. Troubleshooting

- `ctf-solver` command not found: activate the venv or use `python -m ctf_solver`.
- `acp_unavailable` on `task create`: the Manager could not start ACP. The command now
  fails explicitly instead of creating a permanently queued Task. Check the reported
  `acp_error`, the Harness launcher, and the resolved privacy-patch path.
- `ConfigError: ... privacy patch is missing`: the installed package is incomplete or
  corrupt; reinstall the official wheel. Do not create a fake unprotected profile.
- zstd decode error on Python 3.11–3.13: install the optional `zstandard` package in the
  venv, or use Python 3.14+ for standard-library zstd support.
- pytest failures from a ZIP-extracted tree: use a Git checkout for the full suite; the
  release ZIP intentionally has no `.git` history.
- Manager/ACP startup errors: the main-conversation Manager entrypoint is not available;
  use the CLI/MCP surfaces above and read the final acceptance report's BLOCKED items.
