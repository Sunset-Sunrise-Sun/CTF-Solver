# CTF-Solver v0.1.1 Installation Guide

CTF-Solver is a semi-autonomous CTF solving extension for DeepSeek Harness. It is not a
standalone CTF platform and does not introduce a second model loop.

This guide covers the **v0.1.1 installation-hardening candidate**. It is written from the
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

## 6. Skills

The six project Skills live in `<workspace>/.dsh/skills/<name>/SKILL.md`. A workspace with
these files is discovered by the Harness project-skill provider; this was verified with a
real-provider A/B test (6 vs 0). Placing Skills is **not** the same as registering the
Manager MCP server: Harness currently has no supported project-level MCP registration, so
the main-conversation Manager entrypoint remains unavailable.

## 7. Current acceptance boundary — read before use

- The main-conversation `/ctf-solver` → Manager MCP **project-level entrypoint is not
  implemented**; do not expect it to work.
- Model-driven Workers and `session/prompt` are **not open**.
- Tier 2 OS isolation, real competition targets, and challenge-code execution have **not
  passed acceptance**. Do not run untrusted challenge binaries, scripts, macros, exploit
  payloads or installers on the host.
- Real physical-console TTY confirmation is **NOT VERIFIED**.
- Same-child ACP-spawned `tools/call` is **NOT VERIFIED** under the zero-model-call gate.
- Skills being discovered by Harness does **not** mean the Manager MCP has been
  automatically registered with the running session.

Do not use this release for real CTF content until those boundaries are separately
accepted.

## 8. Test status (v0.1.1 candidate)

The final regression is recorded in the v0.1.1 acceptance report in the source/release
materials. The release is tested on the original Windows + Python 3.14.7 environment, with
both system Python and an isolated venv.

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
