# Installing CTF-Solver Beta from a fresh Windows environment

This guide installs the public Beta (`0.1.1`) of CTF-Solver from scratch on Windows. It
uses only local files and the Python standard library: **no package index is required**,
no administrator rights, and no sandbox changes.

> The Beta is accepted on **Windows 11 + Python 3.14.7**. Other platforms and Python
> versions are untested; report results with the community test template.

## 0. What you need

| Item | Requirement |
|---|---|
| OS | Windows 10/11 (64-bit). |
| Python | 3.11+; **3.14+ recommended** (`compression.zstd` built in). On 3.11–3.13 install the optional `zstandard` package for session-log evidence. |
| Harness | A DeepSeek Harness build with the project-scoped Workspace MCP Bridge plugin (`@momojie-s/dsh-workspace-mcp`). This is an environment prerequisite; the Beta cannot register the Manager MCP without it. |
| Disk | ~50 MB for the source checkout plus a venv. |
| Privileges | Normal user. No admin, no service installation, no Docker/WSL. |
| Sandbox | Keep the normal `workspace-write` sandbox. Do **not** disable the sandbox or use `danger-full-access`. |

All commands below are PowerShell. Run them from the repository root unless stated
otherwise.

## 1. Get the Beta source

```powershell
# Clone (or download the Beta ZIP and expand it)
git clone https://github.com/Sunset-Sunrise-Sun/CTF-Solver.git
cd CTF-Solver
git switch release/beta-v0.1.1
```

If you download a ZIP instead, expand it and open a PowerShell window in the extracted
directory; the repository is complete without `.git` history for installation purposes.

## 2. Create a virtual environment

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -V
```

If PowerShell refuses to run `Activate.ps1` because of execution policy, either run
`Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` in this window (it affects
only the current process) or call the venv interpreter directly as shown below.

## 3. Install the package

Two supported ways; both are fully offline when the venv is present.

### 3a. Install from the source tree

```powershell
# The project uses an in-tree stdlib-only PEP 517 backend, so no build tools are needed.
python -m pip install --no-build-isolation --no-deps .
```

`--no-build-isolation` keeps pip from contacting an index or creating a network build
environment; `--no-deps` is safe because there are no runtime dependencies.

### 3b. Build and install a wheel (recommended for repeatable installs)

```powershell
python scripts/build_wheel.py --out dist
python -m pip install --no-index --no-deps .\dist\ctf_solver-0.1.1-py3-none-any.whl
```

The in-tree backend verifies wheel structure and RECORD hashes during the build and
prints the wheel SHA-256. There is no third-party build requirement.

## 4. Verify the installation

The installed package must be the one that Python imports. Run the check from a directory
**outside** the source tree, or use `-P` so that the source checkout cannot shadow it:

```powershell
python -c "import ctf_solver; print(ctf_solver.__file__, ctf_solver.__version__)"
python -P -m ctf_solver version
# ctf-solver 0.1.1

python -m ctf_solver preflight --root .\ctf-solver-root
```

`preflight` is read-only. It prints the runtime facts, the audited ACP launcher, found or
missing tools, Skill status and the package-resource privacy patch path.

> **Source-vs-wheel shadowing:** if `ctf_solver.__file__` points into the source checkout
> (for example because you run from the repository root), that checkout wins over the
> installed package. Use `python -P ...` for version checks. This is documented behaviour,
> not a bug.

## 5. Deploy the six Skills into your Harness workspace

A wheel installs the **program**; the six Skills are project files. Put them in the
workspace you will open in DeepSeek Harness:

```powershell
python scripts/deploy_skills.py --workspace <YOUR_WORKSPACE>
```

The script copies only the six Skill folders, backs up any same-name Skill first, and
leaves the rest of `.dsh` untouched. It refuses to run if a Skill file is missing.

Verify with the product CLI:

```powershell
python -m ctf_solver skills --root <YOUR_WORKSPACE>
```

Expected JSON: `"ok": true`, six names under `"found"`, and `"missing": []`. A missing or
malformed `SKILL.md` exits non-zero with a specific problem.

Harness discovers project Skills from `<project root>\.dsh\skills` automatically; this
needs no global profile change.

## 6. Generate the project-scoped Manager MCP config

The Lead conversation reaches the Manager through a **project-scoped** config file,
`<workspace>\.dsh\mcp.servers.yml`, loaded by the Workspace MCP Bridge plugin.

```powershell
# Use the venv interpreter so the Manager starts with the installed package.
python scripts/gen_mcp_config.py `
    --workspace <YOUR_WORKSPACE> `
    --python .\.venv\Scripts\python.exe `
    --lead-sessions-root "$env:USERPROFILE\.dsh\sessions"
```

The script writes the config and refuses to overwrite an existing file unless `--force`
is given. It does not hardcode machine paths: everything comes from the arguments or
`$env:DSH_HOME` / `$env:USERPROFILE`.

Optional capture settings:

- `--capture-mode real-window --target-window-pid <PID>` — capture the explicit target
  window only (the PID of the process whose window should be captured).
- `--capture-mode fake` — deterministic test mode; screenshots are fake fixtures. Never
  use it to claim a real screenshot.

If the Workspace MCP Bridge plugin is not installed in the running Harness profile,
**stop and report the integration BLOCKED**. Do not edit global profiles, plugins or
settings to fake registration.

## 7. Start Harness and confirm the surface

1. Open `<YOUR_WORKSPACE>` (the repository directory is a convenient workspace) as a
   DeepSeek Harness workspace.
2. Start a conversation. The Manager MCP tools must appear as
   `mcp__ctf-solver__*` — **18 tools**. If you see 0 tools, see
   [TROUBLESHOOTING.md](TROUBLESHOOTING.md).
3. Invoke the core Skill with `/ctf-solver`, then follow
   [QUICKSTART.md](QUICKSTART.md).

Every Manager MCP tool name ends with one of: `ctf_task_create`, `ctf_task_list`,
`ctf_task_status`, `ctf_task_continue`, `ctf_task_pause`, `ctf_task_cancel`,
`ctf_task_complete`, `ctf_approval_request`, `ctf_approval_list`, `ctf_grant_list`,
`ctf_grant_revoke`, `ctf_flag_candidate`, `ctf_screenshot_capture`, `ctf_session_ingest`,
`ctf_events_export`, `ctf_writeup_build`, `ctf_evidence_zip`, `ctf_runtime_status`.

## 8. Offline and air-gapped notes

- The package, the build backend, the tests and the installer helpers use only the
  Python standard library.
- `pip install --no-build-isolation --no-deps .` and the wheel install with `--no-index`
  do not need a package index.
- There is no telemetry and no update mechanism in this Beta.
- Harness itself and its Workspace MCP Bridge plugin are separate prerequisites installed
  by the user; they are not downloaded by these scripts.

## 9. Update and uninstall

```powershell
# Update: fetch the newer Beta branch, then repeat step 3 (and step 6 if the config changed)
git fetch origin
git switch release/beta-v0.1.1
git pull --ff-only

# Uninstall the package but keep your data
python -m pip uninstall ctf-solver

# Runtime data lives outside Git under <workspace>/.ctf-solver-data and <workspace>/tasks;
# delete those directories only when you intend to discard all Tasks and evidence.
```

## 10. What this installer deliberately does not do

- It does not disable the Harness sandbox or ask for `danger-full-access`.
- It does not edit global Harness profiles, plugins or MCP settings.
- It does not install third-party packages, start WSL/Docker, or execute challenge files.
- It does not install the Workspace MCP Bridge plugin; that is an explicit environment
  prerequisite confirmed in step 6.
