# CTF-Solver

**A Lead-first CTF solving extension for DeepSeek Harness.** The Lead conversation is the
executor; a local Manager owns Tasks, approvals, evidence and deliverables. It is not a
standalone CTF platform and does not introduce a second model loop.

> **Status: public Beta (0.1.1).** This Beta is for evaluation and community testing.
> It is **not** an open-source release: see [LICENSE](LICENSE). The product core, the
> Manager MCP surface, the Lead-session evidence path and the Writeup/evidence pipeline
> are implemented and were exercised on the original Windows + Python 3.14.7 test
> machine. Items marked **BLOCKED / NOT VERIFIED** below are real known limitations;
> do not assume them. Cross-machine behaviour outside that one environment is **pending
> community confirmation**.

## What it is

CTF-Solver preserves DeepSeek Harness as the reasoning and runtime layer. It adds:

- one Core Skill plus five specialist Skills (Web, Misc, Crypto, Reverse, Pwn);
- a Manager with an ACP client, per-challenge Workers and a typed `ctf-exec` runtime;
- Task-scoped human approvals and network target grants;
- an append-only, hash-chained evidence store plus a Markdown Writeup and evidence ZIP;
- a Lead-first workflow: the Harness Lead conversation does the analysis with native
  tools, and the Manager records and delivers the evidence.

## Architecture at a glance

```text
User conversation
  -> /ctf-solver Skill (loads the matching category Skill)
  -> Manager MCP tools (project-scoped, 18 tools)
  -> Manager (SQLite state + CAS evidence + hash chain)
       -> ACP client -> `dsh --profile acp` ACP server -> one Worker session per Task
       -> typed `ctf-exec` MCP tool (Worker path, no arbitrary host shell)
  -> Writeup + events.jsonl + evidence.zip (privacy-filtered view)
```

The Lead conversation is bound to a Task once (`lead_session_id`) and its Harness session
log is ingested as evidence. The Manager runs locally and keeps all state under
`<workspace>/.ctf-solver-data/` (git-ignored).

## Core capabilities

| Capability | State |
|---|---|
| Task lifecycle: create / list / status / continue / pause / cancel / complete | Implemented, 18-tool MCP surface |
| Lead session identity + one-time binding + session-log evidence ingestion | Implemented; evidence boundary excludes pre-Task history |
| Evidence chain, `events.jsonl` export, Writeup build, evidence ZIP + manifest | Implemented and locally verifiable |
| Task-scoped human approvals; one-shot, digest-bound, TTY console | Implemented; grant creation is human-only |
| Network target grants (scope/TTL/call budget, no widening) | Implemented; remote targets not part of this Beta |
| Six Skills and category routing hard step | Implemented |
| Typed `ctf-exec` Worker tool (no unrestricted host shell) | Implemented |
| Offline, stdlib-only wheel build (in-tree PEP 517 backend) | Implemented |
| Model-driven Workers / `session/prompt` | **BLOCKED** by ADR-020 zero-model-call gate |
| Tier-2 OS isolation, real targets, challenge-code execution | **NOT AVAILABLE / BLOCKED** |
| Real physical-console TTY approval decision | **NOT VERIFIED** |
| Target-window screenshot capture (Lead path) | **KNOWN ISSUE / fail-closed**, see [KNOWN_ISSUES.md](KNOWN_ISSUES.md) |

## Quick start

```powershell
# 1. Get the Beta branch and install (fresh Windows, Python 3.11+; no admin required)
git clone https://github.com/Sunset-Sunrise-Sun/CTF-Solver.git
cd CTF-Solver

# 2. One-shot local set-up (venv + package + Skills + project MCP config)
powershell -ExecutionPolicy Bypass -File .\scripts\setup_windows.ps1

# 3. Check the install
.\.venv\Scripts\python.exe -m ctf_solver version
.\.venv\Scripts\python.exe -m ctf_solver skills --root .
```

Then open the repository directory as a **DeepSeek Harness workspace**, start a
conversation, call `/ctf-solver`, and create a Task. Full steps:
[INSTALL.md](INSTALL.md) and [QUICKSTART.md](QUICKSTART.md).

> The Beta branch is `release/beta-v0.1.1`. If you downloaded a ZIP instead of cloning,
> the same scripts work from the extracted directory.

## What you need

- Windows 10/11 (the Beta was accepted on Windows 11; other platforms are untested).
- Python 3.11 or newer. Python 3.14+ is recommended (standard-library `compression.zstd`
  for session-log evidence). On 3.11–3.13, install the optional `zstandard` package.
- DeepSeek Harness with the project-scoped Workspace MCP Bridge plugin
  (`@momojie-s/dsh-workspace-mcp`) available in your profile. The Beta does **not**
  modify global Harness profiles, plugins or settings.
- No administrator rights, no Docker/WSL, and **no need to disable the sandbox**. The
  normal `workspace-write` permission is sufficient; never enable `danger-full-access`
  for this project.

## Repository map

- `ctf_solver/` — product package (Manager, ACP client, MCP servers, evidence, delivery,
  policy/broker, runtime, preflight, CLI).
- `.dsh/skills/` — the six project Skills (core + five categories).
- `tests/` — deterministic unit/integration tests with synthetic fixtures.
- `tooling/wheelbuild.py` — in-tree, stdlib-only PEP 517 wheel backend.
- `scripts/` — installer helpers and release verification tools.
- `docs/` — architecture, interfaces, security, decisions and acceptance docs.
- `docs/release/` — Beta release notes, draft-PR description, community test template.

## Documentation

- [INSTALL.md](INSTALL.md) — install from a fresh Windows environment.
- [QUICKSTART.md](QUICKSTART.md) — start Harness, load Skills, connect the Manager,
  create a Task and export a Writeup.
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md) — known environment problems and fixes.
- [KNOWN_ISSUES.md](KNOWN_ISSUES.md) — Beta limitations and verification gaps.
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — module boundaries.
- [docs/SECURITY.md](docs/SECURITY.md) — trust boundaries and approval rules.
- [docs/LOCAL_OPERATION.md](docs/LOCAL_OPERATION.md) — CLI, data layout and tests.
- [docs/LEAD_SESSION_EVIDENCE.md](docs/LEAD_SESSION_EVIDENCE.md) — Lead evidence pipeline.
- [docs/release/BETA_RELEASE_NOTES.md](docs/release/BETA_RELEASE_NOTES.md) — what changed.

## Safety boundary

- The Harness sandbox is **not** an OS security boundary for untrusted binaries. Do not
  run challenge-provided binaries, scripts, macros, exploit payloads or installers on the
  host; Tier-2 isolation is not part of this Beta.
- Remote CTF targets require a Task-scoped grant created from a human-confirmed approval.
  This Beta does not ship accepted remote-target support.
- An agent can *request* approvals; it can never approve or create a grant. Only a human
  at a local interactive console can decide.
- Never submit a Flag automatically. The Agent records a **candidate**; a human confirms
  and submits it.
- Real challenge content, session logs, screenshots, databases and keys must stay out of
  Git. The repository `.gitignore` already covers the runtime data locations.

## Testing and contributions

Offline tests (no model calls, no network):

```powershell
python -m pytest tests -q -p no:cacheprovider
```

The Beta is looking for community verification on **different machines**: clean Windows
installs, Python 3.12/3.13, other Harness builds, and the MCP bridge plugin. Use the
template in [docs/release/COMMUNITY_TEST_TEMPLATE.md](docs/release/COMMUNITY_TEST_TEMPLATE.md)
or open a "Beta test report" issue.

## License

Proprietary public Beta; limited evaluation grant only. See [LICENSE](LICENSE). The
project is **not** open source; no reuse rights are granted beyond evaluation and testing.
