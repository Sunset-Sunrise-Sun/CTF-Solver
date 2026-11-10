# Round 1 Architecture Notes and Harness Integration Limits

**Status:** Round 1 implementation candidate notes (not final MVP acceptance)
**Date:** 2026-11-10
**Branch:** `feat/round1-complete-product-core`

This file records what Round 1 actually verifies, what it deliberately does not
claim, and the exact Harness integration facts that Round 2 must close. It is
written against the frozen documents (`ROUND_1_IMPLEMENTATION_TASK.md`,
`ACCEPTANCE.md`, `ARCHITECTURE.md`, `SECURITY.md`, `DECISIONS.md`), not against
the implementation's convenience.

## 1. What Round 1 implements and proves

Round 1 delivers a complete first-version product core, deterministic tests and a
zero-model-call real ACP lifecycle smoke test:

- Manager + ACP Client (stdio ND-JSON / JSON-RPC 2.0), lifecycle states, request
  correlation, timeouts, malformed input, stderr separation, process-exit handling,
  graceful shutdown, and a client-side `session/prompt` gate (`ModelCallNotAuthorized`).
- One Task = one Worker = one ACP session = one workspace; durable mapping in SQLite
  before a Worker is marked ready; Manager-owned active-session registry (never relies
  on `session/list`).
- Maximum two active Workers, strict FIFO queue, promotion after slot release,
  deterministic failure isolation, restart recovery that never duplicates sessions,
  truthful `cancel_requested` / `paused` states (ACP cancel is never described as an OS
  kill; a slot is held until quiescence is confirmed).
- Manager control MCP surface (Task create/list/status/continue/pause/cancel,
  approvals, target grants, candidate Flag, screenshots, evidence ingest/export,
  Writeup, evidence ZIP, runtime status) and a Worker-scoped MCP server exposing exactly
  one typed tool `ctf_exec` (argv array, no shell string, identity from environment).
- Broker policy validation (Task/Worker/session ownership, tool allowlist and version,
  argv schema, path containment, input hashes, execution tier, approval validity,
  Task-scoped target grants, redirect/DNS revalidation logic, fail-closed denials).
- Runtime executes typed trusted tools only (internal Tier 0 static operations and fixed
  argv Tier 1 probes). Challenge-provided code execution remains blocked.
- Evidence pipeline: complete multi-frame zstd decoding, call/result correlation by
  `callId`, sequence-gap/torn-line/corrupt-frame gaps, idempotent ingestion, SQLite
  append-only per-record hash chain (tamper-evident relative to a protected head; not a
  digital signature), SHA-256 CAS for raw logs/artifacts/screenshots, deterministic
  `events.jsonl` export derived from committed SQLite rows.
- Explicit screenshot capture with blank/failed detection, CAS storage and
  Task/Worker/Step/session/time attribution (fake capture mode in deterministic tests;
  desktop capturer implemented but not exercised in Round 1).
- Chronological Markdown Writeup and deterministic evidence ZIP with
  `manifest.sha256`; independent manifest verification.
- Read-only preflight/doctor that reports installed/missing/not-verified facts and makes
  no environment mutations.
- Six project-local Skills (Core + Web/Misc/Crypto/Reverse/Pwn), UTF-8 without BOM.

## 2. Zero-model-call real ACP smoke test (PASS)

Command (evidence: `round1-evidence/raw/real-acp-smoke-pytest.txt`):

```powershell
$env:CTF_SOLVER_ENABLE_REAL_ACP = '1'
python -m pytest tests/test_real_acp_smoke.py -q -p no:cacheprovider
```

Result: **1 passed** against the locally installed, audited Harness launcher
(`resources\runtime\cli\bin\dsh.cmd`, invoked through `cmd.exe /c`, with an isolated
temporary `DSH_HOME`). The test performed `initialize` (protocolVersion 1), two
`session/new` calls with distinct absolute workspaces, an active-session `session/list`
check (active sessions excluded as documented), `session/close`, and stdin-EOF shutdown
(exit code 0). It never sent `session/prompt`: the client gate raises
`ModelCallNotAuthorized` before any write, and the test asserts that.

This proves the ACP **transport/lifecycle** path works against the real installation. It
does **not** prove model-mediated Worker behaviour (blocked, see §4).

## 3. Session-log privacy P0 gate — mechanism verified, delivery test BLOCKED

The full local audit (`D:\CTFworker\docs\HARNESS_INTEGRATION_CAPABILITY_AUDIT.md`,
SHA-256 `955136d1…fe5373`, read-only) found `dsh-session-log-deepseek` enabled by
default and observed `session-log-deepseek/delivery-accepted` events. CTF content is
sensitive, so external delivery must be disabled or excluded before real content is used.

Round 1 verified the **supported mechanism** without touching global configuration:

- Project sample: `config/acp/cordis.patch.yml` disables the plugin
  (`config.enabled: false`).
- Isolated-profile verification (evidence: `round1-evidence/raw/privacy-gate-*.txt`):
  a dedicated temporary `DSH_HOME` was created and `dsh --profile acp --patch
  config/acp/cordis.patch.yml --dump-config` was run (exit 0, **zero model calls**,
  no transport started). The composed configuration contains
  `- id: session-log-deepseek … config: { enabled: false }`.
- Only the temporary `DSH_HOME` was written (`profiles/acp/*`). The live
  `C:\Users\28746\.dsh\profiles\desktop` profile was not modified (mtime unchanged),
  and no stray global `profiles` directory remains.

**Still BLOCKED:** the required *negative outbound-delivery canary test* proves a
synthetic CTF session canary is absent from real `dsh_session_log` delivery. That
requires an official API request (a model call), which Round 1 does not authorize
(ADR-020). Real CTF content therefore must **not** be processed in Round 1.

## 4. Main-conversation entrypoint gate (`/ctf-solver` → Manager tools) — BLOCKED

The Core Skill and five specialist Skills were created under `.dsh/skills/`. The running
Harness session's own persisted session log (this very conversation) contains catalog
records that change from three CTF Skills to all six after the files were written
(evidence: `round1-evidence/raw/skill-discovery-session-summary.json`, extracted from the
session's `session.v4.jsonl.zstd` with the project decoder; the session's
system-reminder catalog also updated live in-session). That is session-log evidence of
project-level Skill discovery in this installation, with no global configuration change.

It is **not** independently re-verified by Round 1: no raw Harness-side discovery event
was produced outside the exhausted session, and Round 2 must re-verify discovery and the
`/ctf-solver` entry semantics on the real integration path. The format preconditions
(six directories, UTF-8 without BOM, frontmatter name/description, preflight ok) are
covered by deterministic tests.

The remaining requirement is that the main conversation can **invoke Manager control
tools** through a supported project-scoped path. The audited Harness MCP client only
mounts servers through profile-level configuration or through `session/new.mcpServers`
(per ACP session). Project-level Skill bundles can deliver instructions and resources but
the audit found no project-scoped *MCP server registration* mechanism. Consequently:

- Round 1 exposes a working Manager control MCP server (`python -m
  ctf_solver.mcp.manager_server`) and the Worker `ctf-exec` MCP server, verified by
  deterministic MCP tests and the end-to-end stack test that runs the Manager server as
  a real stdio MCP process.
- Attaching the Manager control server to the *current main conversation* without a
  Harness global config/profile change is **not verified and is reported BLOCKED**.
  Round 1 does not claim `/ctf-solver` is fully functional as a Harness entrypoint.
- Smallest owner decisions for Round 2: (a) authorize a profile-scoped MCP registration
  for the Manager control server in a dedicated/isolated profile, or (b) authorize a thin
  Cordis Host Plugin bundle that registers the Manager control tools at Host level, or
  (c) accept a user-launched local Manager server with an explicit out-of-band
  connection. No option is implemented in Round 1; changing the architecture is not
  assumed.

## 5. Execution boundary and Tier 2

- No OS isolation tier is available (Docker Engine/gVisor absent; WSL Ubuntu stopped).
- Worker execution is limited to typed `ctf-exec` calls through Broker/Runtime; challenge
  binaries, scripts, macros, installers and exploit payloads are never executed on the
  host. `tool.remote_probe` exists only to prove Broker denial.
- Tier 2 remains a separate future environment track; Round 1 returns `BLOCKED` for any
  operation that would require it. The current sandbox is explicitly **not** claimed as an
  OS security boundary.
- Harness-state safety: the Manager/CLI default to a **project-local isolated**
  `DSH_HOME` (`.ctf-solver-data/dsh-home`, git-ignored), so `session/new` does not write
  into the live `~/.dsh` profile/session state. A caller that explicitly wants the live
  Harness home must pass `--dsh-home` (manager server) after Round 2 authorizes that
  integration; the live profile is never modified by configuration.

## 6. Real Harness integration items NOT VERIFIED in Round 1

These are intentionally left to Round 2 and must not be reported as working:

1. Core Skill → Manager control tools in the live main conversation (blocked, see §4).
2. Model-mediated Worker behaviour and MCP `tools/call` initiation by a model
   (`session/prompt` is not authorized; the client gate blocks it).
3. Session-log external-delivery negative canary test (blocked, see §3).
4. Real Worker writes and cross-workspace write fencing under a model turn.
5. Live `session/request_permission` round trip between a model-driven Worker and the
   Manager approval relay (the ACP client implements the handler and rejects host-tool
   requests by default; a real model-triggered round trip is not exercised).
6. In-flight ACP cancel/close behaviour during a live model turn (Round 1 verifies the
   notification + close path and truthful state machine only).
7. Real desktop screenshot capture on this machine (the capturer is implemented and
   blank/failed detection is tested with deterministic images; Round 1 integration uses
   the explicit fake capture mode so evidence is reproducible and no personal desktop
   content is recorded).
8. Docker/gVisor isolation, real target access, Flag submission and challenge-code
   execution (out of scope for both development rounds without separate authorization).

## 7. Evidence authority

SQLite is the single authoritative state/event store. Raw Harness logs and artifact
bytes are immutable CAS objects. `events.jsonl` is a deterministic export derived from
committed SQLite records; there is no independent dual-write. The hash chain is
tamper-evident relative to a protected chain head, not a signature. Every denial,
execution and delivery failure produces a durable record; missing frames/records are
recorded as explicit gaps.
