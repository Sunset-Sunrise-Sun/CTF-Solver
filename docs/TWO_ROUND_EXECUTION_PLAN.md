# CTF-Solver — Two-Round Development Execution Plan

**Status:** Approved and frozen by the project owner  
**Decision date:** 2026-11-10  
**Development cadence:** exactly two planned implementation rounds  
**Environment boundary:** no software installation, no Harness global configuration changes, no WSL/Docker deployment or startup.

## 1. Purpose

This document is the canonical execution index for the first CTF-Solver implementation. It prevents the work from drifting into the old CTF Workbench, a standalone CTF platform, a second agent loop, or a sequence of unbounded micro-phases.

The product contract remains in:
- `PRODUCT_SPEC.md`
- `ARCHITECTURE.md`
- `DECISIONS.md`
- `SECURITY.md`
- `EXECUTION_CONTRACT.md`
- `ACCEPTANCE.md`

This plan decides only how to execute the approved product in two concentrated rounds.

## 2. Frozen product direction

CTF-Solver is a semi-autonomous CTF-solving extension for DeepSeek Harness:
- Harness remains the reasoning/runtime layer; no second model loop.
- Explicit entry is `/ctf-solver`; mode persists for the current conversation.
- Core Skill plus exactly five category Skills: Web, Misc, Crypto, Reverse, Pwn.
- Manager owns Task lifecycle, ACP Client, scheduling, MCP control, Broker, evidence, and delivery.
- One challenge = one Task = one independent ACP session/workspace.
- At most two active Workers; subsequent Tasks queue FIFO.
- Worker execution uses typed MCP `ctf-exec`, not arbitrary host Shell.
- Human approval controls sensitive actions; target authorization is Task-scoped.
- User confirms and submits Flag.
- Output is chronological Markdown Writeup + evidence ZIP + SHA-256 manifest. PDF is a later handoff.
- CLI/headless first; explicit screenshots document important program-running steps.
- Cordis is optional and thin, not a second runtime.

The approved product contract is not reopened during implementation. A change requires a written proposal, impact analysis, and owner approval.

## 3. Exactly two implementation rounds

### Round 1 — Complete Product Core

**Task file:** [ROUND_1_IMPLEMENTATION_TASK.md](ROUND_1_IMPLEMENTATION_TASK.md)

Build the complete first-version code structure in one concentrated round:
1. Manager and robust ACP Client.
2. Task/Worker/session/workspace registry, persistence, two-Worker FIFO scheduler.
3. Manager control API/MCP surface.
4. Worker MCP server and typed ctf-exec contract.
5. Runtime/Broker policy and approval/network-grant model.
6. Core Skill and all five specialist Skills.
7. Read-only first-run preflight/doctor.
8. Multi-frame zstd log ingestion, SQLite hash chain, CAS, deterministic JSONL export.
9. Explicit screenshot capture and evidence association.
10. Markdown Writeup and evidence ZIP generation.
11. Fake ACP/MCP servers, synthetic fixtures, comprehensive tests.
12. Zero-model-call real ACP lifecycle smoke test if it uses only the already-installed audited capability.

Round 1 must deliver an implementation candidate for the entire product, not only an ACP Client skeleton. Fake/synthetic integration is acceptable where real model execution is not authorized. Do not claim the MVP is accepted yet.

### Round 2 — Harness Integration and End-to-End Closure

**Task file:** [ROUND_2_INTEGRATION_TASK.md](ROUND_2_INTEGRATION_TASK.md)

Integrate the Round 1 product with the existing Harness installation and close the synthetic workflow:
1. Verify project-level Skill discovery and the actual `/ctf-solver` entry path.
2. Verify Core Skill → Manager control tools without changing Harness global config.
3. Verify real ACP Client lifecycle and independent Worker sessions.
4. Verify per-session Worker MCP mounting/discovery and typed ctf-exec.
5. Verify Broker approvals, Task-scoped target grants, and fail-closed behavior.
6. Verify session-log privacy using a synthetic canary.
7. Verify actual multi-frame log ingestion, SQLite/CAS integrity, restart recovery.
8. Verify explicit screenshots, chronological Markdown Writeup, and evidence ZIP.
9. Complete a synthetic end-to-end challenge, two active Tasks, and one FIFO-queued Task.
10. Fix defects found in Round 1 without redesigning the accepted architecture.

A model-mediated `session/prompt` test requires separate explicit user authorization after the session-log privacy gate is proven. If not authorized, mark only that gate BLOCKED; do not infer approval.

## 4. Environment boundary — applies to both rounds

The owner explicitly did not authorize:
- software/package installation, uninstallation, upgrade, or system configuration;
- Harness global profile/config/plugin/MCP/Skill changes;
- WSL/Ubuntu/Docker/containerd/gVisor installation, startup, deployment, or configuration;
- changes to the old `D:\CTF` project or old Workbench;
- changes to the 110 pre-existing uncommitted imported files and local audit report in `D:\CTFworker`.

Use existing installed dependencies only. Declare missing dependencies in project metadata and mark dependent tests BLOCKED. Project-local source, Skill bundles, and sample configuration files may be developed inside this repository, but do not apply them to global Harness state.

Use synthetic local challenge data only. Do not contact real CTF targets, submit Flags, or execute challenge-provided code on the Windows host. Tier 2 isolation is not part of these two rounds.

## 5. Mandatory P0 release gates

The product must not process real CTF content until all applicable gates pass:
- Session-log external delivery is disabled/excluded through a supported, verified mechanism. The full audit observed `dsh-session-log-deepseek` delivery acceptance. Do not change global Harness configuration to achieve this under the current authorization.
- Main conversation can invoke Manager control tools through a supported project-scoped integration; do not claim `/ctf-solver` works if it only discovers a Skill but cannot reach Manager.
- Each Task maps to exactly one ACP session and workspace; max two active Workers and FIFO queue are enforced by Manager.
- Worker operations pass through typed ctf-exec and Broker; no arbitrary Shell, raw MCP, or Docker Socket bypass.
- Task-scoped approvals/network grants fail closed.
- Evidence is complete, reproducible, and tamper-evident; missing data is explicit.
- User confirmation/submission remains required for Flag.

If a P0 gate requires a prohibited global configuration or environment change, mark BLOCKED and request a separate owner decision. Do not silently bypass it.

## 6. Evidence authority

SQLite is the single authoritative Manager state/event store. Raw Harness logs and artifacts are immutable CAS objects. `events.jsonl` is a deterministic export derived from committed SQLite records; it is not an independently written second source of truth. Do not implement an uncoordinated SQLite + JSONL dual-write.

The hash chain is tamper-evident relative to a protected head; it is not a digital signature.

## 7. Developer coordination and Git discipline

- One lead agent owns integration, final code review, branch state, and acceptance report.
- Parallel coding is allowed only for non-overlapping modules with explicit file ownership; do not let multiple agents edit the same files concurrently.
- Product runtime concurrency (two CTF Workers) is separate from developer-agent concurrency.
- Do not copy source from reference repositories without license review.
- Keep secrets, challenge files, real logs, databases, screenshots, and CAS data out of Git.
- Never reset/clean/stash/overwrite the protected `D:\CTFworker` state.
- Do not create a PR/push/merge unless the owner separately requests it.

## 8. Final reporting

At the end of each round provide:
- commit SHA and branch;
- changed-file inventory;
- exact commands, environment, raw test outputs, exit codes, and timings;
- tests added/changed/removed (removals require explicit rationale; do not weaken tests);
- PASS / FAIL / BLOCKED / NOT VERIFIED matrix;
- unresolved risks and owner decisions;
- proof that prohibited environment and legacy project state were untouched.

After Round 2, stop for independent acceptance. Do not silently start a third broad phase. Any further work must be a narrowly scoped fix tied to a concrete acceptance finding.
