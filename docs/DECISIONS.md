# Architecture Decisions

**Decision log owner:** CTF-Solver architecture  
**Last updated:** 2026-11-10

Changes to accepted decisions require an explicit proposal, rationale, impact analysis, and approval.

## Accepted decisions

### ADR-001 — Harness remains the reasoning/runtime layer; use Scheme A
**Status:** Accepted

Harness is an ACP Server, not an ACP Client. The audited installation did not ship a usable ACP client package. Manager implements the ACP Client transport (or uses a separately audited ACP host/runner) and communicates with dsh --profile acp over stdio ND-JSON / JSON-RPC 2.0. No second CTF model loop.

### ADR-002 — One independent ACP session/workspace per challenge
**Status:** Accepted

Each Task gets a new Harness ACP session with cwd=tasks/<task_id>/work. The initial deployment may use one ACP Server process for multiple sessions. Independent sessions are not process/OS isolation.

### ADR-003 — Core Skill plus five category Skills
**Status:** Accepted

Deliver ctf-solver Core Skill plus ctf-web, ctf-misc, ctf-crypto, ctf-reverse, and ctf-pwn. Core Skill is the single user entry point. Skills do not enforce security policy.

### ADR-004 — Cordis Host Plugin is lightweight and optional/later
**Status:** Accepted

Cordis hooks can register tools, observe tool/session events, and participate in approval. They are useful as lightweight scheduling/authorization/evidence hooks, but are not a second runtime and are not required for the smallest Skill-plus-scripts prototype. Introduce them only where they materially improve the approved architecture. Host Plugin code is fully trusted and outside the Harness sandbox.

### ADR-005 — Two active Workers, FIFO queue
**Status:** Accepted

At most two Workers run simultaneously; further Tasks wait FIFO. Manager is authoritative for queue order and active count.

### ADR-006 — Semi-autonomous operation; human controls sensitive actions
**Status:** Accepted

The Agent may analyze, plan, write helper scripts, and run routine permitted tools. Human approval is required before untrusted-code execution, software installation/toolchain changes, and remote CTF target access. The user confirms and submits any Flag; automatic submission is excluded.

Because Tier 2 isolation is not currently available, approval alone is not sufficient to run untrusted code on the host. Such execution remains blocked until isolation is accepted.

### ADR-007 — Network policy B: public research open, CTF targets scoped
**Status:** Accepted

Public research and documentation lookup may use the internet. Competition-target access requires authorization for the specific Task/target/host/port/action. Out-of-scope targets are denied. Loopback/private destinations are not implicitly allowed.

### ADR-008 — Temporary non-OS-isolated development boundary
**Status:** Accepted with strict restrictions

The product and safe local integration can be developed without claiming OS isolation. Until Tier 2 is available, only static inspection and explicitly approved trusted tools that do not execute challenge-provided code may run. Challenge binaries/scripts/macros/exploit payloads must not execute on the host. WSL2/Docker/gVisor setup is a separate P1 environment track.

### ADR-009 — Session-log external delivery is a P0 security gate
**Status:** Accepted

The latest audit found dsh-session-log-deepseek enabled by default and observed dsh_session_log delivery acceptance. Disable delivery or configure a verified exclusion before processing real CTF data. Prove the supported mechanism with a negative outbound-delivery test.

### ADR-010 — Manager owns evidence: SQLite + CAS + append-only event contract
**Status:** Accepted

Ingest Harness session events/logs into Manager-owned SQLite state/events and a per-record hash chain; store raw outputs/files in SHA-256 CAS. SQLite is the single authoritative Manager state/event store. Generate evidence/events.jsonl deterministically from committed SQLite records; do not independently dual-write SQLite and JSONL as two authorities. Preserve raw source bytes, decode every concatenated zstd frame, correlate calls/results by callId, preserve seq/job/approval state, and record explicit gaps. Hash chain is tamper-evident bookkeeping, not a digital signature.

### ADR-011 — MCP is the unified local-tool interface; no arbitrary host Shell
**Status:** Accepted

Workers call typed MCP tools, especially ctf-exec, rather than unrestricted host Shell. Manager/Broker validates Task, Worker, tool, argv, cwd, inputs/outputs, network scope, and approvals. Workers never receive Docker Socket access.

### ADR-012 — Runtime Broker is the sole controlled Docker API caller
**Status:** Accepted architecture target; Tier 2 not available

When an isolated Docker runtime is installed, Broker is the only component allowed to manage Docker lifecycle. Worker sessions and MCP clients receive no Docker Socket or raw Docker credentials. Audit reports Docker Engine/gVisor absent.

### ADR-013 — Explicit screenshots; CLI/headless first
**Status:** Accepted

Capture important program-running screenshots through an explicit operation, associated with Task/Worker/Step/session and timestamp. GUI is auxiliary. No silent continuous capture. Java/Qt/GPU capture remains unverified.

### ADR-014 — Markdown Writeup + evidence ZIP; PDF later
**Status:** Accepted

Writeup follows actual analysis/operation sequence, preserves hypotheses, real outputs, failures, and screenshots, and is reproducible. Deliver Markdown plus evidence ZIP and SHA-256 manifest. PDF conversion is a later handoff.

### ADR-015 — Human submits Flag; First Blood is excluded
**Status:** Accepted

The Agent may identify a candidate Flag and explain its evidence. The user confirms and submits it. First Blood scanning is a separate project and not part of this MVP.

### ADR-016 — Environment/toolchain setup is a separate workstream
**Status:** Accepted

Product development defines preflight and execution contracts but does not silently install tools or alter the existing D:/CTF project or Harness profile/config. Those actions require explicit authorization.

### ADR-017 — Learn from references; do not copy blindly
**Status:** Accepted

External repositories are design references. Source reuse requires checking license, attribution, notices, and copyleft obligations. Open-ReverseLab is GPL-3.0; do not copy its code without an explicit compatibility decision.

## Open implementation questions

1. Exact Manager/ACP Client bootstrap and lifecycle.
2. Exact MCP server packaging/configuration for Manager control tools and ctf-exec.
3. Exact supported mechanism to disable/exclude dsh-session-log-deepseek.
4. ACP Client framing, timeouts, process supervision, and successful recovery.
5. Reliable cancellation of Harness jobs/process trees.
6. SQLite implementation and crash-safe transaction strategy.
7. CAS retention, export, and deletion policy.
8. Target profile and Broker grant schema.
9. Whether later releases need one ACP Server process per Task.
10. Screenshot behavior for Java/Qt/GPU applications.

Resolve these without silently changing the accepted product contract.

### ADR-018 — Exactly two concentrated implementation rounds
**Status:** Accepted by project owner

Implementation is organized into exactly two planned rounds:
1. Round 1 implements the complete product core (Manager/ACP, Task scheduler, Manager and Worker MCP interfaces, typed ctf-exec, Broker/policy contracts, six Skills, preflight, evidence pipeline, screenshots, Writeup/ZIP, and deterministic tests).
2. Round 2 integrates with the existing Harness installation, validates the real entrypoint and Worker sessions, completes the synthetic end-to-end workflow, and fixes Round 1 defects.

The former Phase 1–7 development cadence is superseded. This decision changes development sequencing only; it does not change the approved product scope or architecture. After Round 2, stop for independent acceptance. Further work must be a narrowly scoped fix tied to a concrete acceptance finding.

### ADR-019 — Existing-environment-only boundary for both rounds
**Status:** Accepted by project owner

Neither round may install, uninstall, upgrade, or configure software/packages; modify Harness global profile/config/plugin/MCP/Skill state; or deploy, install, start, or configure WSL/Ubuntu/Docker/containerd/gVisor. Use existing installed dependencies only. Project-local source, Skills, tests, and sample configuration may be created in the CTF-Solver repository. Missing dependencies or capabilities are reported BLOCKED; agents must not install or bypass them.

Both rounds use synthetic challenge data only. No real CTF target access, Flag submission, or host execution of challenge-provided code is authorized. Tier 2 isolation remains a separate future environment workstream.

### ADR-020 — No model prompt without separate authorization
**Status:** Accepted execution constraint

The two-round development approval does not itself authorize ACP `session/prompt` calls or model usage. Round 1 uses fake servers and zero-model-call ACP lifecycle tests. Round 2 may test model-mediated Worker tool use only after the session-log privacy gate is proven and the owner separately authorizes a synthetic-only model-call test. Without that authorization, mark the model-mediated gate BLOCKED.
