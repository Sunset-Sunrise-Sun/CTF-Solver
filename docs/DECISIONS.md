# Architecture Decisions

**Decision log owner:** CTF-Solver architecture  
**Last updated:** 2026-11-10

This document records product and architecture decisions that must not be silently changed by an implementation agent. A change requires an explicit proposal, rationale, impact analysis, and approval.

## Accepted decisions

### ADR-001 — Harness remains the agent runtime; use Scheme A

**Status:** Accepted

Harness is an ACP Server, not an ACP Client. The audited installation did not ship a usable ACP client package. Manager Core will implement the ACP Client transport (or use a separately audited ACP host/runner) and communicate with `dsh --profile acp` over stdio ND-JSON / JSON-RPC 2.0.

**Consequences**
- No second CTF-specific model loop.
- Harness performs reasoning and tool execution.
- Manager owns task scheduling, scope, approvals, persistence, and evidence.
- ACP client transport and lifecycle tests are first-class implementation work.

### ADR-002 — One independent ACP session and workspace per challenge

**Status:** Accepted

Each Task gets a new Harness ACP session with `cwd=tasks/<task_id>/work`.

**Consequences**
- Task/session/workspace mapping is persisted by Manager.
- One Task's files and evidence must not leak into another Task.
- Independent sessions are not OS isolation.
- The initial deployment may use one ACP Server process for multiple sessions; this is a shared failure domain, not fault isolation.

### ADR-003 — Cordis Host Plugin is a thin adapter

**Status:** Accepted

Use a minimal Cordis Host Plugin to register CTF tools, relay Manager calls, observe tool/session events, and participate in approval requests. Do not put a second reasoning loop or category-solving engine in the plugin.

**Consequences**
- Host Plugin code is fully trusted and outside the Harness sandbox.
- Keep its API small and code review strict.
- Manager policy must remain explicit; plugin hooks alone are not a security boundary.

### ADR-004 — Explicit, persistent conversation mode

**Status:** Accepted

The user enters CTF mode once with `/ctf-solver`. It remains active for the current conversation. New challenges create new Tasks; continuations remain on the active Task. A new conversation requires explicit entry again.

**Consequences**
- Do not require the command for every challenge or every turn.
- Mode state and Task state are separate.
- Do not auto-trigger CTF mode.

### ADR-005 — Two active Workers, FIFO queue

**Status:** Accepted

At most two Workers may run simultaneously. Other Tasks wait in FIFO order.

**Consequences**
- The Manager is authoritative for active count and queue ordering.
- Harness session enumeration cannot replace the Manager registry.
- Tests must cover queue order, worker failure, and slot release.

### ADR-006 — Temporary non-OS-isolated MVP boundary

**Status:** Accepted with strict restrictions

The first development/integration phase may use the current Harness environment without Docker/gVisor isolation, but this is a temporary operational boundary and must never be described as secure isolation.

Before Tier 2 is available:
- allow only metadata/hash inspection and explicitly allowlisted trusted tooling that does not execute challenge-provided code;
- do not execute challenge binaries, scripts, macros, exploit payloads, or untrusted installers on the host;
- default network access to deny;
- allow a network action only through a per-call Manager grant bound to Task, target, port, action, and expiry;
- stop/defer a task when its next step requires untrusted code execution or a capability the broker cannot constrain.

Docker/WSL-based isolation and its acceptance tests are P1 environment work. This decision does not waive the requirement for isolation before arbitrary challenge code execution.

### ADR-007 — Session-log external delivery is a P0 security gate

**Status:** Accepted

The latest audit found that the session-log plugin is enabled by default and can upload tool output, paths, and commands as `dsh_session_log`; the audit observed a `delivery-accepted` event.

**Consequences**
- Disable the plugin or add a verified exclusion before processing real CTF challenge content.
- Do not rely on an untested configuration guess.
- Acceptance requires a negative test proving that CTF session content is not delivered to the official API.
- The exact supported configuration mechanism remains an implementation verification item.

### ADR-008 — Manager owns the evidence pipeline

**Status:** Accepted

Ingest Harness session events/logs into a Manager-owned SQLite index with a per-record hash chain and a SHA-256 content-addressed store (CAS).

**Consequences**
- Preserve original raw log/event bytes.
- Decode every concatenated zstd frame.
- Correlate `tool/call` and `tool/result` by `callId`.
- Preserve sequence, job status, approval decisions, and explicit gaps.
- Generate writeups from evidence records, not from model memory alone.
- A hash chain is tamper-evident local bookkeeping, not a cryptographic signature.

### ADR-009 — MCP access must pass through Manager

**Status:** Accepted

MCP servers are opt-in and execute outside the Harness sandbox. Manager declares and wraps the allowed MCP servers/tools. Every call goes through the per-call authorization broker and evidence recorder.

**Consequences**
- No raw MCP tool bypass for Workers.
- No credentials or broad server access passed through without explicit need.
- Real MCP `tools/call` is not considered verified until a controlled integration test passes.

### ADR-010 — Screenshot capture is explicit and attributable

**Status:** Accepted

Use an explicit screenshot tool call, with Task/session/step identifiers and timestamp. Associate the image using the explicit call and a bounded time window; do not infer ownership from PID/HWND.

**Consequences**
- No silent background desktop capture.
- Store screenshots in CAS and record their digests.
- Java/Qt/GPU capture remains unverified.
- GUI input injection is not a supported MVP dependency.

### ADR-011 — Skill is delivered as a project bundle

**Status:** Accepted

Deliver the user-facing command as a project-level Skill bundle with `SKILL.md`, category references, and scripts as needed. Use UTF-8 without BOM.

**Consequences**
- Keep the Skill concise and route detailed material to references.
- Skill instructions are not a security boundary.
- The Cordis plugin/Manager implement enforcement and durable state.

### ADR-012 — Cancellation must not overclaim

**Status:** Accepted

ACP cancel has only been verified as turn cancellation, not hard process termination.

**Consequences**
- A cancellation request first becomes `cancel_requested`.
- Do not mark `cancelled` until associated jobs/processes are confirmed quiescent.
- If quiescence cannot be confirmed, expose the uncertainty and retain the task as unresolved.

### ADR-013 — Learn from references; do not copy blindly

**Status:** Accepted

External repositories are design references. Reuse of source code requires checking the specific repository license, attribution, notices, and any copyleft obligations. In particular, Open-ReverseLab is GPL-3.0; do not copy its code into this project without an explicit license-compliance decision.

## Open implementation questions (not product-direction changes)

1. Exact packaging/lifecycle of Manager Core relative to the Cordis Host Plugin; choose the smallest reliable deployment after a smoke test.
2. Exact mechanism to disable/exclude `dsh-session-log-deepseek`; must be proven by a negative test.
3. ACP Client implementation details, including executable path discovery and robust ND-JSON framing.
4. Recovery behavior after ACP Server or Manager process failure.
5. Reliable cancellation of Harness jobs/process trees.
6. SQLite implementation/library and crash-safe transaction strategy.
7. CAS retention, export, and deletion policy.
8. Target profile format and broker grant schema.
9. Whether later releases should use one ACP Server process per Task instead of one shared server.
10. Screenshot behavior for Java/Qt/GPU applications.

These questions may be resolved during implementation without changing the accepted product contract above.