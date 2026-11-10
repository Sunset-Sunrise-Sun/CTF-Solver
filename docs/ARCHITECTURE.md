# Architecture

**Status:** approved logical architecture; implementation details remain subject to acceptance tests  
**Date:** 2026-11-10

## 1. Principle

DeepSeek Harness remains the reasoning/runtime layer. CTF-Solver adds:
- Core Skill + five category Skills;
- Manager and Manager-owned ACP Client;
- independent ACP Worker session/workspace per Task;
- typed ctf-exec interface through MCP;
- Runtime and policy Broker;
- SQLite authoritative state/events + CAS artifact bytes;
- Markdown Writeup + evidence ZIP;
- optional lightweight Cordis hooks.

There must not be a second CTF-specific model loop.

## 2. Logical architecture

User → /ctf-solver Core Skill → CTF Manager.

Manager owns Task registry, FIFO scheduler (max 2), ACP Client, MCP tool registry, policy Broker, SQLite event/state index and hash chain, CAS, screenshot/evidence association, and Writeup/evidence ZIP generation.

Manager ACP Client → dsh --profile acp (Harness ACP Server) → one independent Worker session per Task.

Worker → typed ctf-exec MCP tool → Manager/Broker → Runtime → approved CLI/headless tool.

When Tier 2 is available, Broker is the sole controlled Docker API caller. Workers never receive Docker Socket access.

Cordis Host Plugin is a lightweight optional integration layer for event/approval/scheduling hooks; it is not a second runtime.

## 3. Core Skill and five specialist Skills

The Core Skill is the sole user-facing entry point: /ctf-solver. It owns intake, rules, Task lifecycle instructions, and routing.

Five specialist Skills:
- ctf-web
- ctf-misc
- ctf-crypto
- ctf-reverse
- ctf-pwn

They provide category-specific reasoning guidance and on-demand references. They do not grant permissions or execute host commands by themselves.

Project-level bundles live under .dsh/skills/ in the nearest Harness project root. Use UTF-8 without BOM.

## 4. Manager

Manager is the authoritative control plane. It owns conversation mode and Task registry, Task/Worker/session/workspace mapping, max-two FIFO scheduling, competition profiles and target grants, ACP Client lifecycle, MCP tool registry and ctf-exec routing, Broker, session-log ingestion, SQLite/CAS evidence, screenshot attribution, and deliverable generation.

Manager is not a second agent loop. It schedules and governs Harness sessions; Harness performs challenge reasoning.

## 5. ACP Client and Harness ACP Server

The audited Harness is an ACP Server, not an ACP Client. The shipped runtime did not provide a dsh-subagent-acp client. Manager must implement the ACP Client transport or use a separately audited ACP host/runner.

Verified server mode: dsh --profile acp. Transport: stdio ND-JSON, JSON-RPC 2.0.

For each Task, Manager calls session/new with cwd=tasks/<task_id>/work and persists the returned ACP session ID.

The initial design may use one managed ACP Server process with multiple independent sessions. This is session isolation, not process or OS isolation.

Audited implications:
- session/list does not include active sessions; Manager's registry is authoritative.
- one ACP process hosting multiple sessions is a shared failure domain.
- ACP cancel stops a turn but has no verified force-kill of all underlying work.
- resume error paths were tested; successful production recovery and in-flight close/cancel remain acceptance items.

Do not mark a Task cancelled until associated jobs/processes are quiescent.

## 6. MCP and ctf-exec

MCP is the unified local-tool interface. Workers invoke typed ctf-exec, not arbitrary host Shell.

ctf-exec uses a tool identifier and argv array, not an arbitrary shell string. Runtime validates Task/Worker, workspace, tool/version, arguments, input/output paths, execution tier, and network authorization. See EXECUTION_CONTRACT.md.

Manager/Broker is the only controlled Docker API caller when isolated runtime is available. Workers never receive Docker Socket mounts, Docker credentials, or raw Docker API access.

## 7. Runtime and Broker

Runtime performs approved CLI/headless tool execution. Broker is the policy enforcement point and trusted computing base for privileged operations.

Broker validates Task and Worker identity, allowed tool/version, argv schema, cwd/path containment, inputs/outputs, public-research vs CTF-target network policy, approvals/grants, execution tier, and resource limits.

The product performs preflight and reports missing tools. Environment/toolchain installation is a separate workstream and requires explicit authorization.

## 8. Cordis Host Plugin

Cordis Host Plugin is lightweight and optional/later, not a prerequisite for the smallest Skill-plus-scripts prototype. The audit verified it can register tools, intercept tool lifecycle hooks, subscribe to session events, and respond to approval requests.

Use it where it materially improves scheduling, authorization, or evidence hooks. Keep it thin: Host Plugin code is fully trusted and outside the Harness sandbox. Do not move policy enforcement into an unreviewed hook or treat the plugin as sandboxed.

## 9. Evidence data flow

Harness session JSONL.zstd and live events → parser/normalizer → callId and seq correlation → SQLite event/state index with hash chain + CAS raw bytes → Markdown Writeup and evidence ZIP.

The audit verified tool/call, tool/result, job/registered, job/settled, approval and command events; tool calls/results correlate by callId and seq is monotonic.

Session logs use concatenated independent zstd frames. A single-frame Node decode returned only the first frame; Python zstandard streaming decode read the complete audited log. Production ingestion must decode every frame.

Harness logs have no hash chain or signature. Manager must preserve raw source bytes and create its own append-only tamper-evident chain. This is not a digital signature.

## 10. Evidence record contract

Each normalized record includes schema version, event/source IDs, Task/Worker/conversation/ACP session/Step IDs, sequence/timestamp, event type, tool/version/argv/cwd, input/output refs and hashes, exit code, stdout/stderr refs, job/approval/network-grant refs, screenshot refs, previous/current chain hash, provenance, and parser version.

Ingestion must be idempotent, detect sequence gaps, retain unmatched calls/results as explicit gaps, and preserve raw event data in CAS.

## 11. Screenshot attribution

The audit verified desktop capture with PowerShell CopyFromScreen and window capture with PrintWindow flag 2. A Worker has no independent desktop window, so PID-to-HWND does not establish Worker ownership.

Capture important program-running steps through an explicit operation. Metadata includes Task, Worker, Step, ACP session, scope, and timestamp. Store images in CAS and associate them with the explicit call and bounded time window. No silent continuous desktop capture. Java/Qt/GPU capture remains unverified.

CLI/headless evidence is preferred; GUI is auxiliary.

## 12. Suggested local data layout

Runtime data stays outside Git:

- .ctf-solver-data/manager.sqlite
- .ctf-solver-data/cas/sha256/
- .ctf-solver-data/sessions/
- tasks/<task_id>/work/
- tasks/<task_id>/evidence/events.jsonl
- tasks/<task_id>/evidence/shots/
- tasks/<task_id>/evidence/manifest.sha256
- tasks/<task_id>/writeup.md

## 13. Deliverables

Each Task produces a chronological, reproducible Markdown Writeup, an evidence ZIP with selected outputs/screenshots/intermediate artifacts, and a SHA-256 manifest. PDF conversion is a later handoff.

## 14. Failure and recovery

ACP Server exit marks affected sessions interrupted. Manager restart reloads Task/queue/session mappings from SQLite. Missing/corrupt logs and zstd decode failures create explicit evidence gaps. Cancellation remains cancel_requested until quiescence is verified. Failed/blank screenshots are recorded as failures.