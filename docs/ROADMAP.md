# Roadmap

**Baseline date:** 2026-11-10  
**Rule:** ship a small, verified Harness-native extension; do not broaden into a standalone platform.

## Phase 0 — Lock the contract and security boundary

**Status:** documentation baseline created; implementation pending.

- [x] Confirm Scheme A: Manager ACP Client + Harness ACP Server.
- [x] Confirm one Task = one ACP session + one workspace.
- [x] Confirm persistent `/ctf-solver` conversation mode.
- [x] Confirm max 2 Workers and FIFO queue.
- [x] Record evidence, screenshot, MCP, and session-log decisions.
- [ ] Import the complete 46,444-byte local Harness audit report into the repository after receiving the file.
- [ ] Identify the exact supported configuration to disable/exclude `dsh-session-log-deepseek`.
- [ ] Prove the negative outbound-delivery test before real challenge data is used.

**Exit gate:** product/architecture decisions are stable and session-log external delivery is demonstrably disabled for CTF sessions.

## Phase 1 — ACP Manager skeleton

- [ ] Implement a robust stdio ND-JSON / JSON-RPC 2.0 ACP Client.
- [ ] Resolve the installed `dsh` executable explicitly; do not assume it is on PATH.
- [ ] Start and supervise `dsh --profile acp`.
- [ ] Create one session per Task with `cwd=tasks/<id>/work`.
- [ ] Persist Task ID ↔ ACP session ID ↔ workspace mapping.
- [ ] Maintain an authoritative active-session registry; do not depend on `session/list` for active sessions.
- [ ] Enforce max 2 active Workers and FIFO scheduling.
- [ ] Persist queue state and recover safely after Manager restart.
- [ ] Add protocol framing, timeout, EOF, malformed-message, and process-exit tests.

**Exit gate:** synthetic local tasks receive independent sessions/workspaces, queue order is deterministic, and no third Worker starts while two are active.

## Phase 2 — Skill and Cordis integration

- [ ] Build the project-level `.dsh/skills/ctf-solver/SKILL.md` bundle (UTF-8 without BOM).
- [ ] Add concise category references for Web, Misc, Crypto, Reverse, and Pwn.
- [ ] Implement a thin Cordis Host Plugin with typed CTF tools.
- [ ] Relay Skill calls to Manager Core; do not add a second model loop.
- [ ] Subscribe to tool/session/approval events needed for evidence and policy.
- [ ] Implement persistent conversation-mode and explicit exit behavior.
- [ ] Test that a new Task does not require re-entering the mode.

**Exit gate:** one `/ctf-solver` invocation activates the mode for the conversation; multiple Tasks can be created and continued without repeating it.

## Phase 3 — Policy and authorization broker

- [ ] Define action classes (local read, local write, process execution, network, MCP, submit/publish, screenshot).
- [ ] Define a Task-scoped grant schema with target, port, method/action, expiry, and call count.
- [ ] Deny network by default.
- [ ] Validate redirects, DNS resolution, IP ranges, ports, and target scope.
- [ ] Require explicit user approval for sensitive actions.
- [ ] Fail closed if broker state is unavailable or stale.
- [ ] Record every grant, denial, and approval in the evidence chain.

**Exit gate:** integration tests prove that a grant for one Task/target/action cannot authorize a different Task, target, port, or action.

## Phase 4 — Evidence pipeline

- [ ] Parse every concatenated zstd frame in Harness session logs.
- [ ] Correlate `tool/call` and `tool/result` by `callId`.
- [ ] Preserve `seq`, job status, approval decisions, command events, and raw source bytes.
- [ ] Ingest events idempotently into SQLite.
- [ ] Store outputs and attachments in SHA-256 CAS.
- [ ] Append each normalized record to a tamper-evident hash chain.
- [ ] Detect missing frames, sequence gaps, unmatched calls/results, and truncated logs.
- [ ] Add tamper-detection and crash-recovery tests.

**Exit gate:** a synthetic session can be fully reconstructed, verified against raw source, and rejected if an evidence record or artifact is modified.

## Phase 5 — Screenshot and writeup delivery

- [ ] Add explicit desktop/window screenshot capture.
- [ ] Bind each capture request to Task/session/step/time.
- [ ] Store screenshots in CAS and verify non-empty image data.
- [ ] Generate Markdown writeups from canonical evidence records.
- [ ] Embed only verified screenshots/artifacts.
- [ ] Include failed attempts, actual command/output excerpts, and unverified gaps.
- [ ] Generate a SHA-256 manifest for deliverables.

**Exit gate:** a local synthetic challenge produces a writeup whose commands, outputs, screenshots, and artifact hashes can be traced back to evidence records.

## Phase 6 — Local end-to-end MVP acceptance

- [ ] Run an authorized, synthetic, local-only challenge through intake → solve → verify → writeup.
- [ ] Test two simultaneous Workers and FIFO backlog.
- [ ] Test continuation, new Task, pause, cancellation request, and recovery.
- [ ] Prove no CTF session-log content is sent to the official API.
- [ ] Prove there is no raw MCP or network bypass.
- [ ] Verify all deliverables and manifests independently.

**Exit gate:** all P0 checks in [ACCEPTANCE.md](ACCEPTANCE.md) pass. No public target is needed for this acceptance.

## P1 — OS isolation and toolchain

The latest audit reports WSL2 installed but Ubuntu 24.04 stopped, with Docker Engine and gVisor absent.

- [ ] Bring up the WSL2 distribution and verify its lifecycle.
- [ ] Install and configure a disposable isolated execution environment.
- [ ] Verify filesystem, process, network, credential, and resource boundaries.
- [ ] Test malicious/synthetic escape attempts and cleanup behavior.
- [ ] Install only the required CTF tools in the isolated environment (e.g. Ghidra/JDK, GDB, pwntools, SageMath, Wireshark/tshark, radare2/rizin).
- [ ] Validate tool versions and deterministic environment snapshots.

**Exit gate:** arbitrary challenge-provided code may run only after the isolation boundary and its tests are independently accepted.

## P2 — Category depth and optional integrations

- [ ] Expand category references based on real solved challenges.
- [ ] Add opt-in MCP adapters after per-call broker support is stable.
- [ ] Evaluate advanced reverse-engineering tools and headless workflows.
- [ ] Evaluate a dedicated screenshot helper for applications that cannot be captured reliably.
- [ ] Consider per-Task ACP Server processes if the shared-process failure domain becomes unacceptable.

P2 work must not delay or weaken the P0 safety/evidence requirements.