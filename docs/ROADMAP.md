# Roadmap

**Baseline date:** 2026-11-10  
**Rule:** implement the approved Harness-native Skill + Manager + typed Runtime architecture. Keep environment/toolchain setup separate.

## Phase 0 — Lock the contract

**Status:** documentation baseline created; implementation pending.

- [x] Scheme A: Manager ACP Client + Harness ACP Server.
- [x] One Task = one ACP session + one workspace.
- [x] Persistent /ctf-solver conversation mode.
- [x] Maximum 2 Workers and FIFO queue.
- [x] Core Skill + five category Skills.
- [x] Typed ctf-exec through MCP; no arbitrary host Shell.
- [x] Semi-autonomous approvals and human Flag submission.
- [x] Public research access separated from per-Task CTF target authorization.
- [x] Evidence, screenshot, Markdown Writeup + evidence ZIP decisions.
- [ ] Import the complete 46,444-byte local Harness audit report after the file is made available.
- [ ] Identify the exact supported configuration to disable/exclude dsh-session-log-deepseek.
- [ ] Prove the negative outbound-delivery test before real challenge data is used.

**Exit gate:** contract stable; session-log external delivery demonstrably disabled for CTF sessions.

## Phase 1 — Manager and ACP Client

- [ ] Implement robust stdio ND-JSON / JSON-RPC 2.0 ACP Client.
- [ ] Resolve the installed dsh executable explicitly; do not assume it is on PATH.
- [ ] Start/supervise dsh --profile acp.
- [ ] Create one session per Task with cwd=tasks/<id>/work.
- [ ] Persist Task ↔ Worker ↔ ACP session ↔ workspace mapping.
- [ ] Maintain authoritative active-session registry; do not depend on session/list.
- [ ] Enforce max 2 active Workers and FIFO scheduling.
- [ ] Persist queue state and recover safely after Manager restart.
- [ ] Test framing, timeout, EOF, malformed messages, process exit, and recovery.
- [ ] Surface the shared ACP-process failure-domain limitation.

**Exit gate:** synthetic local Tasks receive independent sessions/workspaces; queue order is deterministic; no third Worker starts while two are active.

## Phase 2 — MCP and typed ctf-exec Runtime

- [ ] Define Manager MCP control surface.
- [ ] Implement ctf-exec with typed tool name, argv, cwd, input/output files, timeout, and Task/Worker/Step identity.
- [ ] Build Manager-owned tool catalogue and version/preflight checks.
- [ ] Validate workspace containment and input/output paths.
- [ ] Implement Broker authorization and action classes.
- [ ] Do not expose arbitrary host Shell or Docker Socket.
- [ ] Keep Worker access limited to scoped MCP tools.
- [ ] Record allowed, denied, failed, and completed executions.

**Exit gate:** all Worker tool execution goes through typed ctf-exec and Broker; no raw Shell or Docker bypass exists.

## Phase 3 — Core + five Skills and Harness integration

- [ ] Implement project-level Core Skill ctf-solver.
- [ ] Implement ctf-web, ctf-misc, ctf-crypto, ctf-reverse, and ctf-pwn.
- [ ] Ensure Skill files are UTF-8 without BOM.
- [ ] Implement persistent conversation-mode instructions and Task routing.
- [ ] Add category prerequisites and CLI/headless-first workflows.
- [ ] Add first-run preflight reporting for required tools.
- [ ] Evaluate thin Cordis hooks only where they add value; they are optional/later, not a second runtime.

**Exit gate:** one /ctf-solver invocation activates the mode for the conversation; multiple Tasks can be created and continued without repeating it.

## Phase 4 — Policy, scope, and approvals

- [ ] Define competition profiles and rules.
- [ ] Allow public research/documentation access separately from target traffic.
- [ ] Require per-Task grants for remote challenge access.
- [ ] Bind grants to host/IP, port, protocol/method/action, expiry, and call count.
- [ ] Require human approval for untrusted-code execution, software installation, and remote target access.
- [ ] Block untrusted code execution until Tier 2 is accepted.
- [ ] Keep Flag confirmation/submission with the user.
- [ ] Fail closed if Broker state is unavailable or stale.

**Exit gate:** a grant for one Task/target/action cannot authorize another Task/target/action.

## Phase 5 — Evidence pipeline

- [ ] Parse every concatenated zstd frame in Harness session logs.
- [ ] Correlate tool/call and tool/result by callId.
- [ ] Preserve seq, job status, approval decisions, command events, and raw source bytes.
- [ ] Ingest events idempotently into SQLite.
- [ ] Store outputs/files/screenshots in SHA-256 CAS.
- [ ] Append normalized records to a tamper-evident hash chain and evidence/events.jsonl.
- [ ] Generate manifest.sha256.
- [ ] Detect missing frames, sequence gaps, unmatched calls/results, and truncated logs.
- [ ] Add tamper-detection and crash-recovery tests.

**Exit gate:** a synthetic session can be reconstructed from evidence; modifications are detected.

## Phase 6 — Screenshot, Writeup, and evidence ZIP

- [ ] Add explicit screenshot capture for key program-running steps.
- [ ] Bind captures to Task/Worker/Step/session/time.
- [ ] Store screenshots in CAS and verify non-empty image data.
- [ ] Generate chronological, reproducible Markdown Writeups from evidence.
- [ ] Preserve hypotheses, real outputs, failed attempts, and negative results.
- [ ] Include only verified screenshots/artifacts.
- [ ] Package evidence and manifest into a ZIP.
- [ ] Keep PDF conversion as a later handoff.

**Exit gate:** a local synthetic challenge produces a Writeup and evidence ZIP traceable to raw evidence.

## Phase 7 — Local end-to-end MVP acceptance

- [ ] Run an authorized synthetic local challenge through intake → plan → permitted execution → verification → Writeup.
- [ ] Do not contact public CTF targets during tests.
- [ ] Test two simultaneous Tasks and FIFO backlog.
- [ ] Test continuation, new Task, pause, cancellation request, and recovery.
- [ ] Prove no CTF session-log content is sent to the official API.
- [ ] Prove no raw Shell, raw MCP, or Docker Socket bypass.
- [ ] Verify Flag submission remains a human action.
- [ ] Independently verify deliverables and manifests.

**Exit gate:** all P0 checks in ACCEPTANCE.md pass.

## Separate environment/toolchain track (P1)

This track is separate from product development. Do not install or change environment components without explicit authorization.

Latest audit: WSL2 installed but Ubuntu 24.04 stopped; Docker Engine/gVisor absent; Java/Ghidra, GDB, pwntools, SageMath, Wireshark/tshark, radare2/rizin and other CTF tools are missing or incomplete.

- [ ] Preflight/inventory existing tools and versions.
- [ ] Obtain explicit authorization for environment changes.
- [ ] Bring up the WSL2 distribution.
- [ ] Install/configure disposable isolated runtime and verify its boundary.
- [ ] Make Broker the sole controlled Docker API caller; Worker has no Docker Socket.
- [ ] Install only required CTF tools.
- [ ] Record tool versions and runtime image digest.
- [ ] Test filesystem, process, network, credential, resource, cleanup, and cross-Task boundaries.

**Exit gate:** arbitrary untrusted challenge code runs only after isolation tests pass.

## P2 — Future enhancements

- [ ] Expand specialist Skills from verified solved-challenge experience.
- [ ] Add optional Cordis hooks for stronger event/approval capture.
- [ ] Add opt-in MCP adapters after Broker enforcement is stable.
- [ ] Evaluate specialized headless reverse-engineering tools.
- [ ] Consider a separate First Blood scanner project; do not add it to this MVP.