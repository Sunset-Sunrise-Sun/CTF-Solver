# Round 2 Integration Task — Harness End-to-End MVP

**Status:** Approved execution task  
**Development model:** Round 2 of exactly two planned implementation rounds  
**Prerequisite:** Round 1 implementation candidate and its acceptance report are available.  
**Goal:** Integrate the completed product core with the existing Harness installation, close the synthetic end-to-end workflow, and fix Round 1 defects without changing the approved product architecture.

## 0. Authority and required reading

Read:
1. `docs/PRODUCT_SPEC.md`
2. `docs/ARCHITECTURE.md`
3. `docs/DECISIONS.md`
4. `docs/SECURITY.md`
5. `docs/EXECUTION_CONTRACT.md`
6. `docs/ACCEPTANCE.md)
7. `docs/ROUND_1_IMPLEMENTATION_TASK.md)
8. Round 1 acceptance report and complete raw test evidence.
9. The complete local Harness capability audit at `D:\CTFworker\docs\HARNESS_INTEGRATION_CAPABILITY_AUDIT.md`.

Do not assume a Round 1 “PASS” is proof of real Harness integration. Re-test every integration boundary.

## 1. Environment and authorization boundary

**Clean-room requirement:** Continue the independent implementation. Do not import/reuse old CTF Workbench code, database, API, UI, service, or runtime components from `D:\\CTF` / `D:\\CTFworker`. Do not copy source from reference repositories without a separate license/provenance review and explicit owner approval.



The owner's environment decision remains in force for Round 2:

- Do not install, uninstall, upgrade, or configure software/packages.
- Do not modify Harness global configuration, profiles, global plugins, or global MCP registrations.
- Do not deploy, install, start, configure, or modify WSL, Ubuntu, Docker, containerd, gVisor, or another OS-isolation environment.
- Do not modify `D:\CTF`, old CTF Workbench, or the 110 pre-existing uncommitted imported files and local audit report in `D:\CTFworker`.
- Do not access any real CTF target or submit any Flag.
- Do not execute challenge-provided binaries, scripts, macros, installers, or exploit payloads on the host.
- Use synthetic local fixtures and already-installed trusted tools only.
- Do not issue `session/prompt` or any model call until the privacy gate is proven and the owner has separately authorized the synthetic model-call test. If no such authorization is supplied, mark the model-mediated integration gate BLOCKED; do not infer approval from the two-round development decision.

Project-local source, Skill files, and project-scoped sample configuration may be updated in the CTF-Solver repository. Do not apply project configuration to the user's live Harness installation if doing so would change global state or exceed this authorization.

## 2. Round 2 scope

Round 2 is integration, not a new design phase. Fix Round 1 defects and verify the following product paths.

### A. Harness entrypoint and persistent conversation mode

Verify with the existing Harness installation:
- project-level discovery of the `ctf-solver` Core Skill and all five specialist Skills;
- Skill files remain UTF-8 without BOM;
- user can explicitly enter with `/ctf-solver`;
- CTF mode persists for subsequent messages and attachments in the same conversation;
- a new challenge creates a new Task;
- continuation remains on the current Task;
- ambiguous switching asks one concise clarification;
- natural-language exit ends conversation mode;
- a new conversation requires explicit entry.

The Core Skill must invoke Manager control tools through a supported project-scoped integration. No global config changes are permitted.

If project-level Skills are discovered but the main conversation cannot access Manager tools without global MCP/Plugin registration, report the exact limitation as BLOCKED. Do not fake a successful entrypoint and do not silently introduce a mandatory Cordis Host Plugin.

### B. ACP Client and independent Workers

Using the existing `dsh --profile acp` capability:
- verify ACP Client launch, initialization, process supervision, and graceful shutdown;
- create one independent ACP session per Task with `cwd=tasks/<task_id>/work`;
- mount the Worker-specific `ctf-exec` MCP server using the audited per-session `session/new.mcpServers` path;
- verify MCP server discovery, initialization, and `tools/list`;
- persist Task/Worker/session/workspace mappings;
- test two active Workers and a third FIFO Task;
- verify session close/failure isolation and Manager restart recovery;
- verify no Task inherits another Task's session, workspace, approval, or target grant.

Do not rely on `session/list` to enumerate active sessions. Do not describe ACP cancel as process-tree termination.

### C. Model-mediated Worker test gate

A direct MCP client may test the MCP server's `tools/call` interface without an LLM if the protocol allows it.

An actual Harness Worker invoking MCP through model reasoning may require `session/prompt`. Before any such prompt:
1. prove the session-log external-delivery privacy gate below;
2. obtain separate explicit user authorization for a synthetic-only model-call test;
3. use only synthetic challenge text/files and no secrets or real CTF data;
4. record model/provider, timestamps, cost/usage if available, actual tool calls/results, and evidence.

If the user has not authorized the model call, do not send it. Mark only that model-mediated gate BLOCKED and complete all other safe tests.

### D. Session-log privacy P0 gate

The full audit observed `dsh-session-log-deepseek` enabled by default and a `dsh_session_log` delivery-accepted event.

Before any real CTF data is used:
- identify the exact supported mechanism to disable delivery or exclude CTF sessions;
- do not change Harness global configuration/profile/plugin settings;
- test the mechanism only in an isolated temporary DSH_HOME or a supported project-scoped configuration;
- use a synthetic canary and a negative outbound-delivery test;
- preserve raw test evidence and verify that the canary is absent from outbound `dsh_session_log` delivery.

If the only supported solution requires a prohibited global change, stop at this gate and report BLOCKED. Do not process real challenge material and do not invent a workaround.

### E. MCP, ctf-exec, Broker, and Runtime integration

Using synthetic fixtures and trusted tools already present:
- verify Worker-facing `ctf-exec` requests are typed and schema-validated;
- verify every call passes through Manager/Broker;
- verify tool allowlist/version, argv, cwd/path containment, input/output hashes, timeouts, and execution tier;
- verify denied calls are not executed and have durable denial records;
- verify started-but-failed calls have actual exit code/stdout/stderr records;
- verify public research is not treated as target authorization;
- verify Task-scoped target grants reject wrong Task, host, port, protocol, action, expired grant, redirect, and DNS/private-address mismatch;
- verify Workers cannot access arbitrary host Shell, raw MCP bypass, Docker Socket, or raw Docker credentials.

No real target is contacted. Any operation requiring Tier 2 is BLOCKED.

### F. Evidence pipeline and recovery

Use actual generated ACP lifecycle/session logs where possible, plus deterministic fixtures:
- decode all concatenated zstd frames;
- correlate calls/results by `callId`;
- preserve monotonic `seq`, job state, approvals, command results, stderr, exit codes, and explicit gaps;
- verify idempotent ingestion;
- verify SQLite is the single authoritative state/event store;
- verify JSONL is derived from committed SQLite records (no independent dual-write);
- verify raw source logs and outputs are in CAS with SHA-256;
- verify tamper/truncation/sequence-gap detection;
- restart Manager and reconstruct Task/session/evidence mappings without inventing completion.

### G. Screenshots, Writeup, and evidence ZIP

Run a safe, project-owned synthetic program or other already-installed trusted program; do not execute challenge-provided code.

- Explicitly request screenshot capture at relevant program-running steps.
- Capture actual program/terminal state; do not generate or fabricate screenshots.
- Bind screenshots to Task/Worker/Step/session/time and verify non-empty bytes and hashes.
- Record capture failures honestly.
- Generate chronological Markdown Writeup from actual evidence records.
- Include the real program-running screenshots associated with key execution steps.
- Preserve failed attempts, actual outputs, exit codes, hypotheses, and negative results.
- Produce evidence ZIP and verify every entry against `manifest.sha256`.
- Do not convert to PDF.

### H. Synthetic end-to-end acceptance

Complete at least one synthetic challenge through:

`/ctf-solver` → intake → Task creation → category routing → plan → permitted trusted local operation → evidence ingestion → screenshot (where applicable) → result/Flag candidate state → Markdown Writeup → evidence ZIP.

Also exercise:
- two concurrent Tasks and one FIFO-queued Task;
- continuation and new Task;
- pause and cancellation request;
- Manager restart/recovery;
- a denied approval/network action;
- human-only Flag confirmation/submission boundary.

No real CTF target, real competition Flag, or untrusted challenge executable is used.

## 3. Round 2 defect handling

- Fix defects that violate the accepted contract or Round 1 implementation.
- Do not redesign accepted architecture or expand product scope.
- Do not hide failures by weakening/removing tests, changing expected results without rationale, or relabeling failed tests as skipped.
- Any newly discovered platform limitation must be reported as BLOCKED/NOT VERIFIED with raw evidence.
- If a defect requires a prohibited environment change or global Harness config change, leave it blocked and request a separate owner decision.

## 4. Round 2 deliverables

- integrated source and Skill bundle;
- complete test results with exact commands, environment, raw output, exit codes, and timings;
- actual ACP/MCP integration evidence;
- session-log privacy test evidence or explicit BLOCKED report;
- synthetic end-to-end run folder;
- Markdown Writeup and evidence ZIP with independently verified manifest;
- updated README, architecture notes, and acceptance matrix;
- file change list, Git diff/stat, commit SHA, clean-worktree proof;
- final acceptance report with PASS / FAIL / BLOCKED / NOT VERIFIED for every criterion;
- explicit list of any functions that remain unavailable because the environment or Harness integration boundary is not authorized.

Do not claim the MVP is fully accepted while any P0 privacy, entrypoint, Manager/Worker, Broker, evidence, or delivery gate is BLOCKED.

## 5. Round 2 stop conditions

Stop instead of improvising if:
- integration requires modifying Harness global config/profile/plugin state;
- session-log privacy cannot be verified without a prohibited change;
- an actual model call is required but has not been separately authorized;
- an operation requires installing software or deploying/starting WSL/Docker;
- untrusted code or a real target would need to be accessed;
- a required Harness behavior differs from the audit and needs an architecture change.

The two-round plan does not authorize a third broad development phase. After Round 2, perform independent acceptance; only then prepare narrowly scoped fixes for concrete acceptance failures.
