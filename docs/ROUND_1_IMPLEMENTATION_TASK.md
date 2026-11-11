# Round 1 Implementation Task — Complete Product Core

**Status:** Approved execution task  
**Development model:** Round 1 of exactly two planned implementation rounds  
**Target:** Deliver the complete first-version product code and deterministic tests, with safe local/fake integrations. Round 1 is not limited to the ACP Client.

## 0. Authority and required reading

Read these repository documents before coding, in this order:

1. `README.md`
2. `docs/PRODUCT_SPEC.md`
3. `docs/ARCHITECTURE.md`
4. `docs/DECISIONS.md`
5. `docs/SECURITY.md`
6. `docs/EXECUTION_CONTRACT.md`
7. `docs/ACCEPTANCE.md`
8. `docs/HARNESS_INTEGRATION_AUDIT_SUMMARY.md`
9. This two-round plan and `docs/ROUND_2_INTEGRATION_TASK.md`

The complete Harness audit is reported locally at:

`D:\CTFworker\docs\HARNESS_INTEGRATION_CAPABILITY_AUDIT.md`

Size: 46,444 bytes  
SHA-256: `955136d156a878fc932243081cc42d72575bc4f65510dc03163cb689d7fe5373`

Read the complete local report for exact ACP launch arguments, environment variables, protocol fields, session-log paths, and the verified session-log delivery behavior. Do not guess from the summary.

If any task instruction conflicts with the accepted Product Spec, Architecture, Decisions, or Security Model, stop and report the conflict. Do not silently change the product.

## 1. Approved development and environment boundary

**Clean-room requirement:** CTF-Solver is a fully independent implementation. Do not reuse or import code, database schemas/migrations, APIs, UI, services, or runtime components from the old CTF Workbench / `D:\\CTF` project or `D:\\CTFworker`. Do not copy code from reference repositories. Technical ideas and public protocol knowledge may inform the design; any proposed source reuse requires a separate license/provenance review and explicit owner approval.



The owner has approved a strict two-round development plan with the following environment boundary:

**Allowed**
- Modify files belonging to the new `CTF-Solver` repository on the assigned development branch.
- Create project-local source, tests, documentation, Skill bundles, and sample project-scoped configuration files.
- Use software and Python packages already installed and available.
- Run deterministic unit tests, fake-server tests, static checks, and safe local tests using trusted project-owned fixtures.
- Use a separate clean clone/worktree if necessary.

**Not authorized**
- Install, uninstall, upgrade, or configure software or Python packages on the machine.
- Modify Harness global configuration, profiles, global plugins, global MCP registrations, or global Skills.
- Deploy, install, start, configure, or modify WSL, Ubuntu, Docker, containerd, gVisor, or another OS-isolation environment.
- Modify the old `D:\CTF` project or any old CTF Workbench code/database/API/UI/service.
- Modify, stage, stash, clean, reset, delete, rename, or overwrite the 110 pre-existing uncommitted imported files in `D:\CTFworker`, or its separate local audit report.
- Access a real CTF target, submit a Flag, or run challenge-provided binaries/scripts/macros/exploit payloads on the Windows host.
- Make a model call through `session/prompt` without separate explicit user authorization.

A dependency may be declared in project metadata, but it must not be installed. If a required dependency is absent, mark the affected test/function BLOCKED and report the exact dependency; do not install it.

Use only synthetic challenge data in development and integration tests. Keep generated databases, logs, screenshots, challenge files, secrets, and CAS data outside Git.

## 2. Product contract — do not redesign

Implement the already-approved product:

- DeepSeek Harness remains the reasoning/runtime layer. Do not create a second model loop or standalone CTF platform.
- Explicit user entry: `/ctf-solver`. After activation, CTF mode persists for the current conversation; do not require repeating the command for every Task.
- One challenge = one Task = one independent ACP Worker session and workspace.
- Exactly five challenge categories: Web, Misc, Crypto, Reverse, Pwn.
- Maximum two active Workers. Additional Tasks wait in FIFO order.
- Core Skill plus five specialist Skills.
- Workers use typed MCP `ctf-exec` through Manager/Broker/Runtime. No arbitrary host Shell and no raw Docker Socket.
- Semi-autonomous solving. Sensitive operations require Task-scoped human approval.
- Public research/documentation lookup is distinct from active CTF-target traffic.
- User confirms and submits every Flag. No automatic submission.
- Evidence-backed Markdown Writeup and evidence ZIP. PDF conversion is a later handoff.
- CLI/headless first. GUI is auxiliary and explicit screenshots are required for important program-running steps.
- Cordis Host Plugin is optional and thin. It must not become a second runtime or a mandatory new development track unless a concrete integration blocker is demonstrated and the owner approves a change.

## 3. Round 1 implementation scope

Round 1 is the concentrated implementation round. Implement the complete product structure below; use fakes/synthetic fixtures where real Harness/model execution is not yet authorized.

### A. Repository and packaging

- Establish a clean project layout for Manager, ACP client, MCP servers, Runtime/Broker, Skills, evidence, Writeup, tests, and documentation.
- Add reproducible project metadata and dependency declarations without installing anything.
- Add project-local Skill bundle files under the audited project-level discovery location (for example `.dsh/skills/`).
- Ensure every Skill file is UTF-8 without BOM.
- Add a clear local start/preflight command that does not modify Harness global settings or install dependencies.
- Keep all runtime data outside Git and expand `.gitignore` accordingly.

### B. Core Skill and five specialist Skills

Implement:
- `ctf-solver` — sole user-facing Core Skill and Task router.
- `ctf-web`
- `ctf-misc`
- `ctf-crypto`
- `ctf-reverse`
- `ctf-pwn`

Core Skill intake must accept the previously agreed information:
- challenge title/name and category;
- description as text and/or screenshot;
- challenge ZIP or other supplied files;
- whether a container/environment is supplied;
- target address and port, if applicable;
- competition rules/scope information when available.

Do not demand every optional field at once. Ask only for the one essential missing detail needed to proceed.

Core Skill behavior:
- activate persistent CTF mode after `/ctf-solver`;
- maintain the active Task context across follow-up messages;
- create a new Task for a clearly new challenge without overwriting prior Tasks;
- ask one concise clarification when continuation vs. new Task is ambiguous;
- autonomously explore a solvable path and report only when genuinely blocked;
- never fabricate tool output, screenshots, a Flag, or completion status.

Specialist Skill requirements:
- Web: source/code/configuration and protocol analysis first; active target requests only through a Task-scoped grant.
- Misc: inspect file/archive metadata first; for encrypted archives, autonomously analyze likely password clues and perform only bounded local attempts; ask for help only after a documented finite attempt budget is exhausted.
- Crypto: combine mathematical reasoning and tool-assisted computation; prioritize identifying a mathematical structure or breakthrough before brute-force-style computation.
- Reverse: static analysis first; dynamic execution only inside a separately accepted Tier 2 isolation environment. Tier 2 is unavailable in this development plan, so challenge-provided binaries remain non-executable.
- Pwn: local static analysis and safe local reasoning first; remote exploitation requires a one-time, Task/target/action-scoped authorization window. No remote target is contacted in either development round.
- All categories inherit the Core Skill safety, evidence, and human-Flag rules.

Skills are reasoning instructions, not security controls. Enforce permissions in Manager/Broker.

### C. Manager, ACP Client, Task lifecycle, and scheduler

Implement:
- robust stdio ND-JSON / JSON-RPC 2.0 ACP Client;
- request ID generation/correlation, partial reads, multiple messages per read, response/event interleaving, stderr separation, CRLF/LF, large messages, malformed JSON, EOF, timeout, and process-exit handling;
- explicit ACP process lifecycle states and structured diagnostics;
- launch of the already-audited `dsh --profile acp` mode using the exact executable/arguments from the full audit; do not assume PATH;
- one `session/new` per Task with `cwd=tasks/<task_id>/work`;
- persist Task ID, Worker ID, ACP session ID, workspace, status, and timestamps before marking a Worker ready;
- Manager-owned active-session registry; do not rely on `session/list` to show active sessions;
- one Worker per Task and no workspace/session reuse;
- maximum two active Workers and strict FIFO queue for subsequent Tasks;
- durable Task/queue/session mapping and safe restart recovery;
- truthful `cancel_requested` / `interrupted` states. ACP cancel is not an OS process kill; do not release a slot until associated work is known to be quiescent;
- isolate failure reporting: one Worker failure must not silently complete or corrupt another Task.

The initial architecture may use one managed ACP Server process for multiple sessions. Document its shared failure domain. Do not claim independent OS processes or OS isolation.

### D. Manager control interface, MCP, ctf-exec, Runtime, and Broker

Implement the Manager control API and MCP surface needed for the Core Skill to:
- create/intake a Task;
- list Tasks and obtain Task status;
- continue a Task;
- request pause/cancel;
- request and record approvals;
- retrieve evidence and export deliverables.

Implement the Worker-facing typed MCP execution interface:
- typed tool identifier;
- argv array (never an arbitrary shell command string);
- Task/Worker/Step identity;
- approved tool/version constraint;
- workspace/cwd;
- input files with hashes;
- output paths;
- timeout/resource limits;
- optional approval/network-grant references.

Implement Broker validation for:
- Task and Worker ownership;
- Worker-to-ACP-session mapping;
- tool allowlist and version/preflight;
- argv schema and shell-expansion prevention;
- cwd/path containment;
- input/output path ownership;
- execution tier;
- approval validity;
- Task-specific target host/IP/port/protocol/action/expiry/call-count;
- redirect and DNS destination revalidation where applicable.

Runtime must fail closed. A denied call must be distinguishable from a process that actually started and failed.

**Execution boundary for both rounds:** only static inspection and explicitly allowlisted trusted tools that do not execute challenge-provided code. Do not expose arbitrary PowerShell/CMD, Python-eval, shell-string, raw MCP bypass, or Docker Socket access to Workers. If Tier 2 is required, return BLOCKED.

### E. Approval and network-scope model

Implement data contracts and deterministic tests for:
- approval tied to a specific Task and proposed action;
- remote target grant tied to Task ID, competition profile, host/IP, port, protocol/method/action, expiry/TTL, call count, approver, and decision timestamp;
- no grant inheritance between Tasks;
- public documentation/research distinguished from target traffic;
- loopback/private destinations not implicitly trusted;
- expired, mismatched, missing, or over-broad grants fail closed.

Do not contact a real target. Use synthetic addresses and fake Broker/Runtime responses for tests.

### F. Evidence ingestion, SQLite, CAS, and privacy

Implement:
- complete multi-frame zstd decoding (not a single-frame-only decoder);
- event normalization and `tool/call` ↔ `tool/result` correlation by `callId`;
- preservation of `seq`, job state, approvals, command events, timestamps, process exit status, stdout/stderr, and explicit gaps;
- idempotent ingestion;
- SQLite as the single authoritative state/event store with an append-only per-record hash chain;
- SHA-256 CAS for raw Harness logs and artifact bytes;
- deterministic `events.jsonl` export derived from committed SQLite records. Do not independently dual-write SQLite and JSONL as two authorities;
- manifest generation and independent verification;
- tamper, truncation, missing-frame, sequence-gap, unmatched-call/result, and crash-recovery tests.

Hash chain claims must be precise: tamper-evident relative to a protected chain head, not a digital signature.

**Session-log privacy is a P0 release gate.**
- Read the complete audit and identify the exact supported disable/exclusion mechanism for `dsh-session-log-deepseek`.
- Do not change Harness global config/profile/plugin settings.
- If a supported project-scoped or isolated test-home mechanism exists, test only in a dedicated temporary DSH_HOME and capture evidence.
- If the only effective mechanism requires a prohibited global change, mark the gate BLOCKED and do not process real challenge data. Do not invent a workaround or silently edit configuration.
- Round 1 must not issue `session/prompt` or make a model call.

### G. Explicit screenshots, Writeup, and evidence ZIP

Implement explicit screenshot capture and attribution:
- capture is initiated by an explicit operation, not continuous or silent desktop recording;
- bind each screenshot to Task/Worker/Step/ACP session/scope/time;
- store original bytes in CAS with SHA-256;
- reject or mark blank/failed captures; never fabricate a screenshot;
- CLI/headless output remains primary evidence; GUI is auxiliary.

Generate chronological Markdown Writeups from evidence records. Minimum structure:
1. challenge metadata and supplied materials;
2. challenge description and scope;
3. tool/environment versions actually observed;
4. chronological steps, each with hypothesis/reason, actual action/argv/cwd, actual output/error/exit code, screenshot reference where a program-running step requires it, and conclusion;
5. failed attempts and meaningful negative results;
6. candidate Flag and its exact verification status (candidate/user-confirmed/platform-verified must not be conflated);
7. unresolved or blocked steps;
8. evidence index and hashes.

Important program-running steps must include the corresponding real screenshot where capture is applicable. If a screenshot cannot be captured, record the failure and reason. Never substitute an illustrative or generated image.

Produce an evidence ZIP containing selected original outputs, screenshots, intermediate artifacts, and `manifest.sha256`. PDF conversion is out of scope.

### H. First-run preflight

Implement a read-only preflight/doctor that:
- checks OS/runtime facts and existing tool presence/version;
- checks required Python modules without installing them;
- reports available/missing/unknown tools by category;
- checks project-local Skill discovery prerequisites;
- checks session-log privacy gate status;
- distinguishes “not installed” from “not verified”;
- does not launch WSL/Docker or change any environment setting;
- produces a machine-readable and human-readable report.

Do not attempt to install missing Ghidra, JDK, GDB, pwntools, SageMath, Wireshark/tshark, radare2/rizin, or other tools.

### I. Main-conversation integration feasibility gate

The Core Skill must be able to reach Manager control tools without modifying Harness global config.

Investigate and implement only a supported project-scoped path. Verify:
- project-level Skill discovery;
- how the current main conversation can access Manager control tools;
- how each Worker session receives its own scoped `ctf-exec` MCP server via the audited `session/new.mcpServers` mechanism;
- whether project-scoped MCP/Host Plugin integration is supported without global config changes.

If the Core Skill can be discovered but cannot invoke Manager tools without a prohibited global registration, do not pretend `/ctf-solver` is fully functional. Mark the entrypoint integration BLOCKED, document the exact platform limitation and smallest options requiring owner decision. Do not silently make Cordis mandatory or change the product architecture.

## 4. Round 1 tests and evidence

Use fake ACP/MCP servers and synthetic fixtures for deterministic tests.

Required coverage:
- ACP transport framing, request correlation, event interleaving, malformed messages, EOF, timeout, process exit, and graceful shutdown;
- distinct Task/session/workspace mapping;
- two active Workers + third FIFO queued; FIFO promotion after slot release;
- failure isolation;
- restart reload without duplicate sessions;
- MCP schemas and Broker allow/deny cases;
- Task-scoped approvals and target grants, including cross-Task denial;
- zstd multi-frame parsing, call/result correlation, sequence gaps, idempotency;
- SQLite hash-chain tamper detection and CAS integrity;
- screenshot metadata/blank-capture failure handling;
- Writeup and ZIP reproducibility;
- all six Skills discovered and UTF-8 without BOM;
- preflight performs no environment mutation.

A zero-model-call real ACP smoke test is allowed only with the already-audited installation and an isolated temporary DSH_HOME:
- initialize;
- create independent sessions with distinct temporary workspaces;
- verify returned IDs and Manager mapping;
- inspect active-session listing behavior;
- close one session and verify other sessions remain;
- verify stdin EOF/shutdown.
Do not send `session/prompt`, call a real Worker model, or access a CTF target.

## 5. Round 1 deliverables

- working source for all in-scope modules;
- six project-local Skill files;
- Manager control and Worker execution MCP interfaces;
- test fixtures/fake servers;
- project metadata and no-install preflight;
- README and local operation instructions;
- architecture notes for unresolved Harness integration facts;
- complete test commands, raw outputs, exit codes, and environment snapshot;
- file/change manifest and Git commit SHA;
- acceptance report using PASS / FAIL / BLOCKED / NOT VERIFIED;
- explicit list of functions that are implemented but not yet integrated with a real model call.

Do not report “MVP complete” at the end of Round 1. The required output is a complete first-round implementation candidate ready for Round 2 integration.

## 6. Round 1 stop conditions

Stop and report if:
- a required ACP method/field is not supported by the full audit or installed protocol;
- a required dependency is missing;
- the Core Skill cannot reach Manager tools without global config changes;
- session-log privacy can only be addressed by a prohibited global change;
- any test would need software installation, WSL/Docker deployment, a model call, untrusted-code execution, or real target access;
- the implementation would require changing an accepted product decision.

Do not broaden scope to solve a blocker. Report the smallest decision needed from the owner.
