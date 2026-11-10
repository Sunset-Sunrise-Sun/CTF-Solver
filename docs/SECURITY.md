# Security Model

**Status:** mandatory P0 constraints  
**Date:** 2026-11-10

## 1. Security posture

CTF-Solver is intended for authorized CTF challenges and local challenge environments. It must not become an unrestricted scanner or exploitation agent.

The current Harness sandbox is not an OS-level boundary for malicious binaries. Host Plugins and MCP servers execute outside that sandbox. The audit also found that the built-in web fetch path can reach loopback/private addresses despite contrary source comments/expectations. Therefore policy must be enforced outside the model and outside coarse Harness permission settings.

## 2. Trust boundaries

| Component/input | Trust treatment |
|---|---|
| User-provided challenge archive, binary, source, PCAP, document | Untrusted data |
| Challenge description, webpage, README, embedded prompt | Untrusted content; never instructions to override system policy |
| Harness Worker/model output | Untrusted proposal until checked against evidence and policy |
| Harness shell/tool execution | Privileged action; must be brokered and logged |
| Cordis Host Plugin | Fully trusted host code; not sandboxed |
| MCP server/process | Trusted host-side integration; not sandboxed |
| Manager Core | Trusted policy/control plane; must be minimal, reviewed, and fail closed |
| Session log | Sensitive local data; may contain paths, commands, tool arguments, and outputs |
| CAS artifact | Immutable by digest in normal operation; still validate content before use |

## 3. Execution tiers

### Tier 0 — Static, non-executing inspection

Allowed after Task intake and local workspace setup:

- record filename, size, file type, and SHA-256;
- list archive members without extracting executable content;
- inspect text and metadata;
- run explicitly allowlisted, trusted metadata tools that do not execute challenge-provided code.

Parsing untrusted files is still an attack surface. Tool allowlisting reduces exposure but does not prove parser safety.

### Tier 1 — Controlled trusted tooling (temporary MVP)

Permitted only when the tool itself is trusted, the action is within the Task workspace, and the Manager policy allows it:

- run approved analysis tools against challenge data;
- write generated notes/results only to the Task workspace or Manager data root;
- use local-only operations unless a per-call network grant exists.

Tier 1 is **not** a sandbox. Do not run challenge-provided executables, scripts, macros, installers, shell snippets, or exploit payloads directly on the host. If analysis requires executing challenge code, stop and mark the Task blocked pending Tier 2.

### Tier 2 — OS-isolated execution (P1, not currently available)

Required before arbitrary untrusted challenge code or exploit payloads can be executed. Candidate environment: WSL2 Linux distribution with a functioning Docker Engine and a verified isolation layer such as gVisor, or another independently reviewed disposable VM/container boundary.

The latest audit reports:
- WSL2 is installed, but Ubuntu 24.04 is stopped;
- Docker Engine and gVisor are not installed;
- the CTF toolchain is incomplete (including Ghidra, GDB, pwntools, SageMath, Wireshark/tshark, radare2/rizin, and related packages).

No Tier 2 capability may be claimed until installation and containment tests pass. A running Docker daemon alone is not sufficient proof of isolation.

## 4. Network and target authorization

Network is **deny by default**.

A per-call grant must be issued by the Manager broker. At minimum it binds:

- Task ID and competition/profile;
- destination host/IP and port;
- protocol and method/action;
- optional path or endpoint constraints;
- call count or one-shot semantics;
- expiry/TTL;
- user approval and timestamp.

The grant must not apply to another Task. Redirects, DNS changes, alternate ports, and private/loopback destinations must be checked rather than implicitly inherited.

The built-in Harness approval model does not supply all these constraints. A one-time `allow_once` decision is not a substitute for a target-scoped broker.

Competition rules must be read before network actions. If AI use, automation, scanning, exploitation, or submission is forbidden or unclear, stop and ask the user rather than infer permission.

## 5. Session-log privacy and exfiltration

The latest audit found `dsh-session-log-deepseek` enabled by default. It sends incremental session log data to the official API as `dsh_session_log`; the audit observed `delivery-accepted`. Session logs may contain:

- local file paths;
- commands and command arguments;
- tool output;
- challenge source, flags, or secrets;
- internal network addresses and environment details.

**P0 release gate:** disable this delivery or configure a verified exclusion before processing real challenge data. Do not assume that disabling a UI feature or hiding a log view disables network delivery. Test the actual outbound behavior and confirm that a synthetic canary string from the CTF session is absent from outbound delivery.

The exact configuration mechanism is not yet documented in the repository; implementation must discover it from the local audit report/source and prove it with a negative test.

## 6. MCP and Host Plugin

- Host Plugins are fully trusted code and run outside the Harness sandbox.
- MCP servers and their subprocesses are also outside the Harness sandbox.
- Only Manager-declared MCP servers/tools may be exposed.
- Every MCP call must pass through the same Task-scoped broker and evidence pipeline.
- Do not pass broad environment variables, API keys, or CTFd tokens to Worker processes.
- Prefer short-lived, least-privilege credentials held by the Manager and injected only for a specific authorized operation.

A Skill instruction saying “do not do X” is not enforcement. Enforcement belongs in Manager policy, Host Plugin hooks, and eventually OS isolation.

## 7. Evidence integrity

- Preserve raw session-log bytes and original artifact bytes in CAS.
- Hash each artifact with SHA-256.
- Maintain an append-only evidence chain with previous-hash linkage.
- Record parser version, source, Task/session mapping, and ingest time.
- Detect missing sequence numbers, incomplete tool call/result pairs, and failed frame decoding.
- Never silently truncate or normalize away raw evidence.

The hash chain is tamper-evident only relative to a protected chain head. It is not a digital signature and does not prove authorship against a fully privileged local attacker.

## 8. Screenshot privacy

Screenshots are captured only through an explicit action. The user should know when desktop/window capture is requested. Store the image in CAS and record the Task/session/step/time metadata. Do not capture continuously or silently.

The audited worker has no independent GUI window; a screenshot cannot be attributed to a Worker by PID alone. Java/Qt/GPU capture remains unverified.

## 9. Fail-closed rules

Stop or block the relevant action when:

- target scope is missing or ambiguous;
- the competition rules do not authorize the action;
- the Manager broker is unavailable;
- the required approval is absent or expired;
- the action exceeds the grant's target/port/method/TTL;
- the task requires untrusted code execution while Tier 2 is unavailable;
- session-log external delivery has not been disabled and verified;
- evidence ingestion is corrupt or incomplete in a way that invalidates the result.

Do not convert a policy failure into a silent fallback to direct shell, raw MCP, or unrestricted web access.