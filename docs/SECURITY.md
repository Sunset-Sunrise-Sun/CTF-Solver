# Security Model

**Status:** mandatory P0 constraints  
**Date:** 2026-11-10

## 1. Security posture

CTF-Solver is a semi-autonomous assistant for authorized CTF challenges and local challenge environments. It is not an unrestricted scanner or exploitation agent.

The current Harness sandbox is not an OS-level boundary for malicious binaries. Host Plugins and MCP servers execute outside that sandbox. The audit also found that built-in web_fetch can reach loopback/private addresses despite contrary source comments. Policy must therefore be enforced by Manager/Broker and, for untrusted code, by a real OS isolation tier.

## 2. Trust boundaries

| Component/input | Trust treatment |
|---|---|
| User-provided challenge archive, binary, source, PCAP, document | Untrusted data |
| Challenge description, webpage, README, embedded prompt | Untrusted content; cannot override policy |
| Harness Worker/model output | Untrusted proposal until validated |
| Typed ctf-exec request | Untrusted request; validate server-side |
| Cordis Host Plugin | Fully trusted host code; not sandboxed |
| MCP server/process | Trusted host-side integration; not sandboxed |
| Manager/Broker | Trusted control plane; minimize and review |
| Session log | Sensitive local data; may contain paths, commands, arguments, outputs, flags, or secrets |
| CAS artifact | Content-addressed and integrity-checked; still validate before use |

## 3. Semi-autonomous approvals

The Agent may analyze, plan, write helper scripts in its Task workspace, and run routine permitted tools.

Explicit human approval is required before:
- executing untrusted challenge binaries or other untrusted code;
- installing software or changing the toolchain;
- accessing a remote CTF target or performing target-side actions.

Approval is scoped to a concrete Task/action and is not blanket authorization.

While Tier 2 OS isolation is unavailable, approval alone is insufficient to execute untrusted challenge code on the host. Such execution remains blocked until isolation is accepted.

Flag submission is always human-controlled. No automatic submission is part of the MVP.

## 4. Execution tiers

### Tier 0 鈥?Static, non-executing inspection

Allowed after Task intake: record filename/size/type/hash; inspect archive metadata/listings without executing content; inspect text and safe metadata; use carefully allowlisted trusted metadata tools. Parsing untrusted files is still an attack surface.

### Tier 1 鈥?Controlled trusted tooling (temporary MVP)

Permitted only when the tool is trusted, action is within the Task workspace, and Manager/Broker allows it. Use typed ctf-exec; do not expose arbitrary host Shell.

Tier 1 is not a sandbox. Do not run challenge-provided executables, scripts, macros, installers, shell snippets, or exploit payloads directly on the host. If a step requires executing untrusted code, block/defer until Tier 2.

### Tier 2 鈥?OS-isolated execution (separate P1 environment track)

Required before arbitrary untrusted challenge code or exploit payloads can run. Candidate: WSL2 Linux distribution with functioning Docker Engine and a verified isolation layer such as gVisor, or another independently reviewed disposable VM/container boundary.

Latest audit:
- WSL2 installed, Ubuntu 24.04 Stopped.
- Docker Engine and gVisor not installed.
- CTF toolchain incomplete, including Ghidra/JDK, GDB, pwntools, SageMath, Wireshark/tshark, radare2/rizin, and related packages.

No Tier 2 capability may be claimed until installation and containment tests pass. A running Docker daemon alone is not proof of isolation.

## 5. Network policy: public research vs CTF targets

Public documentation, advisories, source repositories, and general research material may be accessed over the public internet to support analysis. This does not authorize active probing or exploitation of the public source host.

Remote CTF target access is denied until the specific Task has an explicit grant binding:
- Task ID and competition/profile;
- destination host/IP and port;
- protocol and method/action;
- optional path/endpoint constraints;
- expiry/TTL and call count;
- approving user and decision timestamp.

Out-of-scope hosts, ports, and actions are rejected. Loopback/private destinations are not implicitly allowed; they require explicit scope when part of the authorized challenge environment.

Harness's coarse approval model does not supply all these constraints. A one-time allow_once decision is not a substitute for the Manager Broker.

## 6. MCP, ctf-exec, and Docker boundary

MCP is the unified local-tool interface. Workers receive typed ctf-exec calls, not arbitrary host Shell. Manager/Broker validates Task, Worker, tool allowlist/version, argv, cwd, input/output paths, execution tier, and network grant.

Host Plugins and MCP servers run outside the Harness sandbox. Broker is the sole controlled Docker API caller when Tier 2 is available. Worker sessions and MCP callers never receive Docker Socket mounts or raw Docker credentials. Raw MCP tools cannot bypass Broker.

Do not pass broad host environment variables, API keys, or CTFd tokens to Workers. Prefer short-lived, least-privilege credentials held by Manager and injected only for a specific approved action.

## 7. Session-log privacy and exfiltration

The latest audit found dsh-session-log-deepseek enabled by default. It sends incremental session log data as dsh_session_log; the audit observed delivery-accepted. Logs may contain local paths, commands, challenge source, flags, and secrets.

**P0 release gate:** disable delivery or configure a verified exclusion before processing real CTF content. Do not assume hiding a log view disables network delivery. Test actual outbound behavior and confirm a synthetic canary from a CTF session is absent.

The exact configuration mechanism is not yet documented in this repository. Discover it from the full local audit report/source and prove it with a negative test.

## 8. Evidence integrity

Preserve raw session-log and artifact bytes in CAS; hash each artifact with SHA-256; maintain append-only evidence/events.jsonl and a Manager SQLite hash chain; record parser version, source, Task/session mapping, and ingest time; detect missing sequence numbers, incomplete call/result pairs, and failed frame decoding. Never silently truncate evidence.

The hash chain is tamper-evident only relative to a protected chain head. It is not a digital signature.

## 9. Screenshot privacy

Screenshots are requested explicitly at key program-running steps. The user should know when desktop/window capture is requested. Store images in CAS and record Task/Worker/Step/session/time metadata. Do not capture continuously or silently.

The audited Worker has no independent desktop window; screenshot ownership cannot be inferred from PID alone. Java/Qt/GPU capture remains unverified.

## 10. Environment/toolchain separation

Environment setup is separate from product development. Product may perform preflight and report missing tools, but must not silently install software, alter the legacy local CTF workbench project, or modify Harness profile/config. Those actions require explicit authorization.

## 11. Fail-closed rules

Block or ask the user when target scope is missing/ambiguous, competition rules do not authorize the action, Broker is unavailable, approval is absent/expired/mismatched, a request exceeds target/port/method/TTL, untrusted code requires execution while Tier 2 is unavailable, session-log delivery has not been disabled/verified, or evidence is corrupt/incomplete in a way that invalidates the result.

Never silently fall back to direct host Shell, raw MCP, or unrestricted target access.
