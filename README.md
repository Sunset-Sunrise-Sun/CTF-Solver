# CTF-Solver

**A semi-autonomous CTF solving extension for DeepSeek Harness.** Start it once with /ctf-solver; keep solving in the same conversation without repeating the command.

CTF-Solver preserves Harness as the reasoning/runtime layer. It adds a Core Skill and five specialist Skills, a Manager with an ACP Client, independent per-challenge Workers, a typed ctf-exec runtime interface, scoped approvals, durable evidence, and reproducible writeups. It is not a standalone CTF platform and does not introduce a second model loop.

> **Status (2026-11-10, Round 2):** integration candidate on
> `feat/round2-harness-integration`. Round 1 review defects are fixed: the previously
> ignored `ctf_solver/evidence/` source is restored and tracked; approval decisions and
> network grants now require a real local-console human confirmation (the model can only
> request); session-log ingestion is registry-derived (no model-supplied paths); MCP
> argument schemas are enforced; ACP launch uses the audited `dsh --profile acp`;
> challenge files are imported only from the project intake root; and a stdlib PEP 517
> wheel build/fresh-clone check exists. Real zero-model-call Harness integration passes
> 30/30 checks (2 Workers + FIFO, per-session Worker MCP mount, real session-log
> ingestion, real project-owned window screenshot, Writeup/evidence ZIP, restart
> recovery, synthetic end-to-end challenge). The main-conversation `/ctf-solver` →
> Manager tool entrypoint and the session-log negative-delivery canary remain
> BLOCKED/NOT VERIFIED (see [Round 2 integration notes](docs/ROUND_2_HARNESS_INTEGRATION_NOTES.md)).
> This remains an integration candidate and does **not** claim final MVP acceptance.

## Product contract

- One explicit entry: /ctf-solver enters CTF mode for the current conversation.
- Persistent mode: subsequent messages, attachments, and “continue” requests remain in CTF mode. Do not require the command again for each challenge.
- Semi-autonomous: the Agent analyzes, plans, writes helper scripts, and runs permitted routine tools; sensitive actions require human approval.
- Independent challenge Workers: each challenge receives its own Task, workspace, and Harness ACP session.
- Bounded concurrency: at most **2 active Workers**; additional Tasks wait FIFO.
- Five categories only: Web, Misc, Crypto, Reverse, and Pwn. First Blood scanning is a separate future project and excluded from this MVP.
- CLI/headless first; GUI is auxiliary and used primarily for required program-running screenshots.
- No arbitrary host Shell: Workers use typed ctf-exec through MCP; they receive neither unrestricted host Shell nor Docker Socket.
- Evidence-first delivery: record actual argv, cwd, tool version, timestamps, exit code, stdout/stderr, files, and screenshots.
- Human controls: approve untrusted-binary execution, software installation, and CTF target access; the user confirms and submits the Flag.

## Architecture at a glance

User → /ctf-solver Core Skill → CTF Manager → Manager ACP Client → dsh --profile acp (ACP Server) → one Worker session per Task.

Worker → typed ctf-exec MCP tool → Manager/Broker → Runtime → approved CLI/headless tool.

Manager stores authoritative state/events in SQLite, raw bytes in CAS, and produces a Markdown Writeup plus evidence ZIP. Five specialist Skills cover Web, Misc, Crypto, Reverse, and Pwn. Cordis Host Plugin provides lightweight optional hooks; it is not a second runtime.

See [Product Spec](docs/PRODUCT_SPEC.md), [Architecture](docs/ARCHITECTURE.md), and [Execution Contract](docs/EXECUTION_CONTRACT.md). The owner-approved implementation cadence is exactly two rounds: [Two-Round Execution Plan](docs/TWO_ROUND_EXECUTION_PLAN.md), [Round 1 — Complete Product Core](docs/ROUND_1_IMPLEMENTATION_TASK.md), and [Round 2 — Harness Integration](docs/ROUND_2_INTEGRATION_TASK.md).

## Safety and execution boundary

Public research material and documentation lookup may use the public internet. Competition targets are different: remote target access requires authorization for the specific Task and target; out-of-scope hosts, ports, and actions are blocked.

The current Harness sandbox is not an OS security boundary for untrusted binaries. WSL2 is present but Ubuntu 24.04 is stopped; Docker Engine/gVisor are not installed. Until an isolated execution tier is installed and accepted:
- use static inspection and approved trusted tools that do not execute challenge-provided code;
- do not run challenge binaries, scripts, macros, exploit payloads, or untrusted installers directly on the host;
- human approval is required for sensitive actions, but approval alone does not replace OS isolation;
- Workers use typed ctf-exec; no arbitrary host Shell and no Docker Socket are exposed;
- Broker is the sole controlled Docker API caller when Tier 2 is available.

Session-log delivery to the official API must be disabled/excluded and verified before real challenge content is processed. See [Security Model](docs/SECURITY.md).

## Repository map

- docs/PRODUCT_SPEC.md — user-facing behavior and requirements.
- docs/ARCHITECTURE.md — Manager, ACP, MCP, Runtime, evidence, and Cordis boundaries.
- docs/EXECUTION_CONTRACT.md — typed ctf-exec interface; no arbitrary Shell.
- docs/DECISIONS.md — accepted decisions and unresolved implementation details.
- docs/SECURITY.md — trust boundaries, approvals, network scope, and execution tiers.
- docs/ROADMAP.md — exactly two implementation rounds and separate environment boundary.
- docs/TWO_ROUND_EXECUTION_PLAN.md — canonical execution index.
- docs/ROUND_1_IMPLEMENTATION_TASK.md — complete first-round product implementation.
- docs/ROUND_2_INTEGRATION_TASK.md — second-round Harness integration and end-to-end closure.
- docs/INTERFACES.md — frozen Round 1 module contracts (implementation boundary record).
- docs/ROUND_1_ARCHITECTURE_NOTES.md — what Round 1 proves and the remaining Harness integration limits.
- docs/ROUND_1_ACCEPTANCE_REPORT.md — Round 1 PASS/FAIL/BLOCKED/NOT VERIFIED acceptance report.
- docs/ROUND_2_SECURITY_CHANGES.md — Round 2 approval/grant/session-ingest/MCP security remediation.
- docs/ROUND_2_HARNESS_INTEGRATION_NOTES.md — real Harness integration evidence and remaining limits.
- docs/ROUND_2_ACCEPTANCE_REPORT.md — Round 2 PASS/FAIL/BLOCKED/NOT VERIFIED acceptance report.
- docs/ROUND_2_INTERFACES.md — Round 2 module/security interface contracts.
- docs/LOCAL_OPERATION.md — no-install local operation, preflight, testing and data layout.
- docs/REFERENCE_PROJECTS.md — external projects and what to learn from them.
- docs/HARNESS_INTEGRATION_AUDIT_SUMMARY.md — summary of the latest local capability audit.
- docs/ACCEPTANCE.md — objective implementation/release gates.

## Current implementation status (Round 2 integration candidate)

| Area | Status |
|---|---|
| Round 1 evidence source recovery (.gitignore root-anchoring) | Fixed; `ctf_solver/evidence/` tracked and importable |
| Human-confirmed approvals / grants (no MCP decision/create) | Implemented; negative tests; real physical TTY NOT VERIFIED |
| Session-log ingestion (Manager registry only, no caller path) | Implemented; real Harness log ingestion verified |
| MCP argument schema enforcement | Implemented; 154 integrity tests + protocol/exec negative tests |
| ACP permission event session→Task mapping | Fixed; unknown sessions become diagnostics |
| ACP launch `dsh --profile acp` | Fixed; real zero-model-call launch verified |
| Challenge-file controlled intake + hashes + Task isolation | Implemented; Writeup lists real materials |
| Wheel build (stdlib PEP 517 backend, no installs) + fresh-clone check | Implemented; final wheel/fresh-clone evidence in acceptance report |
| Real Harness integration (2 Workers + FIFO, per-session Worker MCP mount, restart recovery) | 30/30 checks PASS (zero model calls) |
| Real project-owned window screenshot, Writeup, evidence ZIP | PASS (synthetic end-to-end run committed under `round2-evidence/end-to-end/`) |
| Main-conversation `/ctf-solver` → Manager tools | **BLOCKED** (no supported project-scoped MCP registration; owner decision needed) |
| Session-log negative delivery canary | **BLOCKED** (requires a model request; mechanism verified in isolated profile only) |
| Model-mediated Worker / `session/prompt` | **BLOCKED by design** (ADR-020) |
| OS-isolated execution tier | Not available; separate future environment track |

## Development rules

0. CTF-Solver is a clean-room independent implementation. Do not reuse code, databases/migrations, APIs, UI, services, or runtime components from the old CTF Workbench / D:/CTF / D:/CTFworker. Reference repositories are for technical ideas; copying source requires license/provenance review and owner approval.

1. Do not change the product contract or decisions silently. Update docs/DECISIONS.md first.
2. Do not expose arbitrary host Shell or Docker Socket to a Worker.
3. Do not automatically submit a Flag; the user verifies and submits it.
4. Keep challenge files, logs, credentials, screenshots, databases, and CAS data out of Git.
5. Follow the owner-approved two-round plan. Do not install software, modify Harness global configuration, or deploy/start WSL/Docker. Do not touch the existing D:/CTF project or protected D:/CTFworker imported files.
6. Do not copy third-party source code without checking its license and recording provenance.
7. Never report a flag, exploit, screenshot, test, or completion state that was not actually verified.

## License

No project license has been selected yet. Do not assume this repository grants reuse rights until a license is added.