# CTF-Solver

**A semi-autonomous CTF solving extension for DeepSeek Harness.** Start it once with /ctf-solver; keep solving in the same conversation without repeating the command.

CTF-Solver preserves Harness as the reasoning/runtime layer. It adds a Core Skill and five specialist Skills, a Manager with an ACP Client, independent per-challenge Workers, a typed ctf-exec runtime interface, scoped approvals, durable evidence, and reproducible writeups. It is not a standalone CTF platform and does not introduce a second model loop.

> **Status (2026-11-10):** Round 1 implementation candidate on branch
> `feat/round1-complete-product-core` (based on the frozen documentation commit
> `960252a`). The complete product core (Manager/ACP Client, FIFO scheduler, Manager and
> Worker MCP interfaces, typed `ctf-exec`, Broker/Runtime, six Skills, preflight,
> multi-frame zstd evidence pipeline with SQLite hash chain + CAS, screenshots,
> Writeup/ZIP) is implemented with deterministic tests and a zero-model-call real ACP
> lifecycle smoke test. Round 1 does **not** claim final MVP acceptance: the
> main-conversation `/ctf-solver` → Manager tool path and the session-log negative
> delivery test remain BLOCKED/NOT VERIFIED for Round 2 (see
> [Round 1 architecture notes](docs/ROUND_1_ARCHITECTURE_NOTES.md)).

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
- docs/LOCAL_OPERATION.md — no-install local operation, preflight, testing and data layout.
- docs/REFERENCE_PROJECTS.md — external projects and what to learn from them.
- docs/HARNESS_INTEGRATION_AUDIT_SUMMARY.md — summary of the latest local capability audit.
- docs/ACCEPTANCE.md — objective implementation/release gates.

## Current implementation status (Round 1 candidate)

| Area | Status |
|---|---|
| Manager control MCP server + loopback IPC | Implemented; deterministic tests + end-to-end fake-ACP stack test |
| ACP Client (stdio ND-JSON JSON-RPC 2.0) | Implemented; fake-server matrix + zero-model-call real ACP smoke test PASS |
| Task/Worker registry, one session/workspace per Task | Implemented; SQLite persisted before ready; recovery without duplicate sessions |
| Two-Worker FIFO scheduler | Implemented; 2 active + 3rd queued + promotion + failure isolation tested |
| Worker MCP `ctf-exec` (typed argv, env identity) | Implemented; stdio MCP tests + Manager IPC chain tested |
| Broker approvals/network grants, fail-closed | Implemented with deny/allow matrix, redirect/DNS revalidation logic |
| Runtime trusted tools | Tier 0 internal + Tier 1 fixed-argv probes; no challenge-code execution |
| Core Skill + five specialist Skills | Implemented under `.dsh/skills/`; UTF-8 no BOM; observed discovered by the local Harness |
| Read-only preflight/doctor | Implemented; no environment mutation tested |
| Multi-frame zstd + SQLite hash chain + CAS + derived JSONL | Implemented; tamper/gap/idempotency/determinism tests |
| Explicit screenshots | Capturer implemented + blank/failure handling tested; desktop capture NOT VERIFIED in Round 1 |
| Markdown Writeup + evidence ZIP + manifest | Implemented; deterministic + independently verified |
| Main-conversation `/ctf-solver` → Manager tools | **BLOCKED** for Round 2 (no supported project-scoped MCP registration) |
| Session-log negative delivery canary | **BLOCKED** (requires a model call; mechanism verified in isolated profile) |
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