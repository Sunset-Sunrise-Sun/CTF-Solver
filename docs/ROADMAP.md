# Roadmap — Exactly Two Development Rounds

**Baseline date:** 2026-11-10  
**Status:** Two-round execution plan approved by the project owner.  
**Rule:** implement the approved Harness-native Skill + Manager + typed Runtime architecture. Do not change the product contract silently.

This roadmap supersedes the former Phase 1–7 implementation sequence. The product scope is unchanged; only the development cadence is consolidated into two concentrated rounds.

## Frozen product contract

- DeepSeek Harness remains the reasoning/runtime layer; no second model loop or standalone CTF platform.
- Explicit `/ctf-solver` entry; CTF mode persists for the current conversation.
- Core Skill plus five category Skills: Web, Misc, Crypto, Reverse, Pwn.
- One challenge = one Task = one independent ACP session and workspace.
- Maximum two active Workers; additional Tasks wait FIFO.
- Manager-owned ACP Client, Task registry, control surface, Broker, evidence, and delivery.
- Worker execution through typed MCP `ctf-exec`; no arbitrary host Shell or raw Docker Socket.
- Semi-autonomous operation, Task-scoped approvals/target grants, and human Flag confirmation/submission.
- SQLite authoritative state/events + CAS raw bytes + derived JSONL export + hash manifest.
- Explicit program-running screenshots, chronological Markdown Writeup, and evidence ZIP. PDF is a later handoff.
- CLI/headless first; Cordis remains optional and thin.
- First Blood scanning, multi-model racing, standalone frontend, and automatic Flag submission remain excluded.

## Round 1 — Complete Product Core

**Canonical task:** [ROUND_1_IMPLEMENTATION_TASK.md](ROUND_1_IMPLEMENTATION_TASK.md)

Implement the complete first-version product structure in one concentrated round:

- [ ] Repository layout, project metadata, no-install preflight, and runtime-data exclusions.
- [ ] Core Skill `ctf-solver` and five category Skills, UTF-8 without BOM.
- [ ] Intake supporting title/category, text or screenshot description, ZIP/files, container context, and optional target address/port.
- [ ] Manager ACP Client over stdio ND-JSON / JSON-RPC 2.0.
- [ ] One ACP session/workspace per Task; persistent Task/Worker/session mapping.
- [ ] Maximum two active Workers and FIFO queue; restart-safe Task registry.
- [ ] Manager control API/MCP and Worker-facing MCP `ctf-exec`.
- [ ] Runtime/Broker validation, tool allowlist, approvals, and Task-scoped target grants.
- [ ] Multi-frame zstd parser, SQLite hash chain, CAS, idempotent ingestion, and derived JSONL export.
- [ ] Explicit screenshot capture and Task/Worker/Step/session/time attribution.
- [ ] Chronological Markdown Writeup and evidence ZIP with independently verifiable manifest.
- [ ] Fake ACP/MCP servers, synthetic fixtures, and comprehensive deterministic tests.
- [ ] Zero-model-call ACP lifecycle smoke test using only the already-installed audited capability, if safe and available.
- [ ] Read-only first-run preflight and honest reporting of missing tools.

**Round 1 exit gate:** all in-scope modules exist and have deterministic tests; the integrated candidate is ready for real Harness integration. Do not claim final MVP acceptance.

## Round 2 — Harness Integration and End-to-End Closure

**Canonical task:** [ROUND_2_INTEGRATION_TASK.md](ROUND_2_INTEGRATION_TASK.md)

Integrate the Round 1 candidate with the existing Harness installation and fix Round 1 defects:

- [ ] Verify project-level Skill discovery and actual `/ctf-solver` entry semantics.
- [ ] Verify Core Skill → Manager control tools using a supported project-scoped integration; no global Harness configuration changes.
- [ ] Verify real ACP Client lifecycle and independent Task sessions/workspaces.
- [ ] Verify per-session Worker MCP mounting/discovery and typed `ctf-exec`.
- [ ] Verify two active Workers and a third FIFO-queued Task.
- [ ] Verify Broker allow/deny behavior, approval scoping, and target-grant isolation.
- [ ] Verify session-log privacy using a synthetic canary and negative outbound-delivery evidence.
- [ ] Verify actual multi-frame log ingestion, SQLite/CAS integrity, and restart recovery.
- [ ] Verify actual screenshots, Writeup chronology, evidence ZIP, and manifest.
- [ ] Complete a synthetic local end-to-end challenge with no real target access and no untrusted-code execution.
- [ ] Fix defects without weakening tests or redesigning accepted architecture.
- [ ] Produce final PASS / FAIL / BLOCKED / NOT VERIFIED acceptance report.

A model-mediated `session/prompt` test requires separate explicit user authorization after the privacy gate passes. Without authorization, mark that specific test BLOCKED and continue other safe tests.

**Round 2 exit gate:** every acceptance criterion is reported with evidence; no P0 issue is hidden or treated as passed merely because it is blocked.

## Environment boundary — applies to both rounds

The owner explicitly selected the existing-environment-only boundary:

- Do not install, uninstall, upgrade, or configure software/packages.
- Do not modify Harness global profiles, configuration, plugins, MCP registrations, or Skills.
- Do not deploy, install, start, or configure WSL/Ubuntu/Docker/containerd/gVisor.
- Do not modify the old `D:\CTF` project or old CTF Workbench.
- Do not modify, stage, stash, clean, reset, delete, rename, or overwrite the 110 pre-existing uncommitted imported files or local audit report in `D:\CTFworker`.
- Use existing dependencies and trusted local tools only.
- Use synthetic fixtures only; do not access real CTF targets or submit Flags.
- Do not execute challenge-provided binaries, scripts, macros, installers, or exploit payloads on the host.

Project-local source, Skills, tests, and sample configuration files may be created in this repository. Do not apply project configuration to global Harness state. If a required dependency or integration capability is unavailable, mark it BLOCKED and report; do not install or bypass.

## Mandatory P0 gates

Before real CTF content can be processed:
1. Session-log external delivery must be disabled/excluded by a supported, verified mechanism. The audit observed `dsh-session-log-deepseek` delivery acceptance. The current authorization forbids changing global Harness config.
2. The main conversation must be able to reach Manager control tools through a supported project-scoped path. Skill discovery alone is not proof of working command integration.
3. Each Task must map to one ACP session/workspace; two-Worker FIFO must be enforced by Manager.
4. Every Worker operation must pass through typed ctf-exec and Broker.
5. Task-scoped approvals and target grants must fail closed.
6. Evidence must be complete and reproducible, with gaps explicit.
7. Flag confirmation/submission remains human-controlled.

If a gate requires a prohibited global/environment change, report BLOCKED and request a separate owner decision. Never silently bypass it.

## Separate environment/toolchain track — outside the two rounds

Tier 2 isolation is not part of either implementation round. No WSL/Docker deployment is authorized in this plan. Until a separate environment workstream is approved and independently accepted:
- challenge-provided code and exploit payloads remain non-executable on the host;
- Reverse dynamic execution remains blocked;
- Pwn execution steps requiring untrusted code remain blocked;
- missing tools are reported by preflight, not installed.

Future environment acceptance must test filesystem, process, network, credential, resource, cleanup, and cross-Task boundaries. A running Docker daemon alone is not proof of isolation.

## P2 — Future enhancements

- Expand Skills from verified solved-challenge experience.
- Add optional Cordis hooks only where they materially improve integration.
- Add opt-in MCP adapters after Broker enforcement is stable.
- Evaluate additional headless reverse-engineering tools after the environment track.
- Keep First Blood scanning a separate project.
