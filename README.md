# CTF-Solver

**A DeepSeek Harness-native CTF solving extension.** Start it once with `/ctf-solver`; keep solving in the same conversation without repeating the command.

CTF-Solver does not replace DeepSeek Harness with another agent runtime. Harness remains responsible for model reasoning and tool execution. CTF-Solver adds the missing control plane around it: challenge/task lifecycle, independent ACP sessions, scoped approvals, durable evidence, screenshots, and reproducible writeups.

> **Project status (2026-11-10):** architecture baseline is being established. Harness ACP lifecycle and several integration primitives have been audited in a real local environment. The Manager, broker, evidence pipeline, and user-facing extension have **not** yet passed end-to-end implementation acceptance.

## Product contract

- **One explicit entry:** `/ctf-solver` enters CTF mode for the current conversation.
- **Persistent conversation mode:** subsequent messages, attachments, and “continue” requests remain in CTF mode. Do not ask the user to repeat the command for each challenge.
- **Independent challenge tasks:** each challenge receives its own task record, workspace, and Harness ACP session.
- **Bounded concurrency:** at most **2 active Workers**; additional tasks wait in FIFO order.
- **Five core categories:** Web, Misc, Crypto, Reverse, and Pwn.
- **Harness-native execution:** use Harness as the reasoning/tool runtime; do not create a second model/agent loop.
- **Evidence-first delivery:** conclusions must be traceable to tool calls, outputs, files, and explicitly captured screenshots. Unknown or unverified claims stay marked as such.
- **Human-controlled scope:** competition rules and target scope are checked before network or state-changing actions.

## Architecture at a glance

```text
User
  │  /ctf-solver
  ▼
Project Skill ──► Thin Cordis Host Plugin / CTF tools
                         │
                         ▼
                    Manager Core
                    ├── Task queue (max 2, FIFO)
                    ├── Policy + approval broker
                    ├── ACP Client
                    │      │
                    │      └── dsh --profile acp (ACP Server)
                    │             └── one session per task
                    ├── Session-log ingestion
                    ├── SQLite hash-chain + CAS evidence
                    ├── Explicit screenshot capture
                    └── Writeup generation
```

See [Product Spec](docs/PRODUCT_SPEC.md), [Architecture](docs/ARCHITECTURE.md), and [Decisions](docs/DECISIONS.md).

## Non-negotiable safety boundary

The current Harness sandbox is **not** an OS security boundary for untrusted binaries. WSL2 is present but the Ubuntu distribution is stopped; Docker Engine/gVisor are not installed. Until an isolated execution tier is installed and accepted:

- static inspection and explicitly allowlisted, trusted tooling may proceed under the Manager policy;
- challenge-provided executables, scripts, macros, or exploit payloads must not be run directly on the host;
- network access is denied by default and must be granted per task/action/target through the external broker;
- MCP and Cordis Host Plugin code are treated as trusted host-side components, not sandboxed Workers.

Session-log delivery to the official API must be disabled/excluded and verified before any real CTF challenge content is processed. Details: [Security Model](docs/SECURITY.md).

## Repository map

- `docs/PRODUCT_SPEC.md` — user-facing behavior and product requirements.
- `docs/ARCHITECTURE.md` — component boundaries and data flows.
- `docs/DECISIONS.md` — accepted architecture decisions and unresolved implementation details.
- `docs/SECURITY.md` — trust boundaries, execution tiers, approvals, and data handling.
- `docs/ROADMAP.md` — phased implementation plan.
- `docs/REFERENCE_PROJECTS.md` — external projects and the specific ideas worth learning from.
- `docs/HARNESS_INTEGRATION_AUDIT_SUMMARY.md` — summary of the latest local capability audit.
- `docs/ACCEPTANCE.md` — implementation and release gates.

## Current implementation status

| Area | Status |
|---|---|
| Harness ACP Server lifecycle | Audited; 22/22 lifecycle checks passed in the local audit |
| Independent ACP sessions/workspaces | Minimal demo verified; Manager integration not yet implemented |
| Cordis Host Plugin hooks/tools | Capability audited; production plugin not yet implemented |
| Manager ACP Client | Not implemented |
| Task queue and 2-Worker limit | Product decision; not implemented |
| External per-call policy broker | Required; not implemented |
| Session-log external delivery disabled | P0 requirement; configuration and negative test pending |
| SQLite hash chain + CAS | Required; not implemented |
| Multi-frame zstd ingestion | Parsing feasibility verified; production ingestion not implemented |
| Screenshot capture and attribution | Capture primitives verified; Manager integration not implemented |
| Writeup generation | Demo mechanism verified; production output/acceptance pending |
| OS-isolated execution tier | Not available; P1 environment work |

## Development rules

1. Do not change the product contract or architecture decisions silently. Update [Decisions](docs/DECISIONS.md) first.
2. Do not copy third-party source code without checking its license and recording provenance.
3. Keep challenge artifacts, logs, credentials, screenshots, databases, and CAS data out of Git.
4. Use local synthetic fixtures for integration tests; do not contact public targets in tests.
5. Never report a flag, exploit, screenshot, test, or completion state that was not actually verified.
6. Treat the latest audit report as evidence, not as proof of untested behavior. See the explicit NOT VERIFIED list.

## License

No project license has been selected yet. Do not assume this repository grants reuse rights until a license is added.
