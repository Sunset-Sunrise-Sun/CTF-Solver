# Superseded: Phase 1 Implementation Task

**Status:** Superseded by the owner-approved two-round development plan. Do not execute this file as a standalone implementation task.

The earlier single-slice ACP Client task has been incorporated into the broader two-round plan. It is retained only as historical context so that existing links do not break.

Use these canonical tasks instead:

1. [Round 1 — Complete Product Core](ROUND_1_IMPLEMENTATION_TASK.md)
2. [Round 2 — Harness Integration and End-to-End Closure](ROUND_2_INTEGRATION_TASK.md)
3. [Two-Round Development Execution Plan](TWO_ROUND_EXECUTION_PLAN.md)

The accepted ACP requirements remain in force: Manager implements the ACP Client over stdio ND-JSON / JSON-RPC 2.0; one Task receives one independent ACP session/workspace; Manager owns the active-session registry; at most two Workers run with FIFO queueing; ACP cancel is not an OS process kill; no model prompt is allowed without separate authorization.

The owner-approved environment boundary applies to both rounds: no software installation, no Harness global configuration changes, and no WSL/Docker deployment or startup. Do not modify the old `D:\CTF` project or the protected 110 imported files and local audit report in `D:\CTFworker`.

This archival file does not override PRODUCT_SPEC.md, ARCHITECTURE.md, DECISIONS.md, SECURITY.md, EXECUTION_CONTRACT.md, ACCEPTANCE.md, or the two canonical round task files.
