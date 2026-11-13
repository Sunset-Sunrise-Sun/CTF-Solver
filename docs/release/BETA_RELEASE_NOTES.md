# CTF-Solver Beta 0.1.1 — Release Notes

**Release type:** public Beta for evaluation and community testing.
**Branch:** `release/beta-v0.1.1`.
**Base:** clean public `main` snapshot; content derived from remediation commit
`3798b2850ad2c72e3a8ae1db846dfcf92c06b638`.
**License:** proprietary public Beta, limited evaluation grant (see `LICENSE`).

## What this Beta is

A Lead-first CTF solving extension for DeepSeek Harness. The Lead conversation performs
the analysis with native Harness tools; a local Manager owns Tasks, approvals, evidence
and deliverables. There is no second model loop.

## Highlights

- **18-tool Manager MCP surface** (Task lifecycle, approvals, grants, evidence,
  deliverables, runtime diagnostics) with project-scoped registration.
- **Lead-session evidence path:** one-time Lead binding, task-creation evidence boundary,
  multi-frame zstd session-log ingestion, hash-chained evidence store.
- **Deliverables:** chronological Writeup, deterministic `events.jsonl`, evidence ZIP with
  a verifiable `manifest.sha256`.
- **Six Skills:** core `ctf-solver` plus Web, Misc, Crypto, Reverse and Pwn.
- **Safety gates preserved:** human-only approval decisions and grant creation; no
  arbitrary host shell; fail-closed ACP; privacy-filtered delivery.
- **Offline packaging:** stdlib-only in-tree wheel backend, no runtime dependencies.
- **New in this Beta:** public docs (install/quickstart/troubleshooting/known issues),
  one-shot Windows setup script, Skills deployment helper, zero-hardcoded-path MCP config
  generator, explicit proprietary Beta license, release/PR/community-test materials.

## Fixes carried into this Beta

- Approval console can decide task-scoped `tool_action` approvals; a non-network approval
  can never mint a network grant (F1).
- Task evidence/Writeup/ZIP exclude pre-Task Lead history via a Manager-recorded boundary
  (F2).
- UTF-8-safe capture scripts / concise CLI errors (F4), and source-vs-wheel `sys.path`
  shadowing documented with `python -P` (F5).

## Known limitations (summary)

See `KNOWN_ISSUES.md` for detail. Most important:

- target-window screenshot capture (F3) remains a known issue and fails closed;
- model-mediated Workers / `session/prompt` are blocked by ADR-020;
- no Tier-2 OS isolation, no accepted real-target access, no challenge-code execution;
- real physical-TTY approval and same-child ACP `tools/call` are not verified;
- the project-scoped Workspace MCP Bridge plugin is a required environment prerequisite;
- cross-machine acceptance is pending community testing;
- proprietary Beta license, not open source.

## Install in one line (after cloning)

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\setup_windows.ps1
```

Then open the workspace in DeepSeek Harness, confirm 18 `mcp__ctf-solver__*` tools, and
call `/ctf-solver`. See `INSTALL.md` and `QUICKSTART.md`.

## Verification scope

Validated on Windows 11 + Python 3.14.7 (system Python and an isolated venv, fresh
isolated Manager root). Offline deterministic tests pass. Anything outside that single
machine is explicitly **pending community confirmation**; do not claim cross-machine PASS
until a community report confirms it.

## Not included

- No formal GitHub Release, no package-index publication, no merge into `main`.
- No internal audit evidence, bundles, session logs, databases, screenshots, challenge
  answers or flags.
- No third-party source or runtime dependency.
