# KNOWN ISSUES — CTF-Solver Beta 0.1.1 (public Beta)

This file lists the limitations and verification gaps that are **known and expected** in
the Beta. Entries marked NOT VERIFIED were not exercised on the acceptance machine; do not
treat them as working. Cross-machine behaviour is explicitly pending community testing.

## Product and verification limits

### KI-1 — One Lead session binds exactly one Task

A Lead conversation binds one Task once (`lead_session_id`). Returning to the same
conversation for a second challenge is not a supported rebinding path in this Beta; open a
new conversation (new Harness session) for a new Task. The Manager rejects reuse rather
than silently rebinding.

**Status:** by design, tested. **Workaround:** new conversation per Task.

### KI-2 — Model-request budget is a supervision target, not a hard limit

The CTF workflow is designed around human supervision with a modest number of model
requests per accepted session (the internal acceptance target used 10). Nothing in the
product enforces that number; automatic model-driven continuation is blocked, so cost is
driven by the human/Lead interaction.

**Status:** documented policy. **Note:** ADR-020 still blocks `session/prompt` and
model-mediated Workers entirely.

### KI-3 — Target-window screenshots (F3)

The Manager/Bridge child-process context cannot reliably capture a "target window" in the
Beta environment. Consequences that are by design:

- Lead-bound Tasks refuse `scope=desktop` and never fall back to a desktop capture;
- `--capture-mode real-window` requires an explicit positive `--target-window-pid`;
- there is no automatic window discovery;
- a failed capture is recorded as failed/missing, never faked.

**Status:** KNOWN ISSUE, fail-closed. **Workaround:** skip screenshots and rely on text
evidence, or run the CLI path where a Worker-oriented capture mode is configured. Do not
mark a missing screenshot as present.

### KI-4 — Model-mediated Workers remain blocked (ADR-020)

`session/prompt` and model-driven Worker execution are not open in this Beta.
`ctf_task_continue` records a continuation but does not call a model. Workers are attached
for legacy `ctf-exec` compatibility only; the Lead conversation is the executor.

**Status:** BLOCKED by design.

### KI-5 — No Tier-2 OS isolation, no real targets, no challenge-code execution

The Beta runs on the host. The Harness sandbox is not an OS security boundary for
untrusted binaries, and Tier-2 isolation (WSL/Docker/gVisor) is not part of this Beta.
Therefore:

- do not run challenge binaries, scripts, macros, exploit payloads or installers;
- real competition targets and network grants are implemented but **not accepted** for
  real use in this Beta;
- the Broker/Docker path is not shipped as an accepted capability.

**Status:** BLOCKED / NOT ACCEPTED.

### KI-6 — Real physical-console TTY approval is not verified

The approval console is designed to require a real interactive TTY and fails closed in
pipes/non-TTY contexts. The positive path (a human physically confirming) was not verified
on the acceptance machine.

**Status:** NOT VERIFIED. **Workaround:** run the exact console command in a real terminal;
report results.

### KI-7 — Same-child ACP-spawned `tools/call` is not verified

Under the zero-model-call gate, the ACP child's `tools/call` path (as opposed to
`tools/list`/initialize mount evidence) was not exercised.

**Status:** NOT VERIFIED.

### KI-8 — Workspace MCP Bridge plugin is an environment prerequisite

Project-scoped MCP registration (`.dsh/mcp.servers.yml`) requires the
`@momojie-s/dsh-workspace-mcp` plugin in the running Harness profile. The Beta does not
install it, and it must not be faked by editing global profiles. Without it the Manager
tools are absent (see TROUBLESHOOTING section 1).

**Status:** environment dependency.

### KI-9 — Python 3.11–3.13 need the optional `zstandard` package

Session-log evidence is multi-frame Zstandard. Python 3.14+ has
`compression.zstd` in the standard library; 3.11–3.13 require the optional `zstandard`
package, otherwise ingestion fails closed with `UnsupportedCompressionError`.

**Status:** documented dependency (no runtime dependency on 3.14+).

### KI-10 — Cross-machine acceptance is pending community testing

The Beta was installed and exercised on **one** Windows 11 + Python 3.14.7 machine (system
Python and an isolated venv, fresh isolated root). It has **not** been validated on a
second machine, other Windows versions, other Python versions, other Harness builds, or
Linux/macOS. Do not claim cross-machine PASS until a community test reports it.

**Status:** PENDING COMMUNITY TEST.

### KI-11 — Single Task evidence window is the bound session after the creation boundary

The Manager records a task-creation byte boundary and ingests only records at/after it.
The delivered evidence is therefore the bound Lead session **after Task creation**, not a
per-Task slice and not the pre-Task conversation. Pre-Task history is intentionally
excluded from Writeup/events/ZIP; raw log bytes remain local in the CAS.

**Status:** by design.

### KI-12 — Delivery privacy is a filtered view, not a guarantee about content

Writeup/`events.jsonl`/ZIP exclude model reasoning, raw passthrough prompts, full Skill
bodies and raw session logs. Tool arguments/outputs and real screenshots can still contain
sensitive content; review artifacts before sharing them.

**Status:** by design. **Note:** never share artifacts that contain real credentials,
third-party data or private challenge material.

### KI-13 — Proprietary Beta license

The repository is a public Beta under a limited evaluation grant ([LICENSE](LICENSE)). It
is not open source, and the owner is expected to confirm or replace the license before any
stable release. Redistribution and commercial use are not granted.

**Status:** policy. **Action for owner:** confirm license text before a stable release.

### KI-14 — Windows-only acceptance and path/ACL quirks

The accepted environment is Windows. Long paths, OneDrive-synced folders, Low Integrity
locations and ancestor `.dsh` directories can break installs/workspaces; see
[TROUBLESHOOTING.md](TROUBLESHOOTING.md) sections 3–5 and 9.

**Status:** platform limitation.

### KI-15 — Evidence schema is 1.2; old roots may be incompatible

The Beta uses the 1.2 database/evidence schema. A root created by an older pre-release
build may be rejected with `unsupported database schema version`. Use a fresh root for the
Beta rather than deleting or rewriting an old evidence chain.

**Status:** migration boundary.

## How to report

Use [docs/release/COMMUNITY_TEST_TEMPLATE.md](docs/release/COMMUNITY_TEST_TEMPLATE.md) or
the "Beta test report" issue form. Include OS, Python, Harness build, whether the MCP
bridge plugin was present, tool count (must be 18), which KI items reproduced, and
command/output excerpts. Do not include real flags, credentials, session logs or private
challenge material.
