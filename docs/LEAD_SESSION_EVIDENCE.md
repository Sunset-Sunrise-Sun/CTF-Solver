# Lead-Session Evidence Integration (Round 1)

**Status:** implemented and verified in the existing DeepSeek Harness environment.
**Scope:** this round only integrates the main-conversation Lead session as the Task
evidence source. It does not rebuild the product, does not add dependencies, does not
change ADR-020, and does not start the deferred Round 2 work.

## 1. Why

The v0.1.1 product could already decode Harness `session.v4.jsonl.zstd` logs, normalize
`tool/call` / `tool/result`, store full tool output in the SHA-256 CAS, maintain a
tamper-evident event hash chain, and render a Writeup. The missing piece was identity:
`SessionLogResolver` only accepted a registered **Worker** session, and the Lead
conversation has no Worker row. Real Lead work therefore never entered the evidence
chain, and Writeups honestly said "No tool executions were recorded".

This round adds a minimal, additive path:

```
Lead conversation ($env:DSH_SESSION_ID)
        │  ctf_task_create(lead_session_id=...)      ctf_session_ingest / ctf_task_complete
        ▼                                                     │
Manager: verify id, unique log, header id, header cwd → one-time binding
        │                                                     │
        ▼                                                     ▼
session_bindings (schema 1.2)  ──────────────►  SessionLogResolver(source=lead)
                                                              │
                                                              ▼
        unchanged evidence pipeline: multi-frame zstd → normalize → CAS → hash chain
                                                              │
                                                              ▼
                            Writeup (tool steps, failures, screenshots) + evidence ZIP
```

The Lead executes with native Harness tools; the Worker / typed `ctf-exec` path remains
for legacy compatibility (ADR-011 restrictions still apply to it). See ADR-022.

## 2. Data model (additive schema 1.1 → 1.2)

| Object | Change |
|---|---|
| `tasks.notes` | unchanged: the **intake** description (written at creation) |
| `tasks.completion_note` | new `TEXT NOT NULL DEFAULT ''`: the **outcome** note (completion/interruption/lifecycle operational notes) |
| `session_bindings` | new table: `session_id TEXT PRIMARY KEY`, `task_id TEXT NOT NULL UNIQUE`, `bound_at`, `bound_by`, `log_sha256` |
| `SCHEMA_VERSION` | `1.1` → `1.2` |

The migration is additive only (`ALTER TABLE ... ADD COLUMN` + `CREATE TABLE/INDEX`),
uses individual statements (no `executescript` inside the migration transaction), and
supports `1.0 → 1.1 → 1.2` and `1.1 → 1.2`. No data is rewritten or dropped.

## 3. Security invariants

1. `ctf_session_ingest` still has **no path parameter** and **no arbitrary session-id
   parameter**. The log is selected only by the Manager registry: the Task's one-time
   Lead binding, or the pre-existing Worker registration.
2. A Lead binding is created **once**, only after the Manager verifies:
   - the supplied id is a single safe path component (no traversal, separators, drives);
   - exactly one `<lead_sessions_root>/<slug>/<session_id>/session.v4.jsonl.zstd` exists;
   - no symlink/junction component and realpath containment under the Lead root;
   - the decoded session header `id` equals the supplied id;
   - the header `cwd` realpath-equals the Manager workspace root (case-insensitive);
   - the session is not already bound to another Task (DB uniqueness on both
     `session_id` and `task_id`).
3. `lead_sessions_root` is an explicit configuration (CLI `--lead-sessions-root`,
   `extra["lead_sessions_root"]`, or `CTF_SOLVER_LEAD_SESSIONS_ROOT`), defaulting to
   `~/.dsh/sessions`; it is never derived from the Manager's isolated `--dsh-home` and
   is never created by the Manager. A missing root fails closed
   (`lead_sessions_root_missing`).
4. Failure reason codes are stable and fail closed: `no_binding`,
   `lead_cwd_mismatch`, `lead_sessions_root_missing`, plus the pre-existing worker-path
   codes (`no_worker`, `unknown_session`, `log_missing`, `ambiguous_session_log`,
   `symlink_rejected`, `path_escape`, `header_mismatch`, `sessions_root_missing`).
5. `source=auto` prefers the explicit Lead binding and otherwise keeps the Worker path;
   `source=worker` is the unchanged legacy path; `source=lead` requires the binding.
6. Completion fails closed: a bound Lead Task auto-ingests its Lead log before the
   completion preconditions run, and the completion is refused if that ingestion fails
   or produces no `evidence_ingested` event for that exact session.

## 4. Usage (tested environment)

Prerequisites: v0.1.1 source/wheel, the six project Skills under `.dsh/skills/`, the
project-scoped Workspace MCP Bridge installed in the Harness profile, and
`.dsh/mcp.servers.yml` with `--lead-sessions-root <DSH_HOME>/sessions` (see
`INSTALLATION_GUIDE.md` section 6.5).

```
# 1. from the Harness native shell, read the Lead session id (never guess it)
$env:DSH_SESSION_ID

# 2. create the Task and bind the Lead session once
ctf_task_create(title=..., category=..., conversation_id=$env:DSH_SESSION_ID,
                lead_session_id=$env:DSH_SESSION_ID, notes=<intake description>,
                supplied_files=[...])

# 3. do the real analysis with native tools; the calls are recorded in the Lead log
# 4. ingest the bound Lead log (idempotent, incremental)
ctf_session_ingest(task_id)
# 5. optional process screenshot; the Manager derives the latest turn/step id
ctf_screenshot_capture(task_id)
# 6. record the candidate flag, complete (auto-ingests if needed), deliver
ctf_flag_candidate(task_id, flag=..., source=...)
ctf_task_complete(task_id, result_state=..., note=<outcome note>)
ctf_writeup_build(task_id); ctf_events_export(task_id); ctf_evidence_zip(task_id)
```

CLI equivalents exist for local/headless use: `ctf-solver manager serve
--lead-sessions-root ...`, `ctf-solver task create --lead-session-id ...`.

## 5. What the Writeup / ZIP contain

- `events.jsonl`: normalized evidence from the bound Lead session (tool calls, tool
  results with CAS hashes, assistant messages, explicit evidence gaps, screenshots,
  flag candidate, completion).
- `writeup.md`: task metadata, intake notes once (section 1), completion note in a
  separate subsection (2.1), actual tool steps with `(turn, step)` and arguments /
  result previews / exit codes / CAS refs, failures and gaps, candidate flag state.
- `raw/session-<sha16>.jsonl.zstd`: the exact ingested Lead log bytes (already in CAS).
- `screenshots/<id>.png`: the captured process screenshot when capture succeeded.
- `manifest.sha256`: every member hashed; the builder verifies the archive internally
  and raises on mismatch; two builds from the same committed evidence are
  byte-identical.

## 6. Acceptance evidence

| Check | Result |
|---|---|
| Full regression suite (worktree, Windows, Python 3.14.7) | **1113 passed, 5 skipped, 1 pre-existing environment-drift failure** (`test_verification_round1.py::test_protected_ctfworker_state_and_audit_hash_unchanged`); the same test fails identically on the untouched base commit `21908de` — it compares live `~/.dsh/profiles/desktop` mtime to a 2026-11-09 snapshot that changed when the Workspace MCP bridge was installed, not by this round |
| Live Lead-session end-to-end (run 1, main conversation) | PASS: 18 Manager tools; Task `t-e3163582b2304947a7a6635c97784cac`; one-time binding; `evidence_ingested` source `lead`; 963 + 13 appended / 962 skipped duplicates (idempotent + incremental); desktop screenshot `ok` 2560x1600 (sha `f22ad241...905321`); Writeup 150 tool steps; ZIP `e2cb6446...f3b7` (5 members) with raw Lead log, screenshot, events and a verifying manifest; two builds byte-identical. This run also exposed the P1-1 completion-note overwrite defect (fixed, below). |
| Live Lead-session end-to-end (run 2, fresh Harness session, after the fix) | See `lead-session-evidence/ACCEPTANCE_REPORT.md` (final run: binding, ingestion, screenshot, notes preservation, Writeup/ZIP verification). |
| Independent verification | See `lead-session-evidence/ACCEPTANCE_REPORT.md` and the raw verifier output under `lead-session-evidence/raw/`. |

## 7. Known limitations (honest)

- **One binding per Lead session.** A Lead conversation can bind one Task in this round;
  per-Task evidence-window filtering and multi-Task binding are deferred. The ingested
  evidence window is the whole bound session (from its start to the last ingestion), so
  a Writeup includes every recorded tool call of that session, not only the challenge
  analysis.
- **HTTP evidence is result-level.** Harness records `web_fetch` URL/status/rendered
  text, not raw request/response bytes. Do not claim packet-level HTTP evidence.
- **Long tool output can be spilled** by Harness to `%TEMP%` with a preview + locator in
  the log; the pipeline records the preview honestly and does not currently re-read the
  spill file.
- **Desktop screenshots capture the real desktop** (as configured by
  `--capture-mode desktop`); that is what the process-screenshot deliverable requires,
  but it means the PNG/evidence ZIP contain the live screen. Review before sharing.
- The evidence hash chain is tamper-evident bookkeeping, **not** a digital signature.
- A live session's log grows while it is being ingested; the additional
  `unmatched_call` gap for the in-flight ingest call itself is expected and recorded
  honestly.
- Wheel installation in the tested environment replaced the installed `0.1.1` package
  with the rebuilt wheel from this branch; roll back with the v0.1.1 release wheel if
  needed (see the acceptance report's rollback section).
