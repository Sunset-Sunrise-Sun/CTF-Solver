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
`INSTALL.md` section 6).

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
| Full regression suite (Windows, Python 3.14.7) | **PASS** for the product tests; the only exception is a historical verification test that compares a live Harness profile mtime with an old snapshot and is not part of this release. The product code itself has no regression in the shipped test set |
| Live Lead-session end-to-end (run 1, main conversation) | PASS: 18 Manager tools; Task `t-e3163582b2304947a7a6635c97784cac`; one-time binding; `evidence_ingested` source `lead`; 963 + 13 appended / 962 skipped duplicates (idempotent + incremental); desktop screenshot `ok` 2560x1600 (sha `f22ad241...905321`); Writeup 150 tool steps; ZIP `e2cb6446...f3b7` (5 members) with raw Lead log, screenshot, events and a verifying manifest; two builds byte-identical. This run also exposed the P1-1 completion-note overwrite defect (fixed, below). |
| Live Lead-session end-to-end (run 2, fresh Harness session, after the fix) | PASS: Task `t-2bc0de882ae44b28a523a180d6154133`; 74 + 13 appended / 73 skipped duplicates; desktop screenshot `ok` 2560x1600 (sha `a100e648...6dbf55`); intake `notes` byte-identical (342 chars) and `completion_note` distinct; Writeup 19 435 B sha `8ef51719...` with 11 `Lead initiated` steps = 11 `tool_call` events; ZIP `abfbaf33...38bc3b` (5 members) with raw Lead log, screenshot, events, writeup and a verifying manifest; two builds byte-identical. Details: internal acceptance record (not part of this release) |
| Independent verification | Contract/deps 24/24 PASS, security/service 29/29 PASS, migration/determinism 12/12 PASS against the final tree; the single full-suite failure is the pre-existing environment-drift test, reproduced identically at base `21908de`. Raw outputs are part of the internal acceptance record |

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


## 8. Round 2 minimal delivery (final development round)

Round 2 (branch `fix/round2-minimal-delivery`, commit `d00cdbd`, base `f30c9a2`) closes the
remaining delivery gaps on top of the Round 1 Lead-session evidence integration:

- **Real target-window capture.** `capture_mode` defaults to `real-window` and a positive
  `--target-window-pid <PID>` is required; the Manager refuses to build a desktop capturer
  for Lead-bound Tasks, never falls back to the desktop on failure, and records
  `capture_method`/`target_pid`/`scope`/`session_id`/`worker_id`/`step_id` in the
  `screenshot_captured`/`screenshot_failed` event. Screenshot ownership for a Lead-bound Task
  is `worker_id=null`, `session_id=<Lead session>`.
- **Writeup shows the real work.** Section 3 lists Harness-native Lead tool calls separately
  from Worker `ctf-exec` executions; successful screenshots are embedded as Markdown images
  under the real `turn{T}-step{S}` (materialised to `tasks/<id>/screenshots/`) with sha256,
  time, dimensions, capture method and target PID; failed/missing captures are marked
  honestly. Historical gaps are classified as resolved / unresolved, and the final ingest
  self-call gap is labelled `Expected capture-boundary gap`.
- **Delivery privacy policy.** One projection in `ctf_solver/delivery/privacy.py` is shared by
  the Writeup, `events.jsonl` export and evidence ZIP: `assistant_message`, `passthrough`,
  job/command bookkeeping and unknown event types are dropped, turn/step events keep only
  numeric metadata, Skill result bodies are replaced by a policy notice, and raw session logs
  are never placed in the ZIP. Raw logs stay unmodified in the local CAS and the evidence
  chain remains append-only/verifiable. Technical tool calls/results, approvals, grants,
  flags, screenshots and gaps are retained as real evidence.
- **Category Skill loading.** The Core Skill requires an actual native
  `skill({"name": "ctf-<category>"})` load after the Task category is known and before reading
  challenge material; discovery output is not a substitute, and load failure stops analysis.
- **Verification.** Full suite 1143 passed / 5 skipped / 1 pre-existing environment-drift
  failure (identical at base `f30c9a2`); independent verifier PASS on the implementation and
  again PASS on the final-audit privacy patch (matrices 16/16, 10/10, 11/11); wheel 66 members /
  RECORD 65/65; 0 new Ruff findings; no new dependencies; no DB migration.
- **Final read-only audit hardening.** Two delivery-projection bypasses were found and fixed
  before release: raw torn-line log previews in `evidence_gap` payloads, and orphaned Skill
  tool results that could not be classified (both canaries now absent from Writeup,
  `events.jsonl` and every ZIP member; raw DB/CAS stay append-only and local). See
  the internal release acceptance report. A live fresh-Harness acceptance run produced a real Task, a Lead-bound session,
  a real target-window screenshot (780x330, only the target window), a Writeup with the real
  tool calls and the embedded image, and a privacy-filtered evidence ZIP
  (no raw log, canary-free) with a verifying manifest. See the internal release acceptance report.
