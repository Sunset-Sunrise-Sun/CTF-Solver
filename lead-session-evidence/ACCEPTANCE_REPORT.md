# CTF-Solver — Round 1 Lead-Session Evidence Integration: Acceptance Report

**Date:** 2026-11-12 (Asia/Shanghai)
**Branch:** `feat/lead-session-evidence` (git worktree
`D:\CTF-SOLVER\scratch\lead-round1`), commit `340d6b5` on top of v0.1.1 tree `21908de`
**Environment:** existing DeepSeek Harness desktop (app 44.7.0, `@deepseek-ai` runtime
0.2.2-rc.1, build `c59d10af…`), Windows 11 26200, Python 3.14.7, pytest 9.1.1,
Workspace MCP Bridge `@momojie-s/dsh-workspace-mcp` 0.3.0, workspace `D:\CTF-SOLVER`.
**Verdict:** **PASS** for the Round 1 scope. Push of the Draft PR is **BLOCKED** only by
the absence of network access to GitHub in this environment (bundle + PR description
prepared).

---

## 0. Scope note (honest disclosure)

The instruction was to execute “CTF-Solver repository Issue #2, latest Owner Decision,
Round 1 only”. This environment has **no network access** to GitHub
(`api.github.com`/`github.com` connection failures; `git ls-remote` failed; `gh` not
installed), so the Issue text could not be fetched and is not quoted here. Execution
therefore followed (a) the six explicit Round 1 requirements in the request and (b) the
local Phase 0 minimal-scope audit (`D:\CTF-SOLVER-review\PHASE0_MINIMAL_SCOPE_AUDIT.md`)
together with the Phase 0 read-only precheck report, which define exactly this Round 1
scope. No Round 2 work was started, no third-party dependency was added, and the
existing product architecture was not rebuilt.

Round 1 delivered: existing v0.1.1 code as the base; uncommitted workspace files
protected before any development; an independent git worktree; Lead identity
integration; evidence ingestion; Writeup; process screenshot; evidence ZIP; operation in
the existing Harness environment; all necessary tests; a Draft PR deliverable (branch +
bundle + PR description, push blocked by network).

---

## 1. Protecting the existing uncommitted workspace state

Before creating the worktree, the Lead recorded and copied the three uncommitted items
to `D:\CTF-SOLVER\scratch\protected-baseline\20261112-0004\` with a SHA-256 manifest:

- `.dsh/mcp.servers.yml` (untracked project MCP config)
- `CTF-Solver-HARNESS-INSTALLATION-ACCEPTANCE.md` (untracked acceptance report)
- `solutions/` (untracked manual solution evidence)

Baseline: branch `fix/v0.1.1-installation-hardening`, HEAD `21908de`, only those three
paths untracked, no tracked modifications. The main checkout was **not** modified except
for the project MCP config, which was deliberately updated (and backed up) as the
integration step; the original content is preserved in
`lead-session-evidence/raw/mcp.servers.yml.original`.

The development happened in an independent git worktree:
`git worktree add D:\CTF-SOLVER\scratch\lead-round1 -b feat/lead-session-evidence 21908de`
(inside the workspace `scratch/` area because the session file sandbox is
workspace-scoped). The main checkout stayed on its branch with its files intact.

---

## 2. Changes (branch `feat/lead-session-evidence`, commit `340d6b5`)

35 files, +3344 / −209. Frozen interfaces and security invariants: contract
`scratch/lead-round1-plan/INTERFACE_CONTRACT.md` (Lead-authored, used to split four
disjoint work streams).

### 2.1 Schema 1.1 → 1.2 (additive)
- `tasks.completion_note TEXT NOT NULL DEFAULT ''` — outcome note, separate from the
  intake `notes`.
- `session_bindings` — `session_id` primary key, `task_id` unique, `bound_at`,
  `bound_by`, `log_sha256`.
- `_migrate_1_1_to_1_2` uses individual statements (no `executescript` inside the
  migration transaction). The legacy `1.0→1.1` migration defect
  (`cannot commit - no transaction is active`) was found while proving the
  `1.0→1.1→1.2` chain and fixed the same way.

### 2.2 Lead identity and resolution
- `SolverConfig.lead_sessions_root`: explicit config (`--lead-sessions-root` /
  `extra` / `CTF_SOLVER_LEAD_SESSIONS_ROOT`) → default `~/.dsh/sessions`. Never derived
  from the isolated `--dsh-home`, never created by the Manager.
- `SessionLogResolver`: new `source=auto|worker|lead`; Lead branch requires the
  one-time binding and validates safe component, unique log, no symlink/junction,
  realpath containment, header `id`, header `cwd` vs Manager root; new reason codes
  `no_binding`, `lead_cwd_mismatch`, `lead_sessions_root_missing`; `validate_lead_candidate`
  for pre-persistence validation returning the raw-log SHA-256. `source=auto`
  prefers a Lead binding, else the Worker path (with an explicit `worker_id` the
  caller keeps the Worker path).
- `ManagerStore`: `SessionBinding`, `bind_lead_session` (hard errors on either
  uniqueness conflict), `get_lead_binding`, `get_task_for_lead_session`.
- `ManagerService`: `create_task(lead_session_id=...)` validates **before** any Task row
  is persisted, binds once, emits `task_created` (with `notes`) and
  `lead_session_bound`; `ingest_session_log(source=...)`; completion auto-ingests the
  bound Lead log when that exact session has no `evidence_ingested` event yet (fail
  closed); screenshot step derivation; runtime status fields/limits.
- MCP/CLI: 18 tools preserved; `ctf_task_create.lead_session_id`,
  `ctf_session_ingest.source`; `--lead-sessions-root` / `--session-log-root` plumbing.

### 2.3 Delivery
- `delivery/screenshot.py`: the real root cause of the historical
  `System.Windows.Forms.SystemInformation : TypeNotFound` failure was a missing
  assembly load; `Add-Type -AssemblyName System.Windows.Forms` is now present. Failure
  diagnostics keep up to 12 lines and decode PowerShell output (utf-8 → gbk →
  latin-1). Capture contract unchanged.
- `delivery/writeup.py`: intake notes rendered exactly once (section 1); the
  completion note gets its own `### 2.1 Completion note (outcome record)` subsection;
  `tool_call` steps show `(turn T, step S)` and are labelled **Lead initiated** for
  Lead-sourced records (`worker_id` NULL) while Worker evidence keeps `Worker
  initiated`; screenshots bind by exact `step_id` or derived `turn{T}-step{S}`.
- `delivery/bundle.py`: raw Lead log included from CAS via `ingestion_sources`;
  post-build internal `verify_zip` (raises `DeliveryError`, cleans up). ZIP bytes stay
  deterministic.
- `notes` / `completion_note` separation in every lifecycle write path (start failure,
  ACP failure, pause, cancel, intake failure, completion-pending, completion-abort
  rollback) — see the live defect in section 5.

### 2.4 Skills and docs
- `ctf-solver/SKILL.md`: executor = the Lead conversation using native Harness tools;
  Manager ingests the bound Lead session log; the actual 18 tools; category-Skill
  routing is a hard step; never claim unrecorded steps. Five category Skills append the
  unified ≤5-line evidence paragraph.
- Docs: ADR-022, README status/product contract, Installation Guide §6.5 + boundaries,
  Local Operation boundaries, and `docs/LEAD_SESSION_EVIDENCE.md`.

**No new third-party dependencies** (`pyproject.toml` dependencies remain empty; the
wheel is built with the in-tree stdlib PEP 517 backend).

---

## 3. Security invariants verified

- `ctf_session_ingest` accepts **no path and no arbitrary session id**; the log comes
  from the Manager registry only. The pre-existing negative test
  (`tests/test_round2_security_integration.py`) remains green.
- Binding is one-time in both directions (DB uniqueness plus hard `StateError`s);
  duplicate/foreign bindings rejected.
- Header id mismatch, cwd mismatch, missing Lead root, ambiguous/missing log,
  symlink/junction components and path escapes all fail closed with stable reason
  codes (independently re-tested).
- Completion fails closed if the bound Lead log cannot be ingested; a previous
  Worker-stub ingest cannot suppress the Lead ingest (session-specific check).
- The evidence chain remains append-only and independently recomputable
  (`evidence verify-chain`: 1097 records, ok).

---

## 4. Live end-to-end runs in the existing Harness environment

The Manager MCP server was run by the Workspace MCP Bridge with
`--root D:/CTF-SOLVER --lead-sessions-root C:/Users/28746/.dsh/sessions
--capture-mode desktop`, and the rebuilt wheel was installed into the managed venv
(offline `pip install --no-index --no-deps --force-reinstall`). The config hot-reload
brought up the new Manager without restarting Harness. All Manager operations below
were performed through real `mcp__ctf-solver__*` calls from Harness conversations.

### 4.1 Run 1 — main Lead conversation (also the defect-discovery run)

| Item | Value |
|---|---|
| Task | `t-e3163582b2304947a7a6635c97784cac` (“Synthetic Lead session evidence pipeline demo”, misc) |
| Lead session | `session-b018eb43-1975-4b34-a091-a6e0eb2f85ac` (binding `bound_by=lead`, log sha `090963d4…`) |
| Ingestion #1 (auto→lead) | 583 frames / 962 records / 963 appended / 0 skipped / 1 expected self-call gap; raw sha `4b947bb7…` |
| Ingestion #2 (auto→lead) | +13 appended / **962 skipped duplicates** (idempotent + incremental); raw sha `07466b19…` |
| Process screenshot | `shot-0cd9e8458a514bc995189de39a03c018`, desktop, **ok**, 2560x1600, sha `f22ad241…905321`, derived step `turn1-step108`, CAS object verified |
| Task completion | completed, `solved_flag_candidate`, evidence head `287fbf78…` |
| Writeup | 270 257 chars, 150 `### Step` headings = 150 `tool_call` events; screenshots bound under their step; failures/gaps honest |
| Evidence ZIP | `e2cb6446…f3b7`, 3 221 239 B, 5 members (events.jsonl, manifest, raw Lead log, screenshot, writeup); manifest verifies; two builds byte-identical |
| Evidence chain | recomputed ok |

### 4.2 Defect found by the live run (P1-1) and fixed

Run 1 exposed that `complete_task` wrote its completion note into `tasks.notes` at the
`COMPLETION_PENDING` transition, clobbering the intake description
(`notes == completion_note == 304 chars`; raw evidence in
`raw/live-run-1-notes-defect-evidence.txt`). Root cause: `set_task_status` had only a
`notes` parameter. Fix: `set_task_status(completion_note=...)` and every operational
lifecycle note now writes `completion_note`, so `notes` is only ever the intake
description; regression test
`test_completion_preserves_intake_notes_and_uses_completion_note` added. Run 1 is kept
as the honest defect-discovery run; run 2 is the accepted demonstration.

### 4.3 Run 2 — fresh Harness session, after the fix (accepted run)

| Item | Value |
|---|---|
| Task | `t-2bc0de882ae44b28a523a180d6154133` (“Synthetic Lead live run 2”, misc) |
| Lead session | `fb4f9ef3-dd76-4a86-a9f6-4892611f9e28` (binding `bound_by=lead`, log sha `6d6d6485…`) |
| Ingestion #1 (auto→lead) | 38 frames / 73 records / 74 appended / 0 skipped / 1 expected self-call gap |
| Ingestion #2 (auto→lead) | +13 appended / 73 skipped duplicates; raw sha `42422d77…` |
| Process screenshot | `shot-c1bfdd20b71e442394a876e0652fb908`, desktop, **ok**, 2560x1600, sha `a100e648…6dbf55`, CAS object verified |
| Intake notes vs completion note | `notes` (342 chars, `INTAKE-DESCRIPTION-MARKER-2…`) **byte-identical** to creation; `completion_note` (160 chars) distinct **PASS** |
| Task completion | completed, `solved_flag_candidate`, evidence head / chain head `93f91ec4…`, chain ok (1097 records) |
| Writeup | 19 435 B, sha `8ef51719…`; **11 `Lead initiated` steps = 11 `tool_call` events** (10 results + 1 honest self-ingest gap); intake marker exactly once in section 1; `### 2.1 Completion note` present; no `Worker initiated` label in Lead evidence |
| Evidence ZIP | `abfbaf33…38bc3b`, 1 657 993 B, 5 members (events.jsonl, manifest, `raw/session-42422d77cb896c41.jsonl.zstd`, screenshot PNG, writeup.md); manifest verifies (4 entries, 0 problems); two builds byte-identical |
| Flag | candidate `flag{synthetic_live_run_2_fb4f9ef3}`, candidate only, **not submitted** |
| Skills | `python -m ctf_solver skills --root D:\CTF-SOLVER` → `ok=true, found=6, missing=[]` |

Note (honest): in run 2 the screenshot was captured with an explicit step id, so the
Writeup shows it through the `ctf_screenshot_capture` step record rather than a separate
formatted `- Screenshot:` bullet; the derived-`turn{T}-step{S}` association path is
demonstrated by run 1 (`turn1-step108`, screenshot line present under its step). Both
cases store the PNG in CAS with a recomputable SHA-256.

Runtime artifact locations (outside Git, as required):
`D:\CTF-SOLVER\tasks\<task_id>\{writeup.md, evidence.zip, evidence\events.jsonl}`;
screenshots/CAS under `D:\CTF-SOLVER\.ctf-solver-data\cas\sha256\`.

---

## 5. Tests

- **Full suite (final tree, worktree):** `python -m pytest -q` →
  **1114 passed, 5 skipped, 1 failed** in ~63 s.
  - The only failure is the pre-existing environment-drift test
    `tests/test_verification_round1.py::test_protected_ctfworker_state_and_audit_hash_unchanged`:
    it asserts that the live `C:\Users\28746\.dsh\profiles\desktop` mtime still equals a
    hard-coded 2026-11-09 baseline value; the directory changed on 2026-11-11 16:59 when
    the Workspace MCP Bridge plugin was installed (documented in the installation
    acceptance report). The verifier reproduced the **identical** failure on the
    untouched base commit `21908de` in a separate worktree, so it is not a regression
    from this round. Baseline evidence: `raw/tests-base-commit-baseline.txt`.
  - 5 skips are the documented Windows symlink/real-ACP opt-in conditions.
- **Evidence-packaging gate (found by the independent verifier on the first evidence
  commit, fixed):** the repository already gates every committed `*junit*.xml` file
  (well-formed, privacy-redacted, zero failures). The recorded raw JUnit XML necessarily
  contains the Windows home path and the documented one baseline-drift failure, so the
  JUnit XML is **kept out of Git** (it remains in the scratch plan directory); the
  committed evidence uses the text suite logs instead, and the gate re-run passes
  (2 passed). Full suite after this evidence-only fix: **1114 passed, 5 skipped,
  1 pre-existing environment-drift failure** (also confirmed independently by the
  verifier on a renamed scratch copy).
- **Focused:** Lead binding/resolver, service flow, delivery/screenshot, skills, MCP
  server, migration, security-integration sets — all green (see verifier matrices).
- **Independent verifier (separate read-only worktree + dedicated base-checkout):**
  contract/dependency matrix 24/24 PASS; security/service matrix 29/29 PASS (including
  the completion-note defect regression and worker-resolution parity with the base
  commit); migration/determinism matrix 12/12 PASS (genuine 1.1→1.2 migration from a
  read-only snapshot of the real pre-round DB, rows preserved, chain recomputed,
  source untouched; writeup and ZIP two-build byte equality; forced manifest failure
  raises). See `raw/VERIFIER_REPORT.md` and `raw/verifier/*`.
- **Bundle / clone check:** `git bundle verify` exit 0 (complete history, ref
  `feat/lead-session-evidence`); a clone from the bundle checks out the same tree cleanly
  and passes the focused Lead/delivery/skills set (98 passed, 1 skipped). See
  `raw/bundle-artifact.txt`, `raw/bundle-clone*.txt`.

---

### 5.1 Final independent verifier verdict

- **Verdict: PASS** on the frozen HEAD `48a70da` (tree `3047e79d…`; `git status` empty
  before/after). `git diff --name-only 726e741 48a70da -- ctf_solver tests .dsh
  pyproject.toml` is empty, proving the post-freeze change was evidence-only.
- Re-run on `48a70da`: full suite **1114 passed, 1 failed (the acknowledged base-identical
  baseline-drift test), 5 skipped**; committed-JUnit gate **2 passed** (blocker
  resolved); focused 8 files **180 passed, 2 skipped**; targeted runtime-status /
  completion-note / Lead-label **4 passed**; skills `ok=true, found=6`; matrices
  contract/deps **24/24**, security/service **29/29**, migration/determinism **12/12**.
  See `raw/VERIFIER_REPORT.md` and `raw/verifier/FINAL2_*`.

## 6. Running in the existing DeepSeek Harness environment

This was verified live, not just by unit tests:

1. **Wheel:** built with the in-tree stdlib backend from the worktree
   (234 337 B, sha `41e9139b…315e`), RECORD 64/64 verified, extracted import and CLI
   checked from a neutral cwd, then installed offline into
   `C:\Users\28746\AppData\Local\CTF-Solver\venv` (pip 26.2.1). Installed package
   reports `0.1.1 / schema 1.2`; the new `completion_note` write path is present
   (`raw/installed-wheel-final.txt`, 121 installed files manifest).
2. **MCP registration:** project-scoped `D:\CTF-SOLVER\.dsh\mcp.servers.yml` loaded by
   the Workspace MCP Bridge; all **18** `mcp__ctf-solver__*` tools were invoked from
   live Harness conversations, including the two new parameters.
3. **Manager/ACP:** the Manager started with the explicit live
   `--lead-sessions-root`, ACP `state=ready` (isolated `DSH_HOME`), and the project
   privacy patch from the installed package; the config hot-reload path was exercised.
4. **Migration on the real DB:** the existing `manager.sqlite` (schema 1.1, 2 tasks,
   18 events) was migrated in place to 1.2 during the live reload; tasks/events/chain
   preserved (`raw/manager-db-schema-1.2.txt`), chain verified afterwards.

---

## 7. Draft PR delivery status

- Branch: `feat/lead-session-evidence` (commit `340d6b5` product/tests/docs; later
  commits only add this evidence trail).
- Git bundle: `D:\CTF-SOLVER\dist\CTF-Solver-Lead-Session-Evidence.bundle`
  (`git bundle verify` exit 0, complete history; clone/focused-test checked; hash
  recorded in the final delivery message and in `raw/bundle-artifact.txt`).
- PR description: `DRAFT_PR.md`.
- **BLOCKED:** creating/pushing the Draft PR requires network access to GitHub. In this
  environment `github.com:443` is unreachable (`git ls-remote` fails; `gh` is not
  installed). The bundle + description let the owner push the branch and open the
  Draft PR without re-running anything.

---

## 8. Known limitations (not hidden)

- One Lead session binds to one Task in this round; the ingested evidence window is
  the whole bound session, not a per-Task slice. Per-Task window filtering and
  multi-Task binding are deferred.
- HTTP evidence is result-level (`web_fetch` URL/status/rendered text), not raw
  request/response bytes.
- Very long tool output may be spilled by Harness to `%TEMP%` (preview-only in the
  log); the pipeline records the preview and marks gaps honestly.
- Desktop capture stores the real screen in CAS/evidence ZIP — required for the
  process-screenshot deliverable, but review before sharing.
- The hash chain is tamper-evident bookkeeping, not a digital signature.
- The installed venv package was replaced by the rebuilt wheel (that is the
  environment-integration evidence). Rollback: reinstall the v0.1.1 release wheel from
  `D:\CTF-SOLVER-review\v011-release-assets\ctf_solver-0.1.1-py3-none-any.whl`.
- The test suite has one pre-existing environment-drift failure (section 5), left
  untouched because it is a historical Round 1 snapshot assertion, not product
  behaviour.

---

## 9. Raw evidence index

See `README.md` in this directory for the curated file list and hashes. Large runtime
artifacts (ZIP/writeup/screenshot/session log/DB) are referenced by path and SHA-256 in
sections 4 and 6 and are intentionally kept out of Git.
