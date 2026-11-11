# Independent Verification Report — Round 1 Lead Session Evidence (FINAL — PASS)

| | |
|---|---|
| Task | `task-4` (shared board, owner `verifier-r1`) |
| Spec | `scratch/lead-round1-plan/INTERFACE_CONTRACT.md` (authoritative Round 1) |
| Artifact under test | `D:\CTF-SOLVER\scratch\lead-round1`, branch `feat/lead-session-evidence` |
| Final frozen HEAD | `48a70da47713933b87deb0027709a020f218f75b` (parent `726e741`; commits `340d6b5` product/tests/Skills/docs, `726e741` acceptance/evidence, `48a70da` evidence-only JUnit-gate fix) |
| Final frozen tree | `3047e79dd162b5e0cb184d5c4d1aee64e8f9f7cc` |
| Tree cleanliness | `git status --porcelain` → **empty** (verified before and after all runs) |
| Product/test identity vs first-frozen tree | `git diff --name-only 726e741 48a70da -- ctf_solver tests .dsh pyproject.toml` → **empty**; subtree hashes identical (`ctf_solver` `6eac4d37d6c03259615f0b2ed906cdb8e7928fed`, `tests` `f2c960adaf3dcef984aa60443fc28c8ec9214873` for both commits) |
| Base | `21908de0dd52099f9f90c1cead6f94445f1d3a1d` in `scratch/lead-round1-plan/base-checkout` (detached worktree) |
| Environment | Windows, Python 3.14.7, pytest 9.1.1, `zstandard` 0.25.0; no network; no new deps |
| Verification mode | read-only wrt product/tests; no commits by the verifier; real Manager DB only via `mode=ro` snapshots |

## 1. VERDICT

**PASS.**

The final frozen tree `48a70da` satisfies the frozen contract: full suite
`python -m pytest -q` → **1114 passed, 1 failed, 5 skipped in 64.81 s**, where the single
failure is the acknowledged, base-commit-identical **baseline-drift** environment test
(live Harness profile mtime change, not a product regression — §4). The repository's
committed-JUnit evidence gate is green (2 passed) after the Lead's evidence-only fix
removed the three previously failing raw XMLs; product code, tests and Skills are
byte-identical to the tree covered by the full matrix (proved by git subtree hashes in the
header table). All product matrices pass: contract/deps **24/24**, security/service
**29/29**, migration/determinism **12/12**, focused tests **180 passed / 2 skipped**,
targeted regression tests **4 passed**, skills `ok=true found=6`.

Verification history: the pre-fix freeze (`726e741`) was correctly reported **BLOCKED**
because the committed evidence XMLs (`lead-session-evidence/raw/junit-*.xml`) violated the
repo's existing JUnit gate. The fix commit `48a70da` is **evidence-only**; the verifier
re-ran the entire matrix on top of it and the gate is now green.

## 2. Exact commands and counts (final frozen tree `48a70da`)

| # | Command (cwd `D:\CTF-SOLVER\scratch\lead-round1`) | Result | Raw output |
|---|---|---|---|
| 1 | `python -m pytest -q` | **1114 passed, 1 failed, 5 skipped, 64.81 s** (only failure = baseline drift) | `FINAL2_full_pytest.txt` |
| 2 | `python -m pytest tests/test_delivery_junit_xml.py -q` | **2 passed** (JUnit evidence gate green) | `FINAL2_junit_gate.txt` |
| 3 | `python -m pytest tests/test_lead_session_binding.py tests/test_session_log_resolver.py tests/test_evidence_store.py tests/test_delivery_writeup_bundle.py tests/test_lead_task_flow.py tests/test_mcp_manager_server.py tests/test_delivery_screenshot.py tests/test_skills.py -q` | **180 passed, 2 skipped, 11.67 s** | `FINAL2_focused_pytest.txt` |
| 4 | `python -m pytest "tests/test_verification_round1.py::test_runtime_status_reports_round1_limits_honestly" "tests/test_manager_service.py::test_runtime_status_and_shutdown_cleanup" "tests/test_lead_task_flow.py::test_completion_preserves_intake_notes_and_uses_completion_note" "tests/test_delivery_writeup_bundle.py::test_tool_call_heading_marks_lead_origin_when_worker_id_is_null" -q` | **4 passed** | `FINAL2_targeted_pytest.txt` |
| 5 | `python -m ctf_solver skills --root .` | `ok=true, found=6, missing=[], problems=[]`, UTF-8 no BOM | `FINAL2_skills.txt` |
| 6 | `python scratch\lead-round1-plan\verifier\phase2_contract_deps.py` | **24/24 PASS** | `FINAL2_contract_deps.txt`, `phase2_contract_deps.json` |
| 7 | `python scratch\lead-round1-plan\verifier\phase2_security.py` | **29/29 PASS** | `FINAL2_security.txt`, `phase2_security.json` |
| 8 | `python scratch\lead-round1-plan\verifier\phase2_migration_determinism.py` | **12/12 PASS** | `FINAL2_migration_determinism.txt`, `phase2_migration_determinism.json` |
| 9 | base-checkout: `python -m pytest tests/test_verification_round1.py::test_protected_ctfworker_state_and_audit_hash_unchanged -q` | **1 failed** — identical values to the frozen-tree failure | `FINAL2_baseline_drift_base.txt` |

Skipped tests (5, environment/protocol only): 2 Windows-symlink intake cases, 2 Windows
symlink/junction resolution cases, 1 opt-in real-ACP smoke test.

## 3. Previously blocking finding — RESOLVED by evidence-only fix `48a70da`

- Pre-fix failure: `tests/test_delivery_junit_xml.py::test_all_committed_junit_xml_files_parse_and_counts_are_consistent`
  failed on the three then-tracked files
  `lead-session-evidence/raw/junit-{after-notes-fix,base-commit-baseline,final}.xml`,
  which contained `C:/Users/28746` (gate at `tests/test_delivery_junit_xml.py:33`) and
  `failures="1"` (gate at `:42`).
- Resolution: commit `48a70da` removes those three tracked XMLs (kept outside Git, as the
  gate requires privacy-redacted, failure-free committed XML) and adds evidence/verifier
  packaging. The JUnit gate now reports **2 passed** (`FINAL2_junit_gate.txt`), and the
  full-suite failure count returned to exactly the acknowledged baseline drift.
- The verifier independently validated the exact fix beforehand in a scratch extraction of
  the pre-fix tree (rename → full suite 1114 passed / 1 failed / 5 skipped,
  `FINAL_full_pytest_sim_after_fix.txt`); the Lead's committed fix produces the same
  result.

## 4. Baseline-drift proof (non-product, explicitly reported)

`tests/test_verification_round1.py::test_protected_ctfworker_state_and_audit_hash_unchanged`
fails in the frozen tree and fails **identically** in a clean base `21908de` worktree:
expected `~/.dsh/profiles/desktop` mtime `1794246751302462400`, actual
`1794409697473832700` (“the live Harness profile directory was modified during
verification”). The live profile was modified before this round (live Harness use), not by
product code. Raw: `FINAL2_baseline_drift_base.txt` (base) and `FINAL2_full_pytest.txt`
(frozen). This single failure is explicitly reported and is **not** counted as a Round 1
regression.

## 5. Contract compliance + dependency freeze (24/24 PASS)

- **§3.1 config**: `lead_sessions_root` priority `extra` > env `CTF_SOLVER_LEAD_SESSIONS_ROOT`
  > `~/.dsh/sessions`, never derived from `dsh_home`; `ensure_runtime_dirs()` does not
  create it (`ctf_solver/core/config.py:149,193`).
- **§3.2 DB**: `SCHEMA_VERSION="1.2"`; `tasks.completion_note TEXT NOT NULL DEFAULT ''`
  (`ctf_solver/storage/db.py:55`); `session_bindings` PK/UNIQUE/FK + index (`:61-68`);
  `_migrate_1_1_to_1_2` additive with individual `conn.execute`, no `executescript`
  (`:307-327`); `1.0→1.2` and `1.1→1.2` wired in `initialize_schema`.
- **§3.3 types**: `TaskRecord.completion_note` appended last, in `to_dict`, defensive
  `from_row` (`ctf_solver/core/types.py:277,300,325`).
- **§3.4 store**: frozen `SessionBinding` + `to_dict`
  (`ctf_solver/manager/store.py:39`), one-time `bind_lead_session`/`get_lead_binding`/
  `get_task_for_lead_session` (`:460,515,524`); `finalize_*` write `completion_note`
  (`:256,341`); `set_task_status` retains `notes = COALESCE(?, notes)` plus the
  Lead-authorised `completion_note = COALESCE(?, completion_note)` (`:156,182`).
  AST check: **no** product call site passes `notes=` to `set_task_status` (A08b).
- **§3.5 resolver**: reason codes incl. `no_binding`, `lead_cwd_mismatch`,
  `lead_sessions_root_missing` (`ctf_solver/manager/session_logs.py:69-87`);
  `resolve(task_id, *, worker_id, source="auto")` with no path/session-id parameter
  (`:268`); `validate_lead_candidate` (`:304`); safe-component check (`:163`);
  Lead-root requirement (`:484`); header id + cwd verification (`:610-681`); unique/
  contained log resolution (`:519`). `ResolvedSessionLog.source` defaults `worker`.
- **§3.6 wiring**: `build_manager_service` passes `lead_sessions_root`/`workspace_root`
  (`ctf_solver/wiring.py:177-178`).
- **§4.1 service**: kw-only ctor args (`ctf_solver/manager/service.py:114`),
  `create_task(..., lead_session_id)` (`:737,747`), `ingest_session_log(..., source="auto")`
  (`:1902`), completion auto-ingest (`:1447,1645`), screenshot step derivation
  (`:1797,1836`), runtime-status surface (`:2023,2053`), updated ROUND1 limits/ROUND2
  security strings.
- **§4.2 MCP**: exactly 18 tools, same names; `ctf_task_create.lead_session_id`
  `maxLength=128` (`ctf_solver/mcp/manager_server.py:98-100`); `ctf_session_ingest.source`
  enum `["auto","worker","lead"]` default `auto` (`:325`); no tool accepts a path or an
  arbitrary session id; `--lead-sessions-root` wired.
- **§4.3 CLI**: `manager serve --lead-sessions-root/--session-log-root`
  (`ctf_solver/cli.py:37,39,281,289`); `task --lead-session-id/--lead-sessions-root`
  (`:345,354`).
- **§5.1 screenshot**: `Add-Type -AssemblyName System.Windows.Forms` immediately after
  `System.Drawing` (`ctf_solver/delivery/screenshot.py:521`); 12-line stderr tail (`:34`);
  UTF-8→GBK→latin-1 decode (`:37`); subprocess no longer forces `text=True/encoding`.
- **§5.2 writeup**: completion-note subsection (`ctf_solver/delivery/writeup.py:297`),
  turn/step heading suffix (`:379`), derived step-id screenshot matching (`:125,147`),
  intake notes printed once in section 1, no duplication in section 2; final-freeze actor
  honesty: `_tool_call_actor` (`:59-70`) renders Lead tool calls as `Lead initiated` while
  Worker evidence keeps `Worker initiated`.
- **§5.3 bundle**: post-build internal `verify_zip` with temp extraction and
  `DeliveryError` on failure (`ctf_solver/delivery/bundle.py:258-266`); raw Lead log from
  CAS under `raw/session-<sha16>.jsonl.zstd` (`:206`).
- **§5.4 skills**: 6 SKILL.md files UTF-8/no BOM; ctf-solver rewritten (Lead executor,
  18-tool table `:27`, category routing hard step `:163`); 5 category skills carry the
  ≤5-line evidence paragraph (`ctf-web` etc. `:53`).
- **Dependency freeze**: `[project].dependencies == []`, only dev extra `pytest>=8`;
  `pyproject.toml`/lock files absent from the `21908de..HEAD` diff; added import
  statements in `ctf_solver/`+`tests/` scan to stdlib/local only; no `print()` added to
  library code; all 35 changed source files (ctf_solver/tests/skills/docs) valid UTF-8
  without BOM; raw Lead-owned evidence artifacts excluded from the source-encoding rule.

## 6. Adversarial security + service behaviour (29/29 PASS)

- **C01** 14 path/session injection ids (`../`, `..\`, drive letters, absolute paths,
  separators, `:`, NUL, newline, over-length, `\\server`) → `unknown_session` before
  binding; nothing written.
- **C02** absent id → `log_missing`. **C03** unbound Task cannot use `source=lead`
  (`no_binding`); unknown source → `ValidationError`.
- **C04** `validate_lead_candidate` returns the raw-bytes SHA-256; binding stores it; only
  the bound Task resolves that session.
- **C05** duplicate bind (same Task twice, same session twice) → `StateError`; unknown
  Task → `NotFoundError`; raw SQL confirms PK/UNIQUE/FK enforcement, exactly one row.
- **C06/C07** header id mismatch → `header_mismatch`; cwd mismatch → `lead_cwd_mismatch`;
  cwd check skipped only when the resolver has no `workspace_root` (test-only allowance).
- **C08** `None`/missing Lead root → `lead_sessions_root_missing`.
- **C09** two logs → `ambiguous_session_log`; none → `log_missing`.
- **C10** tampered registry row with unsafe bound id → `unknown_session`.
- **C11/C12/C13** worker path unchanged; `auto` prefers the binding when no explicit
  `worker_id`; one-time binding + both reverse-map directions.
- **C14** real NTFS **junction** created by the verifier is rejected
  (`symlink_rejected`); plain symlink case environment-skipped (no elevation).
- **D01–D14** service flows on a real `EvidenceStore` + deterministic fakes: create binds
  the verified session (`task_created{lead_session_id, notes}` then `lead_session_bound`);
  invalid candidates fail before persistence; duplicate session rejected without a Task;
  cwd mismatch rejected; `source=lead` ingest redacts paths; re-ingest `appended=0`, no
  duplicate evidence records, chain ok; auto→lead when bound, worker→worker,
  bogus→`ValidationError`; worker-only unchanged; completion persists `completion_note`
  without double-ingest and is idempotent; completion auto-ingests a never-ingested bound
  Lead log exactly once; default screenshot `step_id` derives from the newest ingested
  tool_call (`turn5-step3`), explicit ids kept, no tool call → `None`; **live-defect
  regression**: after `complete_task` with intake `notes`, `tasks.notes` is byte-identical
  (ORM + raw SQL) while `tasks.completion_note` holds the outcome; `COMPLETION_PENDING`
  writes only `completion_note`; pause/cancel never mutate `notes` and record
  `pause: …`/`cancel: …` in `completion_note`.
- **E01/E02 worker parity vs base `21908de`**: 6 scenarios (unknown task, no worker, missing
  root, missing log, header mismatch, valid) produce identical ok/reason_code/message/
  worker_id outcomes; only the new default field `source="worker"` differs.

## 7. Real-DB migration + delivery determinism (12/12 PASS)

- **F01** Genuine pre-Round-1 1.1 database snapshot
  `scratch/lead-round1-plan/manager-pre-round1.sqlite` (schema 1.1, 12 tables, 2 real
  Tasks, 18 real events) copied through a `mode=ro` SQLite backup — the live
  `manager.sqlite` was already migrated to 1.2 by the Lead's live run, so this backup is
  the authoritative 1.1 source.
- **F02** After `initialize_schema` on the copy: `schema_version=1.2`, `completion_note`
  + `session_bindings` added, all 12 pre-existing tables keep identical row counts.
- **F03** All 22 rows in tasks/workers/approvals/network_grants/events byte-identical;
  `completion_note` defaults to `''` for migrated Tasks.
- **F04** Hash chain independently recomputed (`verification_helpers.recompute_chain`) and
  matches stored hashes + protected head; `EvidenceStore.chain_status()` ok over 18 events.
- **F05** Source 1.1 backup byte-identical before/after (SHA-256) and still 1.1.
- **F06** Live DB (already 1.2) snapshot: chain recomputes over 1097 events, 4 Tasks,
  2 session bindings, no NULL `completion_note`; observation in
  `work/migration/live_observation.json`.
- **G01** Two writeup builds byte-identical: SHA-256
  `5f698547d58905aa419cf207fafefddc7e6b703b66ba047c7689558e650a0aee` (4564 bytes).
- **G02** Intake notes exactly once (section 1), completion note once (2.1), no duplication.
- **G03** Tool-call heading carries recorded `(turn 2, step 3)` and the final-freeze actor
  label (`Lead initiated` for `worker_id NULL` evidence); derived-step screenshot attached
  under its step. (Known cosmetic note: a synthetic fixture containing both a Manager
  `execution_started` and a Lead `tool_call` for the same step lists the screenshot under
  each matching section; real Lead-native flow records only `tool_call`; rendering is
  deterministic.)
- **G04** Two ZIP builds byte-identical: SHA-256
  `82bb2a6d1bd8be8dfcb3cda474880c65968d3ac003d8a236f7a8d9aab6aa23f2` (4486 bytes);
  internal `verify_zip` ok; members include `writeup.md`, this Task's `events.jsonl`,
  `screenshots/shot-1.png`, `raw/session-<sha16>.jsonl.zstd` (raw bytes preserved).
- **G05** Forced manifest failure → `DeliveryError` (fail closed); **G06** final ZIP still
  verifies after the forced-failure test.

## 8. Deviations / limitations / risk notes

1. **Resolved pre-fix blocker** (evidence-only): three committed raw JUnit XMLs violated
   the repo's committed-JUnit gate at `726e741`; removed in `48a70da`, gate now 2 passed.
2. **Post-freeze amendment (Lead-authorised)**: `set_task_status` gained
   `completion_note` (frozen §3.4 said "unchanged semantics"). Verified positively by
   D13/D14 + AST A08b; it is what fixes the live completion-note defect.
3. **`auto` + explicit `worker_id`**: the clarified rule ("Lead binding wins for auto")
   applies when `worker_id` is not supplied; an explicit `worker_id` selects the Worker log
   even when bound (documented in the resolver docstring, C12). No impact on the MCP
   default path (`auto`, no worker_id).
4. **Reason-code ordering for `source=lead`**: missing Lead root is reported before a
   missing binding (`lead_sessions_root_missing` vs `no_binding`); both stable, fail-closed,
   independently covered (C03/C08).
5. **Screenshot dual-listing cosmetic note** from §7/G03 (synthetic-only input).
6. **Link/junction tests**: plain symlink creation requires elevation on this host, so the
   repo's own two symlink tests are skipped; the verifier compensated with a real NTFS
   junction (rejected, C14).
7. **Store-level binding input**: `bind_lead_session` enforces only non-empty ids; path/
   header/cwd validation is the resolver's boundary, and a tampered unsafe registry row is
   rejected at resolution (C10).
8. **Create-task race window**: duplicate/foreign bindings are pre-checked and the store
   raises on conflict (fail closed); a lost race could leave the just-created Task row
   without a binding (single-threaded MCP path cannot hit it). Low risk.
9. **Real DB state**: the live `manager.sqlite` is already schema 1.2 (migrated by the
   Lead's live run); the 1.1→1.2 acceptance evidence therefore used the genuine
   pre-Round-1 1.1 backup. Source files were never modified (F05).
10. **Raw evidence encodings**: Lead-owned console/config captures include UTF-16LE and
    BOM'd files; the contract's UTF-8/no-BOM source rule is applied to source/tests/
    skills/docs only (A19), not to raw data artifacts.

## 9. Frozen-state and baseline evidence commands

```
git -C D:\CTF-SOLVER\scratch\lead-round1 rev-parse HEAD        -> 48a70da47713933b87deb0027709a020f218f75b
git -C D:\CTF-SOLVER\scratch\lead-round1 rev-parse HEAD^{tree} -> 3047e79dd162b5e0cb184d5c4d1aee64e8f9f7cc
git -C D:\CTF-SOLVER\scratch\lead-round1 status --porcelain    -> (empty)
git -C D:\CTF-SOLVER\scratch\lead-round1 log --oneline -3      -> 48a70da / 726e741 / 340d6b5
git -C D:\CTF-SOLVER\scratch\lead-round1 diff --name-only 726e741 48a70da -- ctf_solver tests .dsh pyproject.toml -> (empty)
git -C D:\CTF-SOLVER\scratch\lead-round1 diff --stat 726e741..48a70da -> evidence-only (lead-session-evidence/)
base-checkout HEAD                                             -> 21908de0dd52099f9f90c1cead6f94445f1d3a1d
```

## 10. Verifier artifacts (all under `scratch\lead-round1-plan\verifier\`)

- Scripts: `phase2_contract_deps.py`, `phase2_security.py`,
  `phase2_migration_determinism.py`, `phase2_worker_scenarios.py`.
- Final raw outputs: `FINAL2_full_pytest.txt`, `FINAL2_junit_gate.txt`,
  `FINAL2_focused_pytest.txt`, `FINAL2_targeted_pytest.txt`, `FINAL2_skills.txt`,
  `FINAL2_contract_deps.txt`, `FINAL2_security.txt`, `FINAL2_migration_determinism.txt`,
  `FINAL2_baseline_drift_base.txt`.
- Pre-fix evidence (kept for audit): `FINAL_*.txt`, including the BLOCKED-proof
  `FINAL_junit_test.txt`, `FINAL_junit_base_checkout.txt`,
  `FINAL_junit_remediation_sim.txt` and `FINAL_full_pytest_sim_after_fix.txt`.
- Machine-readable: `phase2_contract_deps.json`, `phase2_security.json`,
  `phase2_migration_determinism.json` (re-generated on `48a70da`); migration
  snapshot/observation under `work/migration/`.
- Plan/history: `PLAN.md`; this report.

## 11. Post-verification note

The Lead will copy this final PASS report into the evidence trail as a final evidence-only
commit and regenerate the bundle; that change is text/evidence only and does not alter the
product tree, tests, or Skills verified here. No further product verification is required
for Round 1.

*Report generated by verifier-r1 from the final frozen tree at HEAD 48a70da; product/tests
were never edited by the verifier.*
