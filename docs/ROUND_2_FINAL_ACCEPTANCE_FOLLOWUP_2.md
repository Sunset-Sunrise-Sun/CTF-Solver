# CTF-Solver Final Acceptance Follow-up 2 Report

**Status:** final scope-limited acceptance remediation candidate
**Repository:** `D:\CTF-SOLVER`
**Branch:** `fix/final-acceptance-followup-2` (created from the exact baseline; no history rewrite)
**Baseline HEAD:** `d473e7d5c795f43b466c47342bc4507f89af13ca`
**Implementation commit:** `fe48330ce8170466ff455282b8f95a65193b6240`
**Report commit:** the child commit containing this report and the regenerated manifest
**Round 1:** `feat/round1-complete-product-core` @ `e40f76f317ec3f3186e0120744af2f5924d32721`
**Round 2:** `feat/round2-harness-integration` @ `d38845366075c57f5840127b93bfd58c9c9e24f3`

This is the last final-acceptance remediation. No third development round, no product
feature, no frozen-architecture/authorization-boundary change.

---

## A. Baseline

| Item | Result |
|---|---|
| Branch before work | `fix/final-acceptance-followup` |
| HEAD before work | `d473e7d5c795f43b466c47342bc4507f89af13ca` (exact) |
| Worktree incl. untracked | clean |
| Round 1 HEAD | `e40f76f…` unchanged |
| Round 2 HEAD | `d388453…` unchanged |
| Prior final-hardening/Followup history | present; no amend/rebase/reset/rewrite |
| Original Bundles | all five existing `.bundle` files retained; prior final-hardening `2D5D27B2…EEC74C` unchanged; no overwrite |
| PR #1 | Open / `draft=true` / `merged=false` (read-only check) |

New branch: `fix/final-acceptance-followup-2` from the exact baseline.

---

## B. Three issues: reproduction, root cause, fix, tests

### P0-A — restart recovery must update Task and Worker atomically

**Problem/reproduction.** `recover()` first wrote Worker=STOPPED and then Task=INTERRUPTED;
`_recover_completion_pending()` did the same for the no-evidence case. With a real SQLite
trigger blocking the Task UPDATE, the baseline produced
(`round2-evidence/raw/hardening-followup2-repro-before.txt`):

```
GENERIC_RECOVERY_RAISED IntegrityError repro: interrupted update blocked
GENERIC_RECOVERY_REPRO t1= running worker1= stopped active_slots= 1 queued= queued t3_worker= False
PENDING_RECOVERY_REPRO task= completion_pending worker= stopped active_slots= 0
```

So the Worker slot was released while the Task stayed RUNNING/completion_pending, and the
generic recovery also leaked an unhandled SQLite error.

**Root cause.** Worker and Task status were separate writes with Worker first; failure of
the Task write left the Worker stopped and the slot free.

**Files.** `ctf_solver/manager/store.py`, `ctf_solver/manager/service.py`,
`tests/test_round2_recovery_atomic.py`.

**Fix.** New `ManagerStore.finalize_task_interruption(task_id, expected_status,
result_state, ended_at, notes, worker_id)`:
- one SQLite transaction;
- Task status CAS against the exact current/expected status;
- UPDATE Task to INTERRUPTED and its Worker to STOPPED; both row counts checked;
- any failure rolls the whole transaction back (Task keeps original state, Worker keeps
  the occupied slot);
- no FIFO pump before the transaction commits;
- a Task without a Worker is explicitly handled Task-only (no fake Worker update).

Both recovery paths use it: generic active-Task recovery and completion_pending without
valid completion evidence. Recovery catches and records DB/state failures as diagnostics
and returns the **actual** status; it never reports a fake interrupted success. Failure
keeps Task and Worker untouched and FIFO unadvanced; a later `recover()` retries safely.

**Tests (real SQLite triggers, real ManagerStore/EvidenceStore).**
`hardening-followup2-atomic-tests.txt`, exit 0, 8 passed:
Task update failure → Worker rollback; Worker update failure → Task rollback;
completion_pending no-evidence failure → Task pending + Worker slot; full FIFO
(2 active + 1 queued) with both interruption UPDATEs blocked → no early Worker/Session
and queued Task stays QUEUED; after trigger removal recovery succeeds and the FIFO Task
starts exactly once; repeated pump creates no duplicate; no-Worker Task handled Task-only.

### P0-B — completed Task evidence_head must be immutable

**Problem/reproduction.** `_refresh_evidence_head()` unconditionally wrote the current
global `chain_head()` to the Task row. After completing Task A, creating Task B and
appending B evidence, an ordinary `get_task_status(A)` overwrote A's historical anchor;
the subsequent idempotent completion failed (baseline log):
`EVIDENCE_HEAD_OVERWRITE_REPRO ... overwritten= True`,
`IDEMPOTENT_AFTER_QUERY_FAILED StateError completed Task evidence_head does not match its
completion event anchor`.

**Root cause.** A historical task-completion snapshot was refreshed with the advancing
global append head; no completed-state condition or atomic conditional update existed.

**Files.** `ctf_solver/manager/store.py`, `ctf_solver/manager/service.py`,
`tests/test_round2_evidence_head_immutability.py`.

**Fix.** New `ManagerStore.update_evidence_head_if_not_completed(task_id, head)` performs a
single conditional SQL UPDATE with `WHERE status != 'completed'`, so a refresh can never
overwrite a completion anchor even if the Task completes between read and write.
`_refresh_evidence_head()` uses this conditional API. `get_task_status`,
`build_writeup`, `export_evidence_zip` therefore leave completed snapshots untouched.
`_verify_completed_task_evidence()` still requires anchor == the unique
`task_completed.record_hash`; verification was not weakened.

**Tests (real SQLite + real EvidenceStore).** After completion of A and multiple later B
appends/global-head changes: `get_task_status(A)`, `build_writeup(A)`,
`export_evidence_zip(A)` all keep A COMPLETED with the original anchor; A's completion
event remains unique; chain intact; idempotent completion returns already_completed.
Conditional refresh writes a running Task but returns False/no-write for a completed
Task; direct anchor tamper still fails closed.
Result: `hardening-followup2-atomic-tests.txt`, exit 0 (3 evidence-head tests included in
the 8 passed above; the log covers the combined suites).

### P1 — reproducible Wheel provenance tied to the final Bundle

**Problem/reproduction.** The previously delivered wheel evidence
`hardening-followup-final-canonical-wheel-build.json` recorded build HEAD
`adba48a67efa557666fc3d837497c2cc926a7322`, which is **not reachable** from the current
Bundle history (`WHEEL_PROVENANCE_REPRO build_head_reachable_from_current_bundle= False`).
The wheel bytes were consistent, but provenance was not acceptable.

**Files.** new `scripts/verify_wheel_provenance.py`; corrected
`round2-evidence/raw/hardening-followup-final-canonical-wheel-build.json`; new
`hardening-followup2-wheel-provenance.json` and
`hardening-followup2-wheel-build.json`.

**Fix.** The wheel is rebuilt in a fresh clone at the exact implementation commit
`fe48330…` (which is an ancestor of the final report commit and therefore inside the
final Bundle history). `scripts/verify_wheel_provenance.py` verifies:
- checkout HEAD == expected commit and no tracked modifications;
- every wheel `ctf_solver/**.py` byte is identical to the Git blob at that commit, and
  every tracked source file is present;
- RECORD hashes/sizes for all members;
- extracted-wheel imports and `python -m ctf_solver version`.

The corrected provenance is recorded with actual HEAD, branch, Python 3.14.7, build
command, size and SHA-256; the old evidence file is replaced with this valid provenance
(content correction, not history rewrite). Final Bundle clone rebuild reproduced the same
wheel SHA-256 (see D).

**Result:** provenance verification exit 0 (`verify_wheel_provenance.py`), wheel
**223,327 B**, SHA-256 **`B8E4D112A351A633E87C1DB4C0101422EA34A6B35721D730B7DADC1D7B72BB21`**
(64 members, RECORD/import/version/source bytes all verified). No unresolved limitation.

---

## C. Regression results

| Test item | Passed | Skipped | Failed | Exit code |
|---|---:|---:|---:|---:|
| New atomic recovery + evidence-head suites | 8 | 0 | 0 | 0 |
| Existing completion lifecycle/fault suites + approval attacks + ACP matrix (focused) | 50 | 0 | 0 | 0 |
| Full default suite | **1023** | 4 | 0 | 0 |
| Full suite + zero-model real ACP smoke | **1024** | 3 | 0 | 0 |
| Real Harness integration (zero model calls) | 43/43 checks | — | 0 | 0 |
| Final clean clone (default) | **1023** | 4 | 0 | 0 |
| Final Bundle clone (default) | **1023** | 4 | 0 | 0 |
| Final clean clone + real ACP smoke | **1024** | 3 | 0 | 0 |
| JUnit XML verification (16 tracked XML files vs logs) | 16/16 | 0 | 0 | 0 |

Raw evidence: `hardening-followup2-full-default.txt`,
`hardening-followup2-full-with-real-acp.txt`, `junit-followup2-default.xml`,
`junit-followup2-with-real-acp.xml`, `hardening-followup2-atomic-tests.txt`,
`hardening-followup2-integration.txt`, final clean-clone/Bundle-clone logs and JUnit.
No test was removed, weakened, or converted to skip.

---

## D. Deliverables

| Deliverable | Path | Size | SHA-256 | Verification |
|---|---|---|---:|---|
| New Bundle | `D:\CTF-SOLVER-review\CTF-Solver-Final-Acceptance-Followup-2.bundle` | recorded in final delivery message | recorded in final delivery message | verify exit 0; clone fsck/manifest/tests/wheel checks |
| New Wheel | `D:\CTF-SOLVER\dist\ctf_solver-0.1.0-py3-none-any.whl` | **223,327 B** | **`B8E4D112A351A633E87C1DB4C0101422EA34A6B35721D730B7DADC1D7B72BB21`** | clean clone of `fe48330`; provenance script OK; Bundle clone rebuild identical |
| Final manifest | `D:\CTF-SOLVER\round2-evidence\FINAL_FILE_MANIFEST.txt` | actual file | Git blob bytes | **329 entries / 330 tracked files** (manifest self-excluded); 0 missing/hash/size mismatch in clean clone |
| Final report | `D:\CTF-SOLVER\docs\ROUND_2_FINAL_ACCEPTANCE_FOLLOWUP_2.md` | this file | — | — |
| Repro-before log | `round2-evidence/raw/hardening-followup2-repro-before.txt` | — | — | pre-fix reproduction |
| New test log | `round2-evidence/raw/hardening-followup2-atomic-tests.txt` | — | — | exit 0 |
| Full logs/JUnit | `hardening-followup2-full-*`, `junit-followup2-*.xml` | — | — | exit 0 |
| Wheel provenance | `round2-evidence/raw/hardening-followup2-wheel-provenance.json`, `hardening-followup2-wheel-build.json`, corrected `hardening-followup-final-canonical-wheel-build.json` | — | — | build HEAD `fe48330`; source/RECORD/import/version verified |
| JUnit verification | `hardening-followup-junit-verify.txt`, `junit-xml-verification.json` | — | — | 16 XML parse and count-match |
| Privacy | `privacy-scan-before.json`, `privacy-scan-after.json`, `privacy-redaction-before.json` | — | — | final tree 0 personal home paths; 0 real credentials |

The final Bundle is generated from the report commit; because a bundle cannot contain its
own SHA-256, its size and SHA-256 are recorded in the final delivery message. All other
hashes above are embedded and reproducible.

---

## E. Final state

| Item | State |
|---|---|
| FAIL | **None** |
| BLOCKED | External-delivery canary (requires authorized model request); model-mediated Worker/`session/prompt` (ADR-020); main-conversation `/ctf-solver` → Manager MCP entrypoint (no supported project-scoped registration); Tier 2 isolation/real targets/challenge execution |
| NOT VERIFIED | Real physical-console TTY confirmation; same-child ACP-spawned `tools/call` (zero-model-call gate) |
| Uncommitted changes | none after final report/manifest commits |
| Pushed | no |
| PR modified | no (PR #1 remains Draft/open/unmerged) |
| Protected environment | `D:\CTFworker` fingerprint `C944E18C…622592A7`, audit SHA-256 `955136d1…fe5373`, `~/.dsh/profiles` 775 files/max mtime `2026-11-10T01:52:31` unchanged |
| Model calls / `session/prompt` | 0 / 0 |
| Round 1 / Round 2 / prior history | unchanged; no amend/rebase/reset/rewrite |
| Original Bundles | not overwritten |

No BLOCKED or NOT VERIFIED item is reported as PASS.
