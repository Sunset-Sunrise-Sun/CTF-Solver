# CTF-Solver Final Acceptance Report

**Status:** final patch candidate for independent acceptance
**Repository:** `D:\CTF-SOLVER`
**Branch:** `fix/final-acceptance-final-patch` (created from the exact baseline)
**Baseline HEAD:** `22b6b6f158bfb046760bfb408ec6a53005eafe26`
**Implementation commit:** `25d6eefd7e58c9233971a8fba8c43ad17bd27a37`
**Report commit:** the child commit containing this report and the regenerated manifest
**Round 1:** `e40f76f317ec3f3186e0120744af2f5924d32721`
**Round 2:** `d38845366075c57f5840127b93bfd58c9c9e24f3`

This is the final code-fix round: two remaining acceptance issues, complete regression and final delivery. No new development phase, product feature, frozen-architecture, approval-model or security-boundary change.

---

## 1. Baseline and protection

| Item | Result |
|---|---|
| Baseline branch | `fix/final-acceptance-followup-2` |
| Baseline HEAD | `22b6b6f…` (exact match) |
| Worktree before work | clean (incl. untracked) |
| Baseline Bundle | `CTF-Solver-Final-Acceptance-Followup-2.bundle`, 1,040,190 B, SHA-256 `4D8272FB2881B312352D9AFBC992CADBE8E9AC0374FFD06602C747480AFA68D6` (retained, not overwritten) |
| Baseline Wheel | 223,327 B, SHA-256 `B8E4D112…BB21` (retained as historical baseline) |
| All six prior Bundles | present, SHA-256 unchanged |
| Round 1 / Round 2 / prior Followups | unchanged |
| PR #1 | Open / `draft=true` / `merged=false` (not modified) |

Only additive commits were created in this round; no amend/rebase/reset/history rewrite.

---

## 2. P0 — completion_pending anchor overwrite race

### Reproduction before fix

`ManagerStore.update_evidence_head_if_not_completed()` used `WHERE status != 'completed'`.
During completion, after the Task enters `completion_pending`, writes the unique
`task_completed` event and persists its `record_hash` as the anchor, but before the final
transaction updates status to `completed`, an ordinary refresh could replace that anchor
with the advancing global `chain_head()`. The deterministic interleaving test reproduces
this on the previous implementation: the anchor changes while the Task is
`completion_pending`, and the final idempotent verification then fails.

### Root cause

The conditional UPDATE excluded only `completed`; the `completion_pending` window had
already persisted the immutable completion anchor and must also be excluded.

### Fix

`ctf_solver/manager/store.py`:
`ManagerStore.update_evidence_head_if_not_completed()` now uses a single SQL UPDATE:

```sql
UPDATE tasks SET evidence_head = ?, updated_at = ?
WHERE task_id = ? AND status NOT IN ('completed', 'completion_pending')
```

The condition is evaluated atomically inside SQLite, so a refresh that read RUNNING
before completion began still cannot write after the Task enters `completion_pending`.
`ctf_solver/manager/service.py` continues to call only this conditional interface from
`_refresh_evidence_head()`; `get_task_status`, `build_writeup` and `export_evidence_zip`
therefore cannot alter a completion anchor. `_verify_completed_task_evidence()` was not
relaxed: the anchor must equal the unique `task_completed` event's `record_hash`.

### Deterministic interleaving test (real SQLite + real EvidenceStore)

`tests/test_round2_evidence_head_immutability.py::test_completion_pending_anchor_survives_interleaved_refresh`:
1. complete Task A in a worker thread;
2. block the final `finalize_task_completion` transaction with threading Events;
3. deterministically observe Task A in `completion_pending` with its unique
   `task_completed` event and persisted anchor;
4. append Task B evidence (global head advances);
5. call `get_task_status(A)`, `build_writeup(A)`, `export_evidence_zip(A)`;
6. directly call the ordinary refresh interface and require it to return False;
7. assert A's anchor is unchanged;
8. release the completion transaction; A becomes completed; idempotent completion returns
   `already_completed`; exactly one completion event; chain intact.

No random sleeps. Also added negative test that `completion_pending` refresh is refused,
and retained all previous completed-anchor/ordinary-operation tests.

---

## 3. P1 — Wheel RECORD/provenance verification

### Problem

The provenance checker's RECORD comparison was format-wrong: Wheel RECORD stores
`sha256=<urlsafe-base64(unpadded)>`, not a hex digest, and the checker also did not parse
the algorithm or reject malformed/empty hashes for normal members.

### Fix

`scripts/verify_wheel_provenance.py` now:
- parses every RECORD field as `<algorithm>=<urlsafe-base64>`;
- only supports `sha256`, explicitly failing unsupported algorithms;
- validates base64 (URL-safe, unpadded, canonical round-trip);
- recomputes the digest by algorithm and compares raw digest bytes;
- validates size and missing/extra members;
- accepts empty hash/size only for the RECORD self-entry, and requires every other
  member to have a valid hash and size;
- tampered wheel content is detected.

`tests/test_wheel_provenance.py` (9 tests) covers valid SHA-256, wrong digest, wrong size,
missing RECORD member, extra wheel member, unsupported/malformed hash, RECORD self-entry
special fields, content tampering, and the formal 64-member wheel (`63` hashed members +
RECORD) validating completely.

### Rebuilt provenance

Final wheel was built in a clean clone of implementation commit
`25d6eefd7e58c9233971a8fba8c43ad17bd27a37` (reachable from the final Bundle):
- repository/branch/HEAD: `D:\CTF-SOLVER` build clone, `fix/final-acceptance-final-patch`,
  `25d6eef…`;
- clean tracked checkout at build start;
- Python 3.14.7; command `python scripts/build_wheel.py`;
- RECORD ok (`63` members hashed + RECORD), source bytes identical (60/60 Python files),
  imports ok, `python -m ctf_solver version` → `ctf-solver 0.1.0`;
- Wheel **223,346 B**, SHA-256
  **`84249381FFA058B2273B7E062E3A10ACE0DC1451A44541357F02D44C34952705`**.

The evidence files now all agree on this build:
`hardening-followup2-wheel-build.json`,
`hardening-followup2-wheel-provenance.json`,
`hardening-followup-final-canonical-wheel-build.json`,
`hardening-followup-final-wheel-provenance.json`, and this report. An independent final
Bundle clone rebuild produced the same SHA-256. Historical test logs were not modified.

---

## 4. Verification evidence

| Run | Result | Exit | Evidence |
|---|---|---|---|
| New final-patch suites (interleaving, recovery, Wheel provenance) | **18 passed** | 0 | `finalpatch-atomic-wheel-tests.txt` |
| Full default suite | **1033 passed, 4 documented skips, 0 failed** | 0 | `finalpatch-full-default.txt`, `junit-finalpatch-default.xml` |
| Full suite + zero-model real ACP smoke | **1034 passed, 3 skips, 0 failed** | 0 | `finalpatch-full-with-real-acp.txt`, `junit-finalpatch-with-real-acp.xml` |
| Real Harness integration (zero model calls) | **43/43 PASS** | 0 | `round2-integration.log`, `round2-integration-summary.json` |
| Final clean clone (default) | **1033 passed / 4 skipped** | 0 | final clone logs/JUnit |
| Final clean clone + real ACP | **1034 passed / 3 skipped** | 0 | final clone logs |
| Final Bundle clone (default / real ACP) | **1033/4**, **1034/3** | 0 | Bundle clone logs |
| JUnit XML verification | **19 tracked XML files parsed and count-matched** | 0 | `hardening-followup-junit-verify.txt`, `junit-xml-verification.json` |

No test was deleted, weakened, or converted to skip.

---

## 5. Deliverables

| Deliverable | Path | Size | SHA-256 | Verification |
|---|---|---|---:|---|
| Final Bundle | `D:\CTF-SOLVER-review\CTF-Solver-Final-Acceptance.bundle` | recorded in final message | recorded in final message | `git bundle verify`; independent clone HEAD/fsck/manifest/tests/wheel |
| Final Wheel | `D:\CTF-SOLVER\dist\ctf_solver-0.1.0-py3-none-any.whl` | **223,346 B** | **`84249381FFA058B2273B7E062E3A10ACE0DC1451A44541357F02D44C34952705`** | built from `25d6eef` clean clone; provenance/RECORD/source/import/version OK; Bundle clone rebuild identical |
| Final Manifest | `D:\CTF-SOLVER\round2-evidence\FINAL_FILE_MANIFEST.txt` | actual | Git-blob bytes | **343 entries / 344 tracked files** (manifest self-excluded); 0 missing/hash/size mismatch in clean clone |
| Final report | `D:\CTF-SOLVER\docs\FINAL_ACCEPTANCE_REPORT.md` | this file | — | — |
| Repro/interleaving log | `round2-evidence/raw/finalpatch-atomic-wheel-tests.txt`, `finalpatch-*.txt` | — | — | exit 0 |
| Wheel evidence | `hardening-followup2-wheel-build.json`, `hardening-followup2-wheel-provenance.json`, `hardening-followup-final-canonical-wheel-build.json`, `hardening-followup-final-wheel-provenance.json` | — | — | build HEAD `25d6eef`; all agree |
| JUnit/logs | `junit-finalpatch-*.xml`, `finalpatch-full-*`, final clone logs/JUnit | — | — | exit 0 |
| Privacy | `privacy-scan-*.json`, `privacy-redaction-before.json` | — | — | final tree 0 personal home paths; 0 real credentials |

Because a Bundle cannot contain its own SHA-256, the final Bundle size/hash is recorded in
the delivery message; all other hashes are embedded and reproducible from the committed
tree.

---

## 6. Final state

- **FAIL: none.**
- **BLOCKED:** external-delivery canary (requires authorized model request); model-driven
  Worker/`session/prompt` (ADR-020); main-conversation `/ctf-solver` → Manager MCP
  entrypoint (no supported project-scoped registration; owner decision); Tier 2
  isolation/real targets/challenge-code execution.
- **NOT VERIFIED:** real physical-console TTY confirmation; same-child ACP-spawned
  `tools/call` under the zero-model-call gate.
- Worktree clean; no uncommitted changes after the final manifest commit.
- No push, no PR creation/merge; PR #1 untouched.
- Protected environment unchanged: `D:\CTFworker` fingerprint `C944E18C…622592A7`, audit
  SHA-256 `955136d1…fe5373`, `~/.dsh/profiles` 775 files/max mtime
  `2026-11-10T01:52:31`; no runtime directories; no stray profile.
- Zero model calls and zero `session/prompt`.

No BLOCKED/NOT VERIFIED item is reported as PASS.
