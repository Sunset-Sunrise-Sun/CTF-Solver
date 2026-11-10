# CTF-Solver Final Acceptance Follow-up Report

**Status:** final acceptance follow-up candidate for independent review
**Repository:** `D:\CTF-SOLVER`
**Branch:** `fix/final-acceptance-followup` (new local branch; history not rewritten)
**Baseline HEAD:** `d5bb4778268e7b1364bfe90a7fe3f4e7789f144e`
**Follow-up implementation commit:** `de6e6704f1848427258729164eb69423472493c8`
**Report commit:** the child commit containing this report and the regenerated manifest (local only; no push/PR/merge)
**Round 1 preserved:** `feat/round1-complete-product-core` @ `e40f76f317ec3f3186e0120744af2f5924d32721`
**Round 2 preserved:** `feat/round2-harness-integration` @ `d38845366075c57f5840127b93bfd58c9c9e24f3`

This is a final acceptance follow-up, not a third development round. No architecture,
product scope, approval interaction or authorization model was changed.

---

## A. Baseline

| Item | Result |
|---|---|
| Branch before work | `fix/round2-acceptance-remediation` |
| HEAD before work | `d5bb4778268e7b1364bfe90a7fe3f4e7789f144e` (exact match) |
| Worktree incl. untracked | clean |
| Round 1 head | `e40f76f317ec3f3186e0120744af2f5924d32721` (unchanged) |
| Round 2 head | `d38845366075c57f5840127b93bfd58c9c9e24f3` (unchanged) |
| Final hardening commit in history | `7583849…` ancestor of baseline |
| Original final Bundle | `CTF-Solver-Round2-Final-Hardening.bundle`, 934,688 B, SHA-256 `2D5D27B2F3012293AA46CBDE5F9622B42A8F0537B0F422D1B00F8B8BC2EEC74C` (checked before work; not overwritten) |
| PR #1 | open, `draft=true`, `merged=false` (read-only API check) |

New branch: `fix/final-acceptance-followup` from the exact baseline SHA.

---

## B. Four issues: reproduction, root cause, fix, tests

### P0-1 — cross-Task duplicate/conflicting approval decision events

**Original problem:** approval decision uniqueness was checked by listing
`approval_decided` events filtered to the current Task. A duplicate or conflicting
event for the same `approval_id` filed under another Task was therefore invisible.

**Reproduction (before fix):**
`round2-evidence/raw/hardening-followup-repro-before.txt`:
`CROSS_TASK_APPROVAL_BUG_REPRODUCED grant_created=…` — after approving port 8443 in
Task A, a conflicting decision event for the same approval id was appended under Task B
and grant creation **succeeded** on the baseline.

**Root cause:** `ApprovalGrantService._decision_events()` called
`evidence.list_events(task_id=record.task_id, event_type="approval_decided")`; global
uniqueness was never checked.

**Files:** `ctf_solver/manager/approval_grant_service.py`;
`tests/test_round2_acceptance_hardening.py`.

**Fix:** decision events are now listed **globally** (`event_type=approval_decided`,
no Task filter) and filtered by `approval_id`; exactly one event is required.
The event row `task_id` and payload `task_id` must both equal the approval Task, and the
other fields (approved, action_digest, confirmation_id/os_user, local_console channel)
are checked as before. Chain status must be intact. All cross-Task duplicates,
byte-identical duplicates, conflicting fields, rewritten task_id events and damaged
chains fail closed before approval consumption.

**Tests added (real SQLite ManagerStore + real EvidenceStore):**
cross-Task duplicate event, cross-Task byte-identical duplicate, event row Task B with
payload task_id Task A, legitimate approval still creates exactly one grant. Existing
same-Task duplicate/replay/tamper/chain-damage tests remain.

**Result:** `hardening-followup-approval.txt`, exit 0, **17 passed**. No unresolved
limitation beyond the already documented threat-model boundary (whole SQLite + full chain
consistent rewrite is not defeated without an external anchor).

---

### P0-3A — completion failure must not release the Worker slot

**Original problem:** finalization stopped the Worker (slot released) and then persisted
the completed Task status. If the Task status write failed, the call raised but the Task
stayed `completion_pending` with Worker `STOPPED` and active slots 0, allowing FIFO
admission despite an incomplete Task.

**Reproduction (before fix):** `hardening-followup-repro-before.txt`:
`SLOT_BUG_REPRODUCED StorageError task_status=completion_pending worker_status=stopped
active_slots=0`.

**Root cause:** separate `set_worker_status(..., STOPPED)` and `set_task_status(...,
COMPLETED)` writes were not atomic; Worker release happened first.

**Files:** `ctf_solver/manager/store.py`,
`ctf_solver/manager/service.py`, `tests/test_round2_completion_faults.py`.

**Fix:** new `ManagerStore.finalize_task_completion(task_id, worker_id, result_state,
ended_at, notes)` writes Task `completed` and Worker `stopped` in **one SQLite
transaction**, with compare-and-set on `completion_pending` and the exact Worker/session
ownership. Any failure rolls back both; Task stays `completion_pending`, Worker keeps the
slot, and no FIFO pump happens. Completion and restart recovery both use this path.
Evidence event + historical anchor are verified and `evidence_head` persisted **before**
the transaction; if the transaction fails, both Task and Worker remain protected and the
operation is retryable.

**Fault tests (SQLite triggers abort specific UPDATEs, real transaction rollback):**
Session close failure; completion-event append failure; evidence-head failure; chain
failure; Worker UPDATE failure; Task UPDATE failure; FIFO pump failure; crash/restart
without evidence; valid-evidence restart; restart where finalization is blocked; repeat
completion idempotence. Includes the required scenario: after the Task-status failure the
slot is still held, a queued FIFO Task has **no** Worker/session and is not admitted, then
after removing the fault completion succeeds and the queued Task starts exactly once.

**Result:** `hardening-followup-completion.txt`, exit 0, **19 passed** (10 fault tests +
9 normal completion/idempotence tests). No unresolved limitation.

---

### P0-3B — historical evidence-head snapshot vs advancing global chain head

**Original problem:** `_verify_completed_task_evidence()` compared Task A's saved
`evidence_head` with the **current global** `chain_head()`. Any later event written by
Task B legitimately advanced the global head, so Task A's idempotent completion
re-verification failed.

**Reproduction (before fix):** `hardening-followup-repro-before.txt`:
`GLOBAL_HEAD_BUG_REPRODUCED StateError completed Task evidence_head does not match the
evidence chain head saved_head=d07d…`.

**Root cause:** a Task completion snapshot is a historical anchor, not the global append
position; the two were conflated.

**Files:** `ctf_solver/evidence/store.py`,
`ctf_solver/manager/service.py`, `tests/test_round2_chain_snapshot.py`.

**Fix:** `EvidenceStore.verify_chain_anchor(anchor)` now verifies the saved head is the
record hash of an event present in the current, fully re-verified chain. Completion stores
the `task_completed` event's own `record_hash` as the Task snapshot (not a later global
head). Verification requires: chain intact; the anchor exists in chain; exactly one
completion event for the Task; the anchor equals that event's record hash; event payload
result_state/ended_at match the Task. The global head may legitimately differ and is never
overwritten into the Task snapshot.

**Tests (real SQLite + real EvidenceStore):** cross-Task appends keep completed Task A
idempotent with unchanged head; global head changes; tampered historical anchor fails
closed; corrupted global chain fails closed even though the historical event exists;
three sequentially completed Tasks remain independently idempotent with no duplicate
events/Workers.

**Result:** `hardening-followup-chain.txt`, exit 0, **4 passed**. No unresolved limitation.

---

### P1 — JUnit XML redaction corruption

**Original problem:** the privacy redaction inserted raw `<USER_HOME>` into
`round2-evidence/raw/hardening-final-clone-junit.xml`; the file failed XML parsing
(`ParseError: mismatched tag`).

**Reproduction (before fix):** `hardening-followup-junit-before.txt`
`PARSE_FAIL … ParseError mismatched tag` for that file; all other JUnit files parsed.

**Root cause:** text-oriented byte redaction was applied to XML without entity escaping.

**Files:** `round2-evidence/raw/hardening-final-clone-junit.xml` (only escaped, no test
results changed); new `scripts/verify_junit_xml.py`; new
`tests/test_delivery_junit_xml.py`; all committed JUnit files parsed.

**Fix:** the placeholder is stored as `&lt;USER_HOME&gt;` in XML text nodes. A delivery
verification script parses every tracked JUnit XML with the standard library parser,
aggregates tests/failures/errors/skipped, compares them with the corresponding pytest
console-log summaries (accounting for xpassed), and checks for unescaped placeholders,
personal paths and malformed XML. A regression test covers all committed JUnit files.

**Results:** `hardening-followup-junit-verify.txt`, exit 0, all **12** tracked JUnit files
parse and match logs; `hardening-followup-junit-tests.txt`, exit 0, **2 passed**. No test
result number was altered; only the placeholder was XML-escaped.

---

## C. Regression results

| Test item | Passed | Skipped | Failed | Exit code |
|---|---:|---:|---:|---:|
| Approval attack matrix (incl. 4 cross-Task cases) | 17 | 0 | 0 | 0 |
| Completion fault injection + normal completion | 19 | 0 | 0 | 0 |
| Historical chain-head idempotence | 4 | 0 | 0 | 0 |
| JUnit XML regression test | 2 | 0 | 0 | 0 |
| JUnit XML verifier (12 tracked XML files vs logs) | all parsed/match | 0 | 0 | 0 |
| Full default suite | **1015** | 4 | 0 | 0 |
| Full suite + zero-model real ACP smoke | **1016** | 3 | 0 | 0 |
| Real Harness integration (zero model calls) | 43 checks | — | 0 | 0 |
| Final clean clone (default) | **1015** | 4 | 0 | 0 |
| Final clean clone + real ACP smoke | **1016** | 3 | 0 | 0 |

The 4 default skips remain the documented Windows file-symlink/opt-in-real-ACP limits;
no test was deleted, weakened, or converted to skip.

Raw logs/JUnit: `hardening-followup-full-default.txt`,
`hardening-followup-full-with-real-acp.txt`, `junit-followup-default.xml`,
`junit-followup-with-real-acp.xml`, `hardening-followup-clean-clone-tests.txt`,
`hardening-followup-clean-clone-real-acp.txt`,
`hardening-followup-clean-clone-junit.xml`, `hardening-followup-integration.txt`.

---

## D. Deliverables (absolute path, size, SHA-256, verification)

| Deliverable | Path | Size | SHA-256 | Verification |
|---|---|---|---:|---|
| New Bundle | `D:\CTF-SOLVER-review\CTF-Solver-Final-Acceptance-Followup.bundle` | recorded in final delivery message | recorded in final delivery message | `git bundle verify` exit 0; independent clone HEAD/branch/manifest/fsck checked; original Bundle untouched |
| New Wheel | `D:\CTF-SOLVER\dist\ctf_solver-0.1.0-py3-none-any.whl` | **222,173 B** | **`14EED36298D31A6CC3FDEE749CF5E4CC18986CB266047E1B9573E9676621D83A`** | built from clean clone of `de6e670`; Bundle clone rebuild produced the same SHA-256 |
| Final manifest | `D:\CTF-SOLVER\round2-evidence\FINAL_FILE_MANIFEST.txt` | actual file | — | Git blob bytes, self-excluded, 310 entries / 311 tracked files, 0 missing/hash/size mismatch in clean clone |
| Final report | `D:\CTF-SOLVER\docs\ROUND_2_FINAL_ACCEPTANCE_FOLLOWUP.md` | this file | — | — |
| Attack test logs | `round2-evidence/raw/hardening-followup-approval.txt` | — | — | exit 0 |
| Approval repro-before log | `round2-evidence/raw/hardening-followup-repro-before.txt` | — | — | pre-fix reproduction |
| Completion fault logs | `round2-evidence/raw/hardening-followup-completion.txt` | — | — | exit 0 |
| Chain snapshot logs | `round2-evidence/raw/hardening-followup-chain.txt` | — | — | exit 0 |
| JUnit before/after/verifier | `round2-evidence/raw/hardening-followup-junit-{before,verify,tests}.txt`, `junit-xml-verification.json` | — | — | parse failures before; all parse after |
| Full test logs/JUnit | `round2-evidence/raw/hardening-followup-full-*`, `junit-followup-*.xml` | — | — | exit 0 |
| Clean-clone evidence | `round2-evidence/raw/fresh-clone-20261110T142552Z.{json,log}`, `hardening-followup-clean-clone-*`, `hardening-followup-canonical-wheel-build.json` | — | — | exit 0; wheel hash matches |
| Privacy scan | `round2-evidence/raw/privacy-scan-before.json`, `privacy-scan-after.json`, `privacy-redaction-before.json` | — | — | 47 files/343 personal-path occurrences before → 0 after; 0 real credentials |

Final manifest count: **311 tracked files, 310 manifest entries** (the manifest itself is
excluded). Final tree redaction: 0 personal Windows home paths in tracked/untracked
non-binary text files; credential-pattern scan 0 real credentials. The only intentional
`28746` occurrences are detection regex literals in the privacy/JUnit audit scripts, not
paths.

Note: a Bundle cannot contain its own SHA-256; the final Bundle size/SHA-256 is therefore recorded in the final delivery message and computed from the report commit. All other hashes above are embedded and reproducible from the committed tree.

Limitation (disclosed, not hidden): older Git history commits created before the redaction
work still contain raw path strings; history was not rewritten per policy, so a Bundle
contains that history.

---

## E. Final state

| Item | State |
|---|---|
| FAIL | **None** |
| BLOCKED | Session-log external-delivery canary (requires authorized model request); model-mediated Worker/`session/prompt` (ADR-020); main-conversation `/ctf-solver` → Manager MCP entrypoint (no supported project-scoped registration, owner decision); Tier 2 isolation/real targets/challenge execution |
| NOT VERIFIED | Real physical-console TTY typing; same-child ACP-spawned MCP `tools/call` (zero-model gate) |
| Uncommitted changes | none after the report commit |
| Pushed | no |
| PR modified | no (PR #1 remains Draft/open/unmerged; no PR created) |
| Protected environment touched | no: `D:\CTFworker` fingerprint unchanged, audit hash unchanged, `~/.dsh/profiles` unchanged |
| Model calls / `session/prompt` | 0 / 0 |
| Round 1/Round 2/hardening history | preserved; no amend/rebase/reset/rewrite of prior commits |
| Original Bundle | unchanged (SHA-256 `2D5D27B2…EEC74C`) |

All comparisons and counts in this report are based on the committed files and raw
logs/JUnit listed above. No BLOCKED or NOT VERIFIED item is reported as PASS.
