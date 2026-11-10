# Round 2 Final Acceptance Hardening Report

**Status:** final acceptance hardening candidate for independent review
**Branch:** `fix/round2-acceptance-remediation` (continues the existing remediation branch; no new development branch)
**Baseline HEAD:** `c45299d1b80f362d217abcc2526888b79c75eba5`
**Hardening implementation commit:** `75838497b37750e713683f644e221773aa56242e` (code/tests); this report/evidence commit is its child
**Report commit:** the child commit containing this report and the regenerated Git-blob manifest (local only; no push/PR/merge)
**Round 1 branch preserved:** `feat/round1-complete-product-core` @ `e40f76f317ec3f3186e0120744af2f5924d32721`
**Round 2 branch preserved:** `feat/round2-harness-integration` @ `d38845366075c57f5840127b93bfd58c9c9e24f3`

This is a final, scope-limited acceptance hardening patch. It does not start a third
development round, does not change the frozen Manager/ACP/Broker/Evidence architecture,
does not add product features, and does not unblock the main-conversation entrypoint.

---

## 1. P0-1 — dual-record approval verification

### Defect (reproduced)

`create_grant_from_approval()` previously verified only
`action_digest == SHA256(canonical_payload)`. An attacker with SQLite access could rewrite
**both** `approvals.payload_json` and `approvals.action_digest` consistently (e.g. change
the human-approved port 8443 to 9443 in both fields) and mint a grant with a scope the
human never approved.

### Fix

Grant creation now requires **two independent records** and an intact evidence chain:

1. **Approval row** — approval_id, task_id, action_kind, canonical payload,
   action_digest, status=APPROVED, confirmation_channel=local_console, confirmation_id,
   confirmation_os_user (revalidated after canonicalization and digest re-derivation).
2. **Human decision event** — exactly one `approval_decided` event in the real
   `EvidenceStore` hash chain for this approval, with matching task_id, `approved=true`,
   action_digest, confirmation_id, confirmation_os_user and local_console channel.
   The chain `chain_status()` must be intact and the event must be readable from that
   chain.

Missing, duplicate/conflicting, field-inconsistent or chain-invalid events fail closed
before approval consumption. `confirm_approval()` now treats the event append/verification
as mandatory: if it fails, the approval is invalidated (`CANCELLED`) and the call raises,
so an approval with no durable decision evidence can never later create a grant. Atomic
one-shot consumption, approval TTL, grant TTL/max_calls, cross-Task isolation and CAS
one-winner semantics are preserved.

### Threat model (not overstated)

This mechanism detects inconsistency between the approvals table and an independently
hash-chained confirmation event, plus isolated deletion/modification of either record
(which breaks chain verification). It does **not** claim resistance to an attacker who can
atomically rewrite the entire SQLite database, the whole event chain and all metadata in a
mutually consistent way; there is no external anchor/signature in this development cycle.

### Real attack evidence (not mocks)

`tests/test_round2_acceptance_hardening.py` uses the real `ManagerStore` + real
`EvidenceStore` on a temporary SQLite database. It reproduces the reported attack:
human approves port **8443**, attacker rewrites payload+digest to **9443**, grant creation
is rejected. It also covers: payload-only rewrite, digest-only rewrite, confirmation_id
tamper, confirmation_os_user tamper, Task rewrite, decision-event deletion (chain damage),
decision-event modification (chain failure), duplicate conflicting event, replay of a
consumed approval, general chain damage, and 4-thread concurrent grant creation
(exactly one winner). A failing decision-event append also invalidates the approval.

Raw evidence: `round2-evidence/raw/hardening-approval-attacks.txt` (exit 0, 13 tests).

---

## 2. P0-2 — no ACP launch path can bypass the privacy patch

### Defect

The default production path already composed `--profile acp --patch <abs path>`, but an
explicit `config.acp_command`/public `--acp-command` was treated as a complete command and
could bypass the project privacy patch.

### Fix

- `wiring.default_acp_factory()` now has **one protected construction path**: it always
  resolves the project patch (fail closed if missing/relative) and always builds the
  launch argv through `build_acp_command(..., privacy_patch=<absolute>)`.
- `config.acp_command` and the test-only `CTF_SOLVER_TEST_ACP_COMMAND` environment boundary
  are treated only as a **launcher** and receive the same appended protected
  `--profile acp --patch <absolute project patch>` arguments. A launcher that tries to
  supply its own `--profile`/`--patch` is rejected.
- The public `manager` CLI `--acp-command` flag was removed; `mcp.manager_server` no longer
  has that flag. Fake-ACP tests use the explicit test-only environment/dependency
  injection boundary, not a production CLI flag.
- `--capture-mode fake` has no effect on ACP protection; it only selects the screenshot
  capture backend.
- Windows `.cmd` launch wrapping remains correct; protected args are appended after the
  launcher's own fixed arguments (so interpreter-style test launchers and the real
  `dsh.cmd` both work, while every launch contains exactly the protected args).

### Tests

`tests/test_acp_launch.py`, `tests/test_integration_stack.py`,
`tests/test_round2_security_integration.py`: default production launch contains the
absolute patch; `CTF_SOLVER_ACP_COMMAND` still gets the patch; explicit
`config.acp_command` cannot bypass and cannot smuggle `--profile/--patch`; missing and
relative patch fail closed; public `--acp-command` is rejected by argparse; fake ACP runs
through the test boundary; `.cmd` wrapping still works.

Real Harness evidence (zero model calls): the live Manager ACP argv is
`[COMSPEC, /c, dsh.cmd, --profile, acp, --patch, D:\CTF-SOLVER\config\acp\cordis.patch.yml]`
(evidence A), and the same argv with `--dump-config` in the same isolated `DSH_HOME`
composes a profile with `dsh-session-log-deepseek` disabled (evidence B, exit 0). The
external-delivery canary remains **BLOCKED** (requires a model request).

Raw evidence: `round2-evidence/raw/hardening-acp-tests.txt` (exit 0, 53 tests),
`round2-evidence/raw/round2-integration.log`, `round2-privacy-gate-result.json`.

---

## 3. P0-3 — completion cannot succeed without durable evidence

### Defect

`complete_task()` closed the session, stopped the Worker and persisted `completed` before
writing the `task_completed` event; `_emit()` swallowed evidence failures. A completed
Task could therefore lack its mandatory completion event and evidence-head update.

### Fix

Completion is a two-phase, evidence-first lifecycle with a durable intermediate state:

1. preconditions (status, no unfinished execution, no pending approval, session log
   ingested, intact chain, persisted evidence head, Worker/session ownership, no
   unresolved ACP security/evidence errors);
2. durable `completion_pending` (holds the Worker slot; new executions/flags refused;
   never reported completed; survives restart);
3. ACP session close — on failure the Task is rolled back to its previous active status,
   the slot is held, and a structured `AcpError` is returned;
4. mandatory `task_completed` event append, chain verification and uniqueness check
   (exactly one event per Task; no duplicate emitted on retry);
5. strict `evidence_head` persistence with read-back verification;
6. Worker stop / slot release;
7. durable `completed` + `result_state` + real `ended_at`;
8. re-verification of completion evidence/head, then FIFO pump.

Any event/head/chain/Worker/Task-status failure leaves the Task unfinished (normally
`completion_pending`, with the slot held) and returns an error; it never returns success
without the durable completion event. Restart recovery finalizes a pending completion only
when the completion event is present and the chain is intact; otherwise it marks the Task
`interrupted` (never `completed`). Repeat completion is idempotent and re-verifies the
durable evidence. A FIFO pump failure after durable completion is diagnosed without
creating duplicate Workers; a later pump starts the queued Task once.

### Fault-injection tests (real execution)

`tests/test_round2_completion_faults.py` injects every listed fault: session close
failure, `task_completed` append failure, `evidence_head` update failure, chain-status
failure after the event, Worker status failure, final Task status failure, FIFO pump
failure, restart without completion evidence (→ interrupted), restart with valid
completion evidence (→ completed), and idempotent repeat. Each failing path is asserted to
leave the Task unfinished and the slot held (or a safely recoverable pending state).

Raw evidence: `round2-evidence/raw/hardening-completion-tests.txt` (exit 0, 18 tests);
normal completion also covered by `tests/test_manager_completion.py`.
The real synthetic E2E still ends `status=completed`, `result_state=solved_flag_candidate`,
real `ended_at`, closed session, stopped Worker, unique `task_completed` event and matching
`evidence_head`; the Writeup shows `Status: completed` (never `running`/`unknown`).

---

## 4. Delivery material cleanup

### Manifest / report metadata

- The previous report text said 255 entries; the repository at that commit had
  **262 tracked files** and the manifest excluded itself, so the correct number was
  **261**. The report was corrected and the old manifest header no longer cites a
  non-existent/amended `report_commit` (no self-referential commit SHA).
- The final manifest is regenerated from **canonical Git blob bytes** (not CRLF working
  tree bytes), explicitly excludes itself, and cites only the existing implementation
  commit. Final counts are verified against the final tree/clean clone: **285 tracked
  files, 284 manifest entries** (the manifest itself is excluded).
- Manifest coverage and tracked-file count are reported separately below.

### Privacy redaction

All tracked/untracked non-binary text files were scanned:
**47 files / 343 occurrences** of the personal Windows home path before redaction, **0
after**; replacement is `<USER_HOME>` (and `<USER_ID>` for the bare profile id). A second
byte-level pass handled logs that were not valid UTF-8. The credential-pattern scan
(OpenAI-style keys, GitHub tokens, AWS keys, private-key headers, password/token
assignments) found **0 real credentials**; test-only synthetic token strings are fixtures.

Evidence: `round2-evidence/raw/privacy-scan-before.json`,
`round2-evidence/raw/privacy-scan-after.json`,
`round2-evidence/raw/privacy-redaction-before.json`.
Limitation: the redaction covers the final tree; older Git history commits created before
this hardening were not rewritten (policy: no history rewrite), so the bundle history still
contains those older raw-path strings.

---

## 5. Verification evidence

| Run | Result | Exit | Evidence |
|---|---|---|---|
| Full default suite | **1004 passed, 4 documented skips, 0 failed** | 0 | `hardening-full-default.txt`, `junit-hardening-default.xml` |
| Full suite + zero-model real ACP smoke | **1005 passed, 3 skips, 0 failed** | 0 | `hardening-full-with-real-acp.txt`, `junit-hardening-with-real-acp.xml` |
| Real Harness integration (zero model calls) | **43/43 PASS** | 0 | `round2-integration.log`, `round2-integration-summary.json`, privacy gate JSON |
| Dual-field approval attack matrix (real SQLite + EvidenceStore) | 13 passed | 0 | `hardening-approval-attacks.txt` |
| Completion fault injection + normal completion | 18 passed | 0 | `hardening-completion-tests.txt` |
| ACP launch/integration security matrix | 53 passed | 0 | `hardening-acp-tests.txt` |
| Strict clean clone of the final hardening tree | **1004 passed / 4 skipped** default; **1005 passed / 3 skipped** with zero-model real ACP smoke; wheel built and verified | 0 | `hardening-final-clone-tests.txt`, `hardening-final-clone-real-acp.txt`, `hardening-final-clone-junit.xml` |
| Canonical wheel (clean-clone build) | `ctf_solver-0.1.0-py3-none-any.whl`, **220,523 B**, SHA-256 `C9209690B974899BF65C30F04D34FECADB0212A72A60550B4B4CC368C396C32E`, 64 members | 0 | `hardening-final-canonical-wheel-build.json` |
| Final Git-blob manifest | 284 entries (tracked files 285, manifest self-excluded), 0 missing/hash/size mismatches in a clean clone | 0 | `round2-evidence/FINAL_FILE_MANIFEST.txt` |

Commands used are the documented ones (`python -m pytest tests ...`,
`python scripts/round2_integration.py`, `python scripts/fresh_clone_check.py`,
`python scripts/build_wheel.py`). No test was removed, weakened, or converted to skip.

---

## 6. Acceptance matrix

| Requirement | Verdict |
|---|---|
| P0-1 dual-record approval verification + full attack matrix | **PASS** |
| P0-1 threat-model honesty (no overclaim) | **PASS** (documented in security changes and this report) |
| P0-2 no unprotected production ACP launch path; missing/relative patch fail closed; fake injection preserved; real A/B evidence | **PASS** |
| P0-3 completion cannot succeed without durable completion event/head; fault injection; restart recovery; idempotent repeat | **PASS** |
| Delivery manifest counts/SHA basis/self-reference fixed; clean-clone 100% verification | **PASS** |
| Privacy redaction of final tracked text + credential scan | **PASS (final tree)**; historical commits not rewritten (documented limitation) |
| Full backend + security + real ACP smoke + real Harness integration | **PASS** |
| Wheel + clean-clone rebuild + Git-blob manifest | **PASS** |
| Real physical-console TTY approval typing | **NOT VERIFIED** (automated non-interactive harness; no human present) |
| Same-child ACP-spawned `tools/call` | **NOT VERIFIED** (zero-model-call gate; independent MCP process used for tools/call) |
| Session-log negative external-delivery canary | **BLOCKED** (requires an authorized model request; not executed) |
| Model-mediated Worker / `session/prompt` | **BLOCKED by design** (ADR-020) |
| Main-conversation `/ctf-solver` → Manager MCP entrypoint | **BLOCKED** (no supported project-scoped registration; owner decision) |
| Tier 2 OS isolation / real CTF targets / challenge code execution | **BLOCKED** (not in this environment) |

No FAIL items. The blockers/NOT VERIFIED items above are not claimed as passes.

---

## 7. Git / final delivery

- Branch `fix/round2-acceptance-remediation`; hardening implementation commit
  `75838497b37750e713683f644e221773aa56242e`
  (**78 files changed, 2,393 insertions(+), 603 deletions(-)**);
  the report/evidence commit is the child commit containing this document.
- Round 1 `e40f76f` and Round 2 `d388453` are unchanged; PR #1 untouched (Draft/open);
  nothing pushed or merged.
- Final bundle (only `refs/heads/fix/round2-acceptance-remediation`):
  `D:\CTF-SOLVER-review\CTF-Solver-Round2-Final-Hardening.bundle`; its size and SHA-256
  are recorded in the final delivery message.
- `D:\CTFworker` untouched; no installs/upgrades; no Harness global config change; no
  WSL/Docker; no real CTF target; no challenge execution; no model call/session-prompt;
  runtime data removed from the working tree after evidence collection.
- Runtime/protected-state check: `D:\CTFworker` porcelain fingerprint
  `C944E18C…622592A7`, audit SHA-256 `955136d1…fe5373`, `~/.dsh/profiles` 775 files with
  max mtime `2026-11-10T01:52:31` all unchanged.

Remaining owner decisions/blockers are unchanged: main-conversation entrypoint, external
delivery canary, model-mediated Workers, real TTY verification and Tier 2 isolation.
