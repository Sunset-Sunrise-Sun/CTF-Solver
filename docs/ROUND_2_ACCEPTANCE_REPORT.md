# Round 2 Acceptance Report — Harness Integration and Security Remediation

**Status:** Round 2 integration candidate, ready for independent review
**Branch:** `feat/round2-harness-integration` (local only; not pushed, no PR created)
**Round 1 branch preserved:** `feat/round1-complete-product-core` @ `e40f76f317ec3f3186e0120744af2f5924d32721` (unchanged)
**Round 2 branches from:** Round 1 HEAD `e40f76f`
**Round 2 recovery commit:** `8615af6` (restores the ignored `ctf_solver/evidence/` package; anchors `.gitignore` to the project root)
**Round 2 implementation commit:** `d69b9493c480e81c3908b58f361e84262c0cc646`
**Acceptance report commit:** the follow-up local commit containing this report (see `git log -1`; no push/PR).
**Date:** 2026-11-10 (Asia/Shanghai)

Reporting rule: **PASS / FAIL / BLOCKED / NOT VERIFIED**. A blocked test is not a pass, a
configuration flag is not a delivery proof, and an audited primitive is not proof of
integration. Round 2 does not claim final MVP acceptance.

---

## 1. Executive summary

Round 2 fixed the Round 1 independent-review defects first, then integrated the unchanged
product architecture with the real, locally installed Harness installation:

1. **P0 source recovery.** `.gitignore` line `evidence/` excluded the whole
   `ctf_solver/evidence/` Python package from the Round 1 bundle. The original files were
   still intact in the working tree; they are now tracked, `.gitignore` is root-anchored,
   imports succeed, and `git ls-files ctf_solver/evidence` lists all seven files.
2. **P0 approval/grant security.** The model can only request approvals. Decisions and
   network grants require a real local interactive-console human confirmation; MCP
   decision/grant-creation tools are removed; replay/expiry/cross-Task/tamper/one-shot
   binding fail closed.
3. **P0 session-log read path.** `ctf_session_ingest` no longer accepts a path. The
   Manager resolves the log from its own Task/Worker/session registry under the managed
   isolated `DSH_HOME`, with containment/symlink/ambiguity/header verification.
4. **P1 integration defects.** MCP argument schema enforcement, ACP permission
   session→Task mapping, exact `dsh --profile acp` launch, ACP-standard
   `mcpServers.env` entry array, controlled challenge-file intake, line-ending-stable
   checkout, and a stdlib-only wheel build + fresh-clone verification.
5. **Real Harness integration.** Zero-model-call run against the installed Harness ACP
   server with isolated temporary `DSH_HOME`: **30/30 checks PASS**, including two active
   Workers + FIFO, per-session Worker MCP mount/handshake, direct MCP `tools/call`, real
   multi-frame session-log ingestion, real project-owned-window screenshot, Writeup +
   independently verified evidence ZIP, restart recovery without duplicate sessions, and
   a synthetic end-to-end challenge.

Honest blockers remain: the live main-conversation `/ctf-solver` → Manager MCP entrypoint
(no supported project-scoped registration), the session-log negative-delivery canary
(needs a model call), model-mediated Worker behaviour (not authorized), and Tier 2 OS
isolation (unavailable).

---

## 2. Test evidence

Environment: Windows 11 10.0.26200, Python 3.14.7, pytest 9.1.1, Node 24.19.0, git
2.55; no packages installed for this round.

| Run | Result | Exit | Raw evidence |
|---|---|---|---|
| Full suite, default (real-ACP smoke opt-in off) | **929 passed, 4 skipped, 0 failed** | 0 | `round2-evidence/raw/round2-full-suite-default.txt` + `junit-round2-default.xml` |
| Full suite including zero-model-call real ACP smoke | **930 passed, 3 skipped, 0 failed** | 0 | `round2-evidence/raw/round2-full-suite-with-real-acp.txt` + `junit-round2-with-real-acp.xml` |
| Fresh clone of committed HEAD `d69b949` (strict, no overlay) | **929 passed, 4 skipped** in 60.7 s; clone wheel build PASS | 0 | `round2-evidence/raw/fresh-clone-20261110T120253Z.{json,log}`, `fresh-clone-wheel-build-20261110T120253Z.json`, `round2-fresh-clone-console.txt` |
| Real Harness integration run (zero model calls) | **30/30 checks PASS** | 0 | `round2-evidence/raw/round2-integration.log`, `round2-integration-summary.json` |
| Wheel build (in-tree PEP 517 stdlib backend) | `ctf_solver-0.1.0-py3-none-any.whl`, 204,840 B, SHA-256 `6278B15FFEE1C61433618FCAAD05FE169C6E2C7F51864655203A2B4B82167FE2`, 63 members / 12 packages, extraction+import+CLI verified | 0 | `round2-evidence/raw/round2-wheel-build.txt`, `wheel-build.json` |
| Fresh-clone wheel (same content) | same filename/SHA-256 `6278b15f…67fe2` — deterministic across clone | 0 | `fresh-clone-wheel-build-20261110T120253Z.json` |
| Security negative suites | `tests/test_security_*.py` 45 passed; `tests/test_round2_security_integration.py` 13 passed | 0 | `round2-evidence/raw/security-pytest.txt` |
| Integrity modules (session-log resolver / MCP schema / ACP launch) | 154 passed, 1 documented Windows file-symlink skip | 0 | `round2-evidence/raw/integrity-pytest.txt` |
| Intake + packaging | 60 passed, 2 documented Windows file-symlink skips | 0 | `round2-evidence/raw/packaging-pytest.txt` |

The 4 default skips are documented environment limits only: 2× Windows file-symlink
creation requires elevation, 1× resolver file-symlink case (directory link escapes do
run via junctions), 1× opt-in real ACP smoke (included in the second run). No test was
deleted, weakened, or converted from failure to skip to obtain these results.

Commands:

```powershell
python -m pytest tests -q -p no:cacheprovider
$env:CTF_SOLVER_ENABLE_REAL_ACP = '1'; python -m pytest tests -q -p no:cacheprovider
python scripts/round2_integration.py
python scripts/round2_harness_analysis.py
python scripts/build_wheel.py
python scripts/fresh_clone_check.py         # strict committed HEAD
```

---

## 3. Owner remediation requirements — verdict matrix

| # | Owner requirement | Verdict | Evidence |
|---|---|---|---|
| 一 | Round 1 branch/commit preserved; Round 2 branch created only if absent; no push/PR/merge; D:\CTFworker untouched | **PASS** | Round 1 branch `e40f76f` unchanged; new branch `feat/round2-harness-integration` created from it; no remote refs/push; `D:\CTFworker` porcelain fingerprint unchanged; protected files untouched |
| 二 | Recover complete `ctf_solver/evidence/` source; fix `.gitignore`; track source; imports; wheel; fresh clone | **PASS** | 7 files tracked (`git ls-files ctf_solver/evidence`); `.gitignore` root-anchored; imports verified; wheel + strict fresh clone PASS |
| 三 | Approval/grant security: model cannot decide/authorize; human confirmation bound to Task/target/protocol/action/TTL/calls; replay/expiry/cross-Task/tamper fail closed; negative tests | **PASS (implemented/offline-verified) / NOT VERIFIED (real physical TTY)** | `docs/ROUND_2_SECURITY_CHANGES.md` §1; MCP surface removal test; 45 security tests + 13 Lead security regressions; positive TTY path uses injected fake TTY, non-TTY/agent-context fail closed |
| 四 | Session-log ingestion: registry-only, strict Task/Worker/session binding, no caller path/symlink/traversal; negative tests | **PASS** | `SessionLogResolver`; tool schema has no path/extra properties; 44 resolver tests + real-Harness ingestion PASS |
| 五.1 | MCP schema validation (types/enums/structure/additionalProperties/bounds, not description-only) | **PASS** | `mcp/schema.py` wired into `mcp/protocol.py`; 72 validator tests; protocol/exec negative tests |
| 五.2 | ACP permission event session→Task reverse mapping, unknown session diagnostic not wrong Task | **PASS** | `tests/test_round2_security_integration.py::test_acp_permission_events_are_mapped_through_session_registry` |
| 五.3 | ACP launch exact `dsh --profile acp`; fake launcher + real zero-model smoke | **PASS** | `acp/launch.py` tests; real integration log shows actual argv `[.../dsh.cmd, --profile, acp]`, protocolVersion 1 |
| 五.4 | Controlled challenge-file import/isolated workspace/hashes/multi-file/cross-Task isolation/Writeup record; no arbitrary host read | **PASS** | `IntakeService`; 48 intake tests; Manager integration test; E2E Writeup lists real imported material SHA-256 |
| 六.1 | Re-check the 3 XPASS tests and remove stale xfail markers | **PASS** | `tests/test_verification_round1.py` now has 3 permanent regression tests (no xfail), all passing |
| 六.2 | No test deletion/weakening; full suite from fresh clone | **PASS** | Strict fresh clone runs 929 passed / 4 documented skips; suite grew from 658 to 933 collected |
| 六.3 | SQLite single authority; deterministic JSONL from committed rows; CAS/chain/manifest/ZIP | **PASS** | Existing evidence/tamper/idempotency tests + real session-log ingestion + real ZIP manifest verification |
| 六.4 | Wheel contains all required Python packages | **PASS** | 12 packages incl. `ctf_solver.evidence`, `ctf_solver.security`; extraction imports + `python -m ctf_solver version` |
| 七 | Continue Round 2 integration (skills discovery, entrypoint, Manager MCP, real ACP, Worker MCP mount, direct tools/call, 2+FIFO, restart, real log ingestion, screenshot/Writeup/ZIP, synthetic E2E); mark BLOCKED honestly otherwise | **PASS where authorized; entrypoint BLOCKED** | Integration 30/30 checks PASS; Skill discovery session-log evidence PASS; main-conversation Manager MCP entrypoint **BLOCKED** (no project-scoped registration; see §4) |
| 八 | Privacy gate: only isolated temp DSH_HOME; no global changes; no real CTF data/targets; no model calls; do not report config as delivery verification | **PASS (mechanism) / BLOCKED (canary)** | Mechanism re-verified in isolated home; negative outbound-delivery canary **BLOCKED** (needs model request; no authorization); no model call made |
| 九 | Round 2 final deliverables (code, Skills, interfaces/integration evidence, tests/logs, wheel+clone, security negatives, E2E run dir, Writeup+ZIP, SHA-256 manifest, commit SHA/stat, acceptance matrix) | **PASS** | This report; `round2-evidence/`; `FILE_MANIFEST.txt`; commits `8615af6` + `d69b949` + report commit |

### ROUND_2_INTEGRATION_TASK.md scope verdicts

| Scope | Verdict | Evidence |
|---|---|---|
| A. Entrypoint and persistent conversation mode | **PARTIAL: Skill discovery PASS; `/ctf-solver` → Manager tools BLOCKED** | Session-log catalog evidence + installed-source scan; no project-scoped MCP registration (owner decision needed); mode/persistence semantics are Skill instructions, live model conversation not authorized |
| B. ACP Client and independent Workers | **PASS** | Real ACP: 2 independent sessions/workspaces, FIFO queue/promotion, close isolation, per-session MCP mount, restart recovery no duplicates |
| C. Model-mediated Worker test gate | **BLOCKED** | No `session/prompt`/model authorization (ADR-020); client gate prevents prompts |
| D. Session-log privacy P0 gate | **PASS (mechanism) / BLOCKED (canary)** | Isolated-profile config verification; negative delivery canary requires model call |
| E. MCP/ctf-exec/Broker/Runtime integration | **PASS** | Direct MCP tools/call against real Worker-scoped server; denied typed call fails closed; no shell/Docker boundary change |
| F. Evidence pipeline and recovery | **PASS** | Real Harness multi-frame logs ingested via registry (idempotent, gaps explicit), SQLite/CAS/chain checks from existing suites |
| G. Screenshots, Writeup, evidence ZIP | **PASS** | Real project-owned-window capture (PrintWindow flag 2), chronological Writeup, deterministic ZIP + verified manifest |
| H. Synthetic end-to-end acceptance | **PASS (zero-model-call synthetic)** | `round2-evidence/end-to-end/` (writeup.md, evidence.zip, screenshot.png, input); 2+FIFO/cancel/restart exercised; flag candidate human-submission boundary preserved |

### Mandatory P0 gates (two-round plan)

| Gate | Verdict |
|---|---|
| Session-log external delivery disabled/excluded by a supported verified mechanism | **PARTIAL PASS**: mechanism verified in isolated temp DSH_HOME; negative delivery canary **BLOCKED** (model call required; real CTF content remains unauthorized) |
| Main conversation can invoke Manager tools via supported project-scoped integration | **BLOCKED** (no supported mechanism found in installed source; options documented for owner) |
| One ACP session/workspace per Task; max two FIFO enforced by Manager | **PASS** (fake + real Harness) |
| Worker operations only through typed ctf-exec and Broker | **PASS** |
| Task-scoped approvals/network grants fail closed; human-only decisions | **PASS** (offline verification; real physical TTY NOT VERIFIED) |
| Evidence complete, reproducible, tamper-evident; gaps explicit | **PASS** |
| User confirmation/submission for Flag retained | **PASS** (candidate only; no submission tool) |

---

## 4. Conclusions, limits and owner decisions

1. **Main-conversation `/ctf-solver` → Manager control tools: BLOCKED.** The six Skills
   are discovered by the running Harness (session-log proof), the Manager control MCP
   server is real and tested, and each Worker session receives its own MCP server through
   `session/new.mcpServers` (real handshake proven). But no supported **project-scoped**
   registration path for mounting the Manager control server into the live main
   conversation exists (MCP rows come from profile-level `cordis.patch.yml` layers).
   Options for the owner: (a) authorize a dedicated profile-scoped MCP registration;
   (b) authorize a thin Cordis Host Plugin bundle registering Manager tools; (c) accept a
   user-launched local Manager connected out-of-band. This was not silently implemented.
2. **Session-log negative outbound-delivery canary: BLOCKED.** It requires a model/API
   request. The supported disable mechanism is verified in an isolated profile, but a
   config value `enabled: false` is not reported as delivery-verified. Real CTF content
   must not be processed until this gate is closed with separate authorization.
3. **Model-mediated Worker behaviour (`session/prompt`, live MCP tool calls by a model,
   permission round-trips under a real turn): BLOCKED by design.** No model call was
   made in this round; the client gate raises before sending.
4. **Real physical-console approval interaction: NOT VERIFIED.** The positive decision
   path is exercised with an injected TTY; non-TTY, agent-context, EOF, wrong-phrase and
   replay paths are tested to fail closed.
5. **Real Skill discovery inside a model-driven ACP Worker turn: NOT VERIFIED** (the ACP
   session log has no catalog without a prompt); discovery is proven by the live
   interactive Harness session log and by the installed Skill-filesystem project-root
   source.
6. **Approval-gated `ctf-exec`: not exercised end-to-end** because no tool that both
   requires approval and is permitted exists in the Round 2 execution tier; the Broker
   and the human-confirmation service are tested independently on both sides.
7. **Tier 2 OS isolation / challenge-code execution / real targets: BLOCKED** (separate
   environment track; nothing claimed).
8. **MCP schema validator is a documented subset** (no `$ref`/`oneOf`/`not`); security
   enforcement remains in Broker validation, not in the schema layer.
9. **Fresh-clone line-ending defect fixed:** `.gitattributes` forces LF checkout; strict
   clone of committed HEAD passes the Skill/UTF-8 tests. `core.autocrlf=true` remains in
   the machine/global config (unchanged; not modified).
10. **Round 1 defects found previously are permanently regression-tested** (execution-row
    request/result JSON, durable Task evidence head, non-empty privacy-gate evidence
    files) — the three former XPASS tests are now normal tests and pass.

---

## 5. Repository, build and change summary

- Branch history on `feat/round2-harness-integration`: `e40f76f` (Round 1) → `8615af6`
  (P0 source recovery) → `d69b949` (Round 2 implementation) → report commit.
- Implementation commit diff stat: **93 files changed, 13,437 insertions(+), 446
  deletions(-)** (`git show --stat d69b949`); includes new `security/`, `intake.py`,
  `session_logs.py`, `approval_grant_service.py`, `mcp/schema.py`, `acp/launch.py`,
  stdlib wheel backend/tooling/scripts, Round 2 docs, tests and evidence.
- Per-file SHA-256/size manifest for the implementation commit:
  `round2-evidence/FILE_MANIFEST.txt` (225 tracked files). A final manifest for the
  report commit is added as `round2-evidence/FINAL_FILE_MANIFEST.txt`.
- Wheel: `ctf_solver-0.1.0-py3-none-any.whl`, 204,840 B, SHA-256
  `6278B15FFEE1C61433618FCAAD05FE169C6E2C7F51864655203A2B4B82167FE2` (deterministic in
  fresh clone).
- Synthetic end-to-end run directory: `round2-evidence/end-to-end/` (`writeup.md`,
  `evidence.zip`, `screenshot.png`, `synthetic_challenge_input.txt`; runtime databases
  and CAS remain outside Git and were removed from the working tree after the run).

---

## 6. Environment / protected-state verification

| Check | Result |
|---|---|
| Round 1 branch | `feat/round1-complete-product-core` still at `e40f76f317ec3f3186e0120744af2f5924d32721` |
| No push / PR / merge | `origin` untouched; no PR created or merged; PR #1 untouched |
| `D:\CTFworker` 110 uncommitted files | untouched: 43 porcelain entries, fingerprint `C944E18C…622592A7` unchanged |
| Protected local audit report | size 46,444 B, SHA-256 `955136d1…fe5373` unchanged (read-only) |
| Harness live profiles/config | `~/.dsh/profiles` 775 files, max mtime `2026-11-10T01:52:31`; isolated `DSH_HOME` used for every real ACP run; no stray global `profiles` |
| Software installation | none |
| WSL/Docker | not deployed/started |
| Real CTF targets / challenge code | none contacted/executed |
| Model calls / `session/prompt` | **0** (client gate; no prompt issued) |
| Runtime data in Git | none; `.ctf-solver-data/`, `tasks/`, `challenge-uploads/` absent from the tree and git-ignored |
| Orphan processes | none from this work (no ctf-solver ACP/MCP/window probe processes remain) |

---

## 7. Stop declaration

Round 2 implementation and integration stop here. **Round 3 has not been started**, no
product scope was expanded or removed, nothing was pushed and no PR was created/merged.
The result is a Round 2 integration candidate that is independently reproducible
(clean clone + tests + wheel + evidence run) and is submitted for ChatGPT/owner
independent review.
