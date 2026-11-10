# Round 1 Acceptance Report — Complete Product Core

**Status:** Round 1 implementation candidate (NOT final MVP acceptance)
**Branch:** `feat/round1-complete-product-core` (not pushed; no PR created or merged)
**Frozen documentation baseline:** `960252ab48d1810401a460f6b035b76348b2f520`
**Implementation commit:** `bf50b85a6790a50764d5568bc76250234dd28732`
**Round 1 development model:** one concentrated round; Round 2 has NOT been started.
**Report date:** 2026-11-10 (Asia/Shanghai)

This report follows `docs/ROUND_1_IMPLEMENTATION_TASK.md` §5 and the reporting rule in
`docs/ACCEPTANCE.md`: every claim is marked **PASS / FAIL / BLOCKED / NOT VERIFIED**, with
the command, environment, fixture and raw evidence reference. A blocked test is not a
pass, and "code exists" is not treated as evidence.

---

## 1. Executive summary

Round 1 delivered the complete first-version product structure, not an ACP-only slice:

- Manager + robust ACP Client over stdio ND-JSON / JSON-RPC 2.0.
- Task/Worker/ACP-session/workspace registry with durable SQLite persistence before a
  Worker is marked ready; Manager-owned active-session registry.
- Maximum two active Workers with strict FIFO queueing, promotion, failure isolation and
  restart recovery that never duplicates sessions; truthful pause/cancel semantics (ACP
  cancel is never described as an OS kill; a slot is held until quiescence).
- Manager control MCP surface and Worker-scoped MCP server exposing exactly one typed
  tool `ctf_exec` (argv array, environment identity, no shell/command string).
- Broker policy (ownership, tool allowlist/version, argv schema, path containment, input
  hashes, execution tier, Task-scoped approvals and target grants, redirect/DNS
  revalidation logic) and typed Runtime for trusted tools only.
- Evidence pipeline: complete multi-frame zstd decoding, call/result correlation, explicit
  gaps, idempotent ingestion, SQLite append-only hash chain, SHA-256 CAS, deterministic
  `events.jsonl` export derived from committed SQLite rows.
- Explicit screenshot capture with blank/failure handling; chronological Markdown Writeup;
  deterministic evidence ZIP with independently verified `manifest.sha256`.
- Core Skill + five specialist Skills under `.dsh/skills/`, read-only preflight/doctor,
  CLI, and a project-scoped session-log privacy sample for isolated `DSH_HOME` only.

**Verified numbers (final runs):**

| Run | Result | Exit | Raw log |
|---|---|---|---|
| Full suite, default (real-ACP smoke opt-in off) | **654 passed, 1 skipped, 3 xpassed** | 0 | `round1-evidence/raw/final-full-suite.txt` |
| Full suite incl. real zero-model-call ACP smoke | **655 passed, 3 xpassed, 0 skipped** | 0 | `round1-evidence/raw/final-full-suite-with-real-acp.txt` |
| JUnit totals (with real ACP) | **658 cases, 0 failures, 0 errors, 0 skipped** | 0 | `round1-evidence/raw/junit-final-with-real-acp.xml` |
| Zero-model-call real ACP smoke | **1 passed (~4 s, isolated DSH_HOME)** | 0 | `round1-evidence/raw/real-acp-smoke-pytest.txt` |
| Independent verifier suite | 60 passed + 3 xpassed (defects fixed) | 0 | `round1-evidence/raw/verifier-tests-postfix.txt` |
| Read-only preflight | all six Skills present, no mutation | 0 | `round1-evidence/raw/preflight-report.txt` / `.json` |

- No model call, `session/prompt`, real CTF target, untrusted binary execution, software
  installation, WSL/Docker start, or Harness global configuration change was performed.
- `D:\CTFworker` was not modified (git-status fingerprint and audit SHA-256 unchanged).
- Honest blockers remain for Round 2 (main-conversation entrypoint, session-log negative
  delivery canary, model-mediated Workers, Tier 2 isolation).

---

## 2. Deliverables

| Deliverable | Location |
|---|---|
| Product source (Manager/ACP/MCP/Broker/Runtime/evidence/delivery/preflight/CLI) | `ctf_solver/` (52 `.py` files, ~16.7k lines incl. comments/docstrings) |
| Six project-local Skills (UTF-8, no BOM) | `.dsh/skills/{ctf-solver,ctf-web,ctf-misc,ctf-crypto,ctf-reverse,ctf-pwn}/SKILL.md` |
| Frozen module contracts | `docs/INTERFACES.md` |
| Architecture / integration limits | `docs/ROUND_1_ARCHITECTURE_NOTES.md` |
| Local operation manual | `docs/LOCAL_OPERATION.md` |
| Project metadata (no install required) | `pyproject.toml` |
| Project-scoped session-log privacy sample | `config/acp/cordis.patch.yml` |
| Tests (34 test modules + shared fakes/fixtures) | `tests/` (44 `.py` files, ~14.2k lines) |
| Raw test logs, verifier report, environment snapshot | `round1-evidence/raw/` |
| Privacy-gate evidence summary | `round1-evidence/privacy-gate.md` |
| File/change manifest (implementation commit) | `round1-evidence/FILE_MANIFEST.txt` |
| Env snapshot | `round1-evidence/environment-snapshot.txt` |

Runtime data (`manager.sqlite`, CAS, task workspaces, exports, screenshots) is git-ignored
and is not present in the repository tree.

---

## 3. Test evidence and commands

Command (from `D:\CTF-SOLVER`, Python 3.14.7, pytest 9.1.1, Windows 11 26200):

```powershell
# default deterministic suite (real ACP smoke intentionally opt-in)
python -m pytest tests -q -p no:cacheprovider

# full suite including the zero-model-call real ACP smoke
$env:CTF_SOLVER_ENABLE_REAL_ACP = '1'
python -m pytest tests -q -p no:cacheprovider
```

Per-suite case counts are in `round1-evidence/raw/test-counts-per-suite.txt`. Summary by
area (all green):

| Area | Cases |
|---|---|
| ACP transport/client/permission/contract | 73 |
| Broker policy + network grants | 200 |
| Manager service/store/scheduler/IPC | 30 |
| Manager MCP / protocol / Worker exec server | 26 |
| Runtime catalog/executor/tools/pipeline | 96 |
| Evidence zstd/normalize/store/ingest/CAS/manifest | 113 |
| Delivery (screenshot, Writeup, ZIP) | 12 |
| End-to-end stack (fake ACP + real MCP + Broker/Runtime + delivery) | 2 |
| Skills / preflight / core contracts / CLI | 42 |
| Independent verifier suite | 63 |
| Zero-model-call real ACP smoke | 1 |
| **Total** | **658** |

Notable end-to-end evidence (`tests/test_integration_stack.py`, 2 passed): a real Manager
MCP stdio server is spawned with the audited ACP Client connected to the fake ACP server;
three Tasks produce exactly two running Workers and one FIFO Task; Worker `ctf-exec`
requests travel through the Worker MCP server → Manager loopback IPC → Broker → Runtime and
return actual argv/cwd/exit code/stdout; a denied `tool.remote_probe` call is
distinguishable and never executes; session logs are ingested idempotently; an explicit
screenshot is bound and stored in CAS; a candidate Flag is recorded without submission;
Writeup and evidence ZIP are produced and the ZIP manifest verifies independently; cancelling
a running Task promotes the FIFO Task; a degraded Manager with an unavailable ACP command
serves control tools and keeps Tasks queued rather than faking execution.

---

## 4. Acceptance matrix

Legend: **PASS** = implemented and verified by deterministic test/evidence in this round;
**BLOCKED** = cannot be verified under the frozen environment/authorization; **NOT
VERIFIED** = implemented or partially implemented but not proven; **FAIL** = not met.

### 4.1 ROUND_1_IMPLEMENTATION_TASK.md sections A–I

| Requirement | Verdict | Evidence |
|---|---|---|
| A. Clean repository/packaging layout; project metadata without installing; Skills under project-level discovery path; UTF-8 no BOM; no-install start/preflight; runtime data git-ignored | **PASS** | `pyproject.toml`, `.gitignore`, `tests/test_skills.py`, `tests/test_preflight.py`, preflight report; no install performed |
| B. Core Skill + five specialist Skills; intake fields; persistent-mode instructions; routing; specialist category rules; skills are instructions not controls | **PASS (format/contract) / NOT VERIFIED (live behavior)** | Six `SKILL.md` files; `tests/test_skills.py`; session-log evidence of live catalog update `round1-evidence/raw/skill-discovery-session-summary.json`; live main-conversation behavior is Round 2 |
| C. Robust ACP Client (framing, correlation, interleaving, malformed, EOF, timeout, exit); explicit lifecycle states/diagnostics; audited launch command; one `session/new` per Task with `tasks/<id>/work`; persist mapping before ready; Manager registry; max 2 FIFO; restart recovery; truthful cancel; failure isolation; shared failure domain documented | **PASS** | `tests/test_acp_*.py` (73), `tests/test_manager_*.py` (30), `tests/test_scheduler.py`; zero-model-call real ACP smoke; `docs/ROUND_1_ARCHITECTURE_NOTES.md` §1–2; no OS-process/OS-isolation claim made |
| D. Manager control API/MCP; typed Worker `ctf-exec`; Broker validation (ownership, allowlist/version, argv schema/expansion, cwd/path, inputs/outputs, tier, approvals, Task-scoped target host/port/protocol/action/expiry/count, redirect/DNS); fail each closed; denied vs executed-failed; no arbitrary shell/socket | **PASS (implemented/denied matrix) / BLOCKED (Tier 2, real target)** | `tests/test_mcp_*.py` (26), `tests/test_broker_*.py` (200); `tests/test_runtime_*.py` (96); no network-capable tool is executable in Round 1 |
| E. Approval model + Task-scoped target grants; no cross-Task inheritance; public research separate; loopback/private not implicitly trusted; expired/mismatched/missing grants fail closed | **PASS** | Broker network/approval matrices; Manager approval/grant scoping tests; synthetic addresses only |
| F. Multi-frame zstd; normalization + call/result correlation; seq/job/approval/command preservation; idempotency; SQLite single authority + hash chain; CAS; deterministic derived JSONL (no dual-write); manifest verification; tamper/truncation/gap/crash tests; precise hash-chain claim; session-log privacy gate handled honestly | **PASS (pipeline) / BLOCKED (negative delivery canary)** | `tests/test_zstd_frames.py`, `tests/test_evidence_*.py` (113); tamper/gap/idempotency/determinism tests; `round1-evidence/privacy-gate.md`; canary test requires model call per ADR-020 |
| G. Explicit screenshot capture/attribution; CAS + SHA-256; reject/mark blank or failed; no fabricated screenshots; chronological Writeup structure; evidence ZIP + manifest; no PDF | **PASS (fake/capture-mode + metadata) / NOT VERIFIED (real desktop capture)** | `tests/test_delivery_*.py`; integration test uses explicit fake capture mode; desktop capturer implemented (`CopyFromScreen`, DPI-aware, blank detection) but not executed this round to avoid recording personal desktop content |
| H. Read-only preflight/doctor: OS/runtime facts, tool presence/version, Python modules, Skills prerequisites, privacy-gate status, not-installed vs not-verified, no WSL/Docker launch, machine+human readable | **PASS** | `tests/test_preflight.py`; `round1-evidence/raw/preflight-report.{json,txt}`; preflight performed no mutations (test snapshots tree) |
| I. Main-conversation integration feasibility: project-level Skill discovery; main conversation can reach Manager control tools without global config; per-session Worker MCP via `session/new.mcpServers`; project-scoped MCP/Host Plugin support | **BLOCKED (entrypoint) / PASS (Worker session MCP spec)** | Skill files + session-log catalog evidence exist; Manager control MCP server is implemented/tested as a real stdio process, but the audited Harness has no project-scoped MCP registration path, and attaching it to the live main conversation would require a global config/profile change (prohibited). Reported in `docs/ROUND_1_ARCHITECTURE_NOTES.md` §4 with smallest owner options; `/ctf-solver` is **not** claimed functional |

### 4.2 ACCEPTANCE.md "Round 1 — Complete Product Core" gates

| Gate | Verdict | Evidence |
|---|---|---|
| Manager ACP Client, task registry, one-Task/one-session mapping, max-two FIFO, persistence | **PASS** | ACP + Manager suites; integration stack |
| Manager control interface + Worker-facing typed `ctf-exec` MCP interface | **PASS** | `test_mcp_manager_server`, `test_mcp_exec_server`, protocol tests, integration stack |
| Broker approval/network-grant validation implemented and fail-closed tests pass | **PASS** | 200 broker policy/network tests with spy executor |
| Core Skill + five Skills present and discovered from project-local bundles | **PASS (present/format) / NOT VERIFIED (independent live discovery)** | `tests/test_skills.py`; session-log catalog evidence; Round 2 re-verification required |
| Read-only preflight reports availability without installing/configuring | **PASS** | preflight tests + report; no mutation |
| Multi-frame zstd ingestion, SQLite hash chain, CAS, derived JSONL export, idempotency tests | **PASS** | evidence suites |
| Explicit screenshot association, Markdown Writeup, evidence ZIP, manifest verification | **PASS** | delivery + integration tests; real desktop capture NOT VERIFIED |
| Fake ACP/MCP and synthetic end-to-end tests | **PASS** | full fake-ACP stack test; degraded-Manager test |
| Zero-model-call real ACP lifecycle smoke where the installation supports it | **PASS** | `round1-evidence/raw/real-acp-smoke-pytest.txt` (initialize v1, 2 sessions, list excludes active, close isolation, EOF exit 0) |
| Round 1 report clearly distinguishes implementation from real Harness/model integration | **PASS** | this report + `docs/ROUND_1_ARCHITECTURE_NOTES.md` |
| Clean-room: no old Workbench/D:\CTF/D:\CTFworker code/db/API/UI/service reuse; no reference-repo source copied | **PASS (by construction; no external source imported)** | independent implementation; third-party licenses not exercised; provenance review remains an owner audit item |
| No software install/upgrade; no Harness global config change; no WSL/Docker; no untrusted code; no real target; no automatic Flag submission | **PASS** | environment snapshot; verifier environment checks; integration/tests use synthetic fixtures only |

### 4.3 Mandatory P0 gates (two-round plan)

| P0 gate | Verdict |
|---|---|
| Session-log external delivery disabled/excluded by a supported verified mechanism before real CTF content | **PARTIAL PASS**: supported mechanism identified and verified in an isolated temporary `DSH_HOME` (composed config `enabled: false`, exit 0, live profile untouched). Negative outbound-delivery canary **BLOCKED** (requires a model call; ADR-020). Real CTF content is **not authorized** in Round 1. |
| Main conversation can invoke Manager control tools without global config changes | **BLOCKED** (documented limitation; options for owner decision in architecture notes) |
| One ACP session/workspace per Task; two-Worker FIFO enforced by Manager | **PASS** |
| Worker operations through typed ctf-exec + Broker; no arbitrary Shell/raw MCP/Docker Socket bypass | **PASS** (no shell-string surface; argv-only; environment identity; ACP host-tool permission requests rejected by default) |
| Task-scoped approvals/network grants fail closed | **PASS** |
| Evidence complete/reproducible/tamper-evident; gaps explicit | **PASS** (hash chain is tamper-evident relative to protected head; not a signature — documented) |
| User confirmation/submission for Flag retained | **PASS** (no submission tool exists; candidate state only) |

---

## 5. Independent verification findings and resolution

An independent verifier (separate teammate, no product-source edits) ran the authors' suite,
wrote a 63-case adversarial suite, reproduced the real ACP smoke and the privacy-gate
experiment, and reported six findings. Disposition:

| # | Severity | Finding | Status |
|---|---|---|---|
| D1 | Medium | Durable `executions.request_json` was always `{}` because Manager store read `request`/`result` while Runtime pipeline supplies `request_json`/`result_json`; denied rows lost `result_json` too | **FIXED** in implementation commit; verifier test `test_defect_execution_rows_lose_request_and_denied_result_json` now XPASSes; `store.record_execution` handles both key shapes |
| D2 | Low-Med | Durable `Task.evidence_head` was never persisted (Writeup rendered `unknown`) | **FIXED**; Manager refreshes and persists the chain head after manager events, on status/build/export; verifier test now XPASSes |
| D3 | Low | Cited privacy-gate raw evidence files `privacy-gate-exit.txt` / `privacy-gate-home-path.txt` were empty | **FIXED**; regenerated with exit code, command, DSH_HOME path and file inventory; verifier test now XPASSes |
| D4 | Deliverable gap | No Round 1 acceptance report / change manifest / commit SHA at verification time | **ADDRESSED** by this report, `round1-evidence/FILE_MANIFEST.txt`, implementation commit `bf50b85`, and the report commit |
| D5 | Claim not proven | "Skills observed discovered by Harness" had no raw evidence | **ADDRESSED HONESTLY**: session-log evidence added (`skill-discovery-session-summary.json`); wording now states session-log/session-reminder observation and marks independent live discovery as NOT VERIFIED / Round 2 |
| D6 | Risk | `ctf_solver task …` CLI could start the real ACP client with the live `~/.dsh` profile (no isolated home) | **FIXED**: Manager server and CLI now default to a project-local isolated `DSH_HOME` (`.ctf-solver-data/dsh-home`, git-ignored); using the live home requires explicit `--dsh-home`. Tests added (`test_cli.py`) and documented |

Verifier verdicts that remain valid: PASS for the implementable Round 1 gates; BLOCKED for
the four honestly reported integration gates; NOT VERIFIED for real desktop capture and
independent live Skill discovery.

---

## 6. Change manifest and commit

- Implementation commit: **`bf50b85a6790a50764d5568bc76250234dd28732`**
  (subject: `feat(round1): complete product core candidate (Manager/ACP/MCP/Broker/evidence/delivery)`).
  Parent: `960252ab48d1810401a460f6b035b76348b2f520` (frozen docs baseline).
  Diff stat: **140 files changed, 31,704 insertions(+), 14 deletions(-)** (`git show --stat bf50b85`).
- This report and any final evidence additions are in the follow-up local commit on the
  same branch; neither commit is pushed and no PR was created or merged.
- Full file/change manifest with per-file SHA-256 and size (implementation commit):
  `round1-evidence/FILE_MANIFEST.txt`.
- Tracked pre-existing files changed: `.gitignore` (runtime-data exclusions), `README.md`
  (Round 1 status, repository map, honest limitation links). No accepted product/decision
  document was modified.

---

## 7. Environment and protected-state verification

| Check | Result | Evidence |
|---|---|---|
| Branch/HEAD before commit | `feat/round1-complete-product-core` at frozen docs commit `960252a` | `round1-evidence/environment-snapshot.txt` |
| No software installation/upgrade | none performed | environment snapshot; verifier environment checks |
| No Harness global profile/config/plugin/MCP/Skill change | `~/.dsh/profiles` = **775 files**, max mtime `2026-11-10T01:52:31` (unchanged from the audit baseline); no global `profiles` directory left after isolated-gate runs | environment snapshot; verifier `verifier-environment-baseline.json` / `-end.json` |
| `D:\CTFworker` 110 pre-existing uncommitted files untouched | git-status porcelain fingerprint unchanged from start to end; no staging/clean/reset performed on that repo | verifier report §protected-state (TWO_ROUND plan); verifier baseline/end JSON |
| Local Harness audit report untouched | size 46,444 B, SHA-256 `955136d156a878fc932243081cc42d72575bc4f65510dc03163cb689d7fe5373` verified before reading and at end | environment snapshot; verifier report |
| No WSL/Docker deployment/start | none performed | verifier environment checks; `tests/test_preflight.py` isolation reporting |
| No real CTF target / real challenge data | synthetic fixtures only; no network target contacted | tests; architecture notes |
| No untrusted challenge code executed | Runtime has only Tier 0 internal tools + fixed-argv probes; challenge-code/tier2 calls fail closed | `tests/test_runtime_*.py`, `tests/test_broker_*.py` |
| No model call / `session/prompt` | 0; client gate raises `ModelCallNotAuthorized`; real ACP smoke asserts no prompt request is sent | ACP tests; real smoke log |
| No runtime data committed | `.ctf-solver-data/`, `tasks/`, `exports/`, `captures/` absent from tree; git-ignored | final `git status`; `.gitignore` |
| No orphan Worker/Manager processes after tests | final integration teardown; no `ctf_solver` worker processes observed | verifier environment checks; test teardown helpers |

The only write outside the repository made during the round was an **isolated temporary
`DSH_HOME`** under `%TEMP%` for the ACP smoke/privacy-gate evidence (deleted/left under temp
by design; never the live profile). An accidental empty/partial global `profiles` directory
created once during privacy-gate experimentation was removed after inspection and is absent;
the live Harness profile was never written.

---

## 8. Unresolved issues and Round 2 decisions required

1. **Main-conversation entrypoint (`/ctf-solver` → Manager control tools) is BLOCKED.**
   Skill discovery alone is not a working command surface. Smallest owner options are
   documented in `docs/ROUND_1_ARCHITECTURE_NOTES.md` §4: (a) authorize a profile-scoped
   MCP registration in a dedicated/isolated profile; (b) authorize a thin Cordis Host Plugin
   bundle that registers the Manager tools at Host level; (c) accept a user-launched local
   Manager server connected out-of-band. Round 1 does not assume any option.
2. **Session-log negative outbound-delivery canary is BLOCKED**: requires a real model
   request after the privacy gate, with separate owner authorization (ADR-020). Real CTF
   content must not be processed until Round 2 proves the canary is absent from
   `dsh_session_log` delivery.
3. **Model-mediated Worker / MCP `tools/call` by a model is BLOCKED** by design in Round 1
   (no `session/prompt`). Round 2 requires privacy-gate proof plus separate explicit
   authorization; otherwise that gate stays BLOCKED.
4. **Real Harness session-log ingestion is NOT VERIFIED**: ingestion is proven against
   synthetic multi-frame fixtures and fake-ACP-produced logs, not real Harness logs from a
   live model turn.
5. **Live in-flight ACP cancel/close and `session/request_permission` round trip during a
   real model turn are NOT VERIFIED**; Round 1 verifies the protocol paths, truthful state
   machine and Manager-side permission handling only.
6. **Real desktop screenshot capture is NOT VERIFIED** in this round (capturer implemented,
   blank/failure handling tested; integration uses explicit fake capture mode to avoid
   recording personal desktop content). Java/Qt/GPU capture remains unverified per audit.
7. **Approval-gated `ctf-exec` end-to-end binding not exercised**: the Broker's approval
   digest must be built from `policy.models.approval_details(request)`; both sides are
   tested independently, but no Round 1 tool both requires approval and is permitted (all
   such actions are denied earlier by the tier/denial policy). Round 2 integration tests
   should add a permitted approval-gated call.
8. **Tier 2 OS isolation is BLOCKED/unavailable** (Docker Engine/gVisor absent; WSL Ubuntu
   stopped); challenge-provided code execution remains prohibited. Separate environment
   track required before any claim of isolation.
9. **Independent live Skill discovery and clean-room provenance** are NOT VERIFIED by a
   second party in this environment; the session-log catalog evidence and construction-level
   independence are recorded, and Round 2 should re-verify both.
10. **Real Harness integration remains a separate acceptance event**: per
    `ROUND_1_IMPLEMENTATION_TASK.md` §5, this is a complete first-round implementation
    candidate, **not** "MVP complete".

---

## 9. Stop declaration

Round 1 is complete and stopped here. **Round 2 has not been started.** No push, PR or
merge was performed. The working tree is clean apart from the follow-up report/evidence
commit on the local branch. Independent review (project owner + ChatGPT) is requested
before any Round 2 work begins.
