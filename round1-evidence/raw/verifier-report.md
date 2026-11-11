# Round 1 Independent Verification Report

**Verifier:** `verifier-round1` (independent; not an author of any product module)
**Task:** shared task `task-5` — independent adversarial verification of Round 1
**Repository:** `D:\CTF-SOLVER`, branch `feat/round1-complete-product-core`, HEAD `960252ab48d1810401a460f6b035b76348b2f520`
**Date:** 2026-11-10 (commands run 18:29–18:43 local, Asia/Shanghai / UTC+8)
**Environment:** Windows, Python 3.14.7, pytest 9.1.1, `zstandard` 0.25.0 (+ stdlib `compression.zstd`), audited Harness launcher present.
**Authorities used:** frozen `docs/ACCEPTANCE.md`, `docs/ROUND_1_IMPLEMENTATION_TASK.md`, `docs/PRODUCT_SPEC.md`, `docs/ARCHITECTURE.md`, `docs/SECURITY.md`, `docs/EXECUTION_CONTRACT.md`, `docs/DECISIONS.md` (ADR-018/019/020/021), `docs/INTERFACES.md`, plus the read-only full audit `D:\CTFworker\docs\HARNESS_INTEGRATION_CAPABILITY_AUDIT.md`.

**Independence statement.** The verifier wrote its own fixtures (`tests/support/verification_helpers.py`) and its own adversarial tests (`tests/test_verification_round1.py`, 63 test cases: 60 pass + 3 documented defects xfail). It did not reuse the authors' `tests/support/fakes.py`. It did not edit product source, other tests, docs, `pyproject.toml`, `.dsh`, or any Manager/ACP/evidence/policy/runtime/delivery code. It ran no git state-changing command and did not spawn subagents.

---

## 1. Commands and raw results

| # | Command | Result | Exit | Raw evidence |
|---|---|---|---|---|
| 1 | `python -m pytest tests -q -p no:cacheprovider` (authors' suite only, independent rerun) | **592 passed, 1 skipped** (skip = opt-in real ACP smoke, as designed) | 0 | [`verifier-authors-only-suite.txt`](verifier-authors-only-suite.txt); authors' own log [`../../round1-evidence/raw/all-tests-first-pass.txt`](all-tests-first-pass.txt) claims the same counts |
| 2 | `python -m pytest tests -q -p no:cacheprovider` (full suite **including** verifier tests) | **652 passed, 1 skipped, 3 xfailed** | 0 | [`verifier-full-suite.txt`](verifier-full-suite.txt) |
| 3 | `python -m pytest tests/test_verification_round1.py -q -p no:cacheprovider` (verifier's own adversarial suite) | **60 passed, 3 xfailed** | 0 | [`verifier-own-tests-final.txt`](verifier-own-tests-final.txt) (earlier iterations: [`run1`](verifier-own-tests-run1.txt), [`run2`](verifier-own-tests-run2.txt)) |
| 4 | `$env:CTF_SOLVER_ENABLE_REAL_ACP='1'; python -m pytest tests/test_real_acp_smoke.py -q -p no:cacheprovider` | **1 passed in 2.68 s** (zero-model-call: initialize, 2× `session/new`, active-session list check, close, stdin EOF) | 0 | [`verifier-real-acp-smoke.txt`](verifier-real-acp-smoke.txt) |
| 5 | Isolated-profile privacy-gate reproduction: `$env:DSH_HOME=<temp>; cmd /c '"...\dsh.cmd" --profile acp --patch "D:\CTF-SOLVER\config\acp\cordis.patch.yml" --dump-config'` | exit 0; composed config contains `patched by D:\CTF-SOLVER\config\acp\cordis.patch.yml` and `- id: session-log-deepseek … config: { enabled: false }`; only the temporary `DSH_HOME` was written (4 files), then removed; live `~/.dsh/profiles/desktop` mtime unchanged | 0 | [`verifier-privacy-gate-dump-config.txt`](verifier-privacy-gate-dump-config.txt), [`verifier-privacy-gate-result.txt`](verifier-privacy-gate-result.txt) |
| 6 | Read-only CLI: `python -m ctf_solver version`, `skills --root .`, `preflight --quiet`, `evidence --help` | all exit 0; `skills` reports six UTF-8/no-BOM/frontmatter-valid skills; `preflight` (quiet) exits 0 | 0 | [`verifier-cli.txt`](verifier-cli.txt) |

The 3 xfails are **verifier defect-documentation tests**, not author test failures: they assert the contracts the product currently violates (see §4 defects D1–D3) and are marked `xfail(strict=False)` so that fixing the defect makes them pass (`XPASS`).

No software was installed; no Harness global config/profile/plugin/MCP/Skill change was made; no WSL/Docker was started; no CTF target and no model call / `session/prompt` was performed by the verifier.

---

## 2. Independence and side-effect guards in the verifier tests

- Every verifier test runs under an autouse guard that makes `socket.create_connection`,
  `socket.getaddrinfo`, `socket.socket.connect` and `RuntimeExecutor._execute_subprocess`
  raise, and blocks `AcpClient.start`. Any accidental network destination, subprocess tool
  execution, or real ACP launch fails the test loudly. All tests still pass, so the
  verification suite made no network target access and no real ACP/model call.
- The only subprocesses the verifier suite permits are read-only local probes
  (`git status` on `D:\CTFworker`, Harness-preflight tool-version probes) and they are
  asserted not to launch `wsl`/`docker`/`runsc`.
- All fixtures write only under pytest `tmp_path`; repo runtime-data dirs
  (`.ctf-solver-data/`, `tasks/`, `captures/`, `exports/`) do not exist in the repository
  after the runs.
- The Manager is exercised through its real SQLite store, real CAS, real Broker/Runtime
  pipeline and real loopback IPC server; only the ACP client is a verifier-owned fake.
  The `session/prompt` method of that fake raises and records, and every Manager test
  asserts the record stays empty.

---

## 3. Protected environment and clean-room evidence

Baseline and end snapshots are machine-recorded in
[`verifier-environment-baseline.json`](verifier-environment-baseline.json) and
[`verifier-environment-end.json`](verifier-environment-end.json).

| Protected item | Start | End | Verdict |
|---|---|---|---|
| `git -C D:\CTFworker status --porcelain` SHA-256 (no writes by verifier; read-only) | `a28414c28d7b0df5c03ff7429083eaa2786a99d07e9ccc682399e9a20986dcac` | identical | **PASS** (unchanged) |
| `D:\CTFworker\docs\HARNESS_INTEGRATION_CAPABILITY_AUDIT.md` | size 46,444 B, SHA-256 `955136d156a878fc932243081cc42d72575bc4f65510dc03163cb689d7fe5373` | identical | **PASS** (matches task-mandated hash) |
| Live Harness profiles (`~/.dsh/profiles/*` mtime) | snapshot | identical (incl. `desktop`) | **PASS** (dump-config used a temp `DSH_HOME`; live profile untouched) |
| Repo HEAD / branch | `960252a…`, `feat/round1-complete-product-core` | identical | **PASS** (no commit/staging by verifier) |
| Repo runtime data in tree | none | none (`.ctf-solver-data`, `tasks`, `captures`, `exports` absent) | **PASS** |

**Observation (not a defect, not caused by the verifier):** between the verifier's initial
`git status` (all product files untracked, `?? ctf_solver/`, `?? tests/`, …) and the end
snapshot, the repository files were **staged** by concurrent Lead work: `git status`
now reports `A  ctf_solver/...`, `A  tests/...`, `M  .gitignore`, `M  README.md`, and
`AM round1-evidence/raw/verifier-full-suite.txt` (the last is the verifier's own log that was
staged and then re-written by a later verifier run). The verifier executed no `git add`,
`commit`, `reset`, `clean`, or other state-changing git command; HEAD is unchanged.

**Clean-room checks (code-level):** no product source contains `CTFworker`, `D:\CTF`,
`D:/CTF/`, `from backend`, `import backend`, `MVP_BACKEND`; no auto-install commands
(`pip install`, `winget`, `choco`, `apt-get`), no `docker run`/`wsl.exe` invocation;
`pyproject.toml` declares **zero** runtime dependencies (no installation required).
Full provenance review of external-reference copying is **NOT VERIFIED** (not possible from
code inspection; requires the owner's license/provenance review).

---

## 4. Defects found (ordered by severity)

### D1 — `executions.request_json` is always `{}`; denied-call `result_json` is `{}` (durable execution ledger loses the request document) — **Medium**

- **Where:** `ctf_solver/manager/store.py:526-559` (`record_execution`) reads
  `row.get("request", {})` / `row.get("result", {})` at lines **556–557**, but
  `ctf_solver/runtime/pipeline.py:578-579` supplies the keys
  `request_json` / `result_json`. The SQL columns `executions.request_json` /
  `executions.result_json` are therefore written as `{}` on insert.
  For an **allowed** call, `pipeline.py:326` later updates `result_json` via
  `update_execution`, but `request_json` is never repaired. For a **denied** call there is
  no update at all, so both the request and the denial result are lost from the
  `executions` row.
- **Impact:** the `executions` table (INTERFACES.md §2: "one row per ctf-exec call,
  allowed or denied") no longer keeps the original request/denial record that
  EXECUTION_CONTRACT.md §9 describes. The evidence hash chain still records the request in
  `execution_denied` payloads, so this is an audit-completeness/ledger defect, not a
  security-policy bypass.
- **Reproduction:** `python -m pytest tests/test_verification_round1.py::test_defect_execution_rows_lose_request_and_denied_result_json -q`
  → xfail (asserts `request_json["task_id"]`). Standalone probe: build a real
  `ManagerStore`+`EvidenceStore`+`Broker`+`ExecutionPipeline` on a tmp root, run one
  allowed and one denied call, then
  `SELECT request_json, result_json FROM executions` → both `request_json == "{}"`.
- **Expected fix (owner's decision, not applied by verifier):** pass `request`/`result`
  keys (or have the store read `request_json`/`result_json`), and cover denied rows.

### D2 — Durable `Task.evidence_head` is never populated; Writeup renders "unknown" — **Low–Medium**

- **Where:** `PRODUCT_SPEC.md:46` requires the minimum durable Task fields to include the
  evidence-chain head. `ManagerStore.update_task_fields` supports `evidence_head`
  (`ctf_solver/manager/store.py:168`) but **no Manager code calls it**
  (`ctf_solver/manager/service.py` emits events only). The Writeup therefore prints
  `Evidence chain head: 'unknown'` (`ctf_solver/delivery/writeup.py:137`), even when the
  task has a long evidence chain. `get_task_status()` reports the live chain head
  separately, so the information is not lost, only the durable Task contract is unmet.
- **Reproduction:** `python -m pytest tests/test_verification_round1.py::test_defect_task_evidence_head_is_never_persisted -q`
  → xfail (`store.get_task(...).evidence_head is None` after events exist; Writeup contains
  ``Evidence chain head: `unknown` ``).
- **Expected fix:** update the Task row's `evidence_head` (at least on task-level event
  append / before writeup/ZIP), or explicitly document the deviation as an accepted
  Round 2 item.

### D3 — Cited privacy-gate raw evidence files are empty (evidence-quality defect) — **Low**

- **Where:** `docs/ROUND_1_ARCHITECTURE_NOTES.md:82-84` and
  `round1-evidence/privacy-gate.md:36-39` cite
  `round1-evidence/raw/privacy-gate-exit.txt` and `privacy-gate-home-path.txt` as the raw
  output/home-path evidence. Both files are **0 bytes**; only `privacy-gate-result.txt`
  (16 B, `exit_code=0`) carries the exit code, and `privacy-gate-dump-config.txt`
  (12,380 B) carries the composed config.
- **Impact:** the *conclusion* is not affected — the verifier independently reproduced the
  mechanism (§1 item 5) and confirmed the composed config and untouched live profile. But
  the cited raw evidence is incomplete/mis-labelled and should be regenerated or the
  citation corrected.
- **Reproduction:** `python -m pytest tests/test_verification_round1.py::test_defect_privacy_gate_evidence_files_are_not_empty -q` → xfail.

### D4 — Required Round 1 deliverables not present yet (process gap) — **Deliverable gap**

- `docs/ROUND_1_IMPLEMENTATION_TASK.md:306` requires an "acceptance report using
  PASS / FAIL / BLOCKED / NOT VERIFIED". No such Round 1 acceptance report exists in
  `docs/` or `round1-evidence/` at verification time (only `privacy-gate.md` and raw logs).
  Likewise §5's "file/change manifest and Git commit SHA" is absent (HEAD unchanged,
  changes staged by the Lead, no commit/manifest). This report is the independent
  verifier's evidence; the Lead still owes the deliverable acceptance report.
- **Status: NOT VERIFIED (deliverable absent).**

### D5 — "Skills observed discovered by the local Harness" claim has no raw evidence — **Claim not proven (minor)**

- `README.md:83` and `docs/ROUND_1_ARCHITECTURE_NOTES.md:98-100` claim the six Skills were
  *observed discovered live* by the running Harness. The verifier confirms the discovery
  **preconditions** (exactly six project-local `.dsh/skills/*/SKILL.md`, UTF-8 without BOM,
  valid `name`/`description` frontmatter, `preflight` and `ctf_solver skills` report
  `ok: true`), but there is **no raw log/evidence file** for a live discovery observation,
  and the verifier did not create one (that would require touching the live Harness).
  Treat the "observed discovered" wording as **NOT VERIFIED** until raw evidence exists.

### D6 — `ctf_solver task …` CLI starts the real ACP client against the live profile (risk / not exercised) — **Risk, NOT VERIFIED**

- `ctf_solver/cli.py:107-136` (`task create|list|status`) calls
  `wiring.build_manager_service(config)` whose default ACP factory
  (`ctf_solver/wiring.py:49`) builds the environment with
  `build_acp_env(base=os.environ, dsh_home=config.extra.get("dsh_home"))` — i.e. **without**
  an isolated `DSH_HOME` unless the caller sets one. Those commands therefore start the real
  audited ACP server on the **live** Harness profile and `create` issues a real
  `session/new`. This is documented as "real wiring" in `docs/LOCAL_OPERATION.md:61-70` and
  does not issue `session/prompt`, but it is not verified and can interact with live
  Harness session state. The verifier deliberately did **not** run it (round constraint: do
  not touch global Harness state). Recommend a `--dsh-home`/isolated-profile requirement or
  an explicit warning for these commands in Round 2.

---

## 5. Verdict matrix — `docs/ACCEPTANCE.md` §J Round 1 gates

| Round 1 gate (`ACCEPTANCE.md` §J) | Verdict | Evidence / reason |
|---|---|---|
| Manager ACP Client, Task registry, one-Task/one-session mapping, max-two FIFO scheduler, persistence | **PASS** | verifier manager tests (2 active + 3rd queued + promotion; persisted session/workspace/token; no `session/list` dependence); authors' transport/ACP tests; real ACP smoke (table §1 item 4) |
| Manager control MCP interface + Worker-facing typed `ctf-exec` MCP interface | **PASS** | tool list exactly the 19 frozen `ctf_*` tools; one typed `ctf_exec` tool, argv array only, identity from env/outer IPC token; end-to-end fake-ACP stack test in authors' suite |
| Broker approval/network-grant validation implemented and fail-closed tests pass | **PASS** | 20-case denial matrix with spy executor (no executor call on denial), approval matrix (missing/cross-task/expired/pending/already-used/wrong digest), grant matrix (task/profile/host/port/protocol/method/path/expiry/exhaustion), redirect + DNS revalidation, network disabled fails closed |
| Six Skills present and discovered from project-local bundles | **PASS (present) / NOT VERIFIED (live discovery claim)** | format/UTF-8/no-BOM/frontmatter verified by verifier and `ctf_solver skills`; "observed discovered" has no raw evidence (D5) |
| Read-only preflight without installing/configuring | **PASS** | verifier test runs preflight on an empty temp root and the repo root: root bytes unchanged, `read_only=true`, `mutations=[]`, no wsl/docker/runsc subprocess; CLI `preflight --quiet` exit 0 |
| Multi-frame zstd ingestion, SQLite hash chain, CAS, derived JSONL, idempotency | **PASS** | verifier independent tests: 2-frame decode + line split across frames, truncated/corrupt gaps, call/result correlation, idempotent re-ingest (0 appended), independent chain recomputation, trigger tamper + DROP-TRIGGER tamper + truncation detection, deterministic byte-identical JSONL export twice and after reopen, CAS verify/corruption fail-closed |
| Explicit screenshot association, Markdown Writeup, evidence ZIP, manifest verification | **PASS (fake capture) / NOT VERIFIED (real desktop capture)** | screenshot metadata bound to Task/Worker/Step/session/time, CAS SHA-256, blank capture recorded as failure; Writeup deterministic and ZIP reproducible with independently verified `manifest.sha256`; real desktop capture is honestly labelled NOT VERIFIED in docs and was not exercised |
| Fake ACP/MCP and synthetic end-to-end tests pass | **PASS** | full suite 652 passed / 1 skipped / 3 documented xfails, exit 0 |
| Zero-model-call real ACP lifecycle smoke test (existing installation) | **PASS** | independently rerun: 1 passed, exit 0, isolated temporary `DSH_HOME`, `session/prompt` gate raised before any transport write |
| Round 1 report distinguishes implementation from real Harness/model integration | **NOT VERIFIED (deliverable absent)** / wording honest | no formal acceptance report file exists (D4); README §Status and `ROUND_1_ARCHITECTURE_NOTES.md` §4/§6 do honestly mark BLOCKED/NOT VERIFIED items |

### `docs/ROUND_1_IMPLEMENTATION_TASK.md` §3 A–I

| Section | Verdict | Notes |
|---|---|---|
| A. Repository and packaging | **PASS** | clean layout; `pyproject.toml` with **no** runtime deps (nothing installed); six project-local skills; `.gitignore` covers all runtime data; no runtime dirs in tree |
| B. Core Skill + five specialist Skills | **PASS** | exactly six; UTF-8 no BOM; frontmatter `name`/`description`; intake/routing/persistent-mode content present; specialists state Web grant-only, Misc bounded-attempt budget, Crypto structure-first, Reverse Tier-2-blocked, Pwn scoped-remote authorization; skills explicitly say Manager/Broker enforce permissions |
| C. Manager, ACP Client, Task lifecycle, scheduler | **PASS** with one Round-2 item | ND-JSON/JSON-RPC transport matrix (authors' tests), persisted-before-ready proven by verifier callback (`starting` + no Worker row at `session/new` time), one-session/one-workspace, 2+FIFO+promotion, truthful `cancel_requested` when close fails (slot held), shared-ACP failure interrupts (never completes), recovery preserves mapping and creates no duplicate session. **Successful resume is NOT implemented in Round 1** (documented; Round 2 item) |
| D. Manager control interface, MCP, ctf-exec, Runtime, Broker | **PASS** | 19 control tools; typed argv-only exec; Broker fail-closed order verified; denied-before-execution vs executed-but-failed distinguished by spy executor; untrusted/Tier-2/tool-version/cwd/paths/inputs/outputs/limits denials all verified; no shell tool in manager/exec/default catalogue |
| E. Approval and network-scope model | **PASS (contracts + logic)** | Task-scoped approvals consumed once; grants scoped by task/profile/host/port/protocol/method/path/TTL/call-count; cross-task denial; redirect/DNS revalidation; loopback/private require explicit `allow_private`; network tools are not functional in Round 1 and fail closed |
| F. Evidence ingestion, SQLite, CAS, privacy | **PASS (evidence) / BLOCKED (canary)** | see §J evidence row above. Session-log privacy: supported disable mechanism independently reproduced in an isolated `DSH_HOME`; the required negative outbound-delivery canary **cannot be run without a model call** (ADR-020) → **BLOCKED** |
| G. Explicit screenshots, Writeup, evidence ZIP | **PASS (fake capture) / NOT VERIFIED (desktop)** | explicit-only capture path, no continuous-capture loop; blank/failed honest; Writeup sections 1–8 generated from evidence; ZIP + manifest deterministic/reproducible; PDF out of scope |
| H. First-run preflight | **PASS** | read-only, machine+human report, available/missing/not-verified separated, no install/start; verifier confirmed no mutation and no WSL/Docker launch |
| I. Main-conversation integration feasibility gate | **BLOCKED (honestly reported)** | docs state no supported project-scoped MCP registration exists; Round 1 exposes a working Manager control MCP server but does not claim `/ctf-solver` is fully functional as a Harness entrypoint. Not a silent failure; BLOCKED is the correct verdict |

### `docs/ROUND_1_IMPLEMENTATION_TASK.md` §4 tests/evidence and §5 deliverables

| Requirement | Verdict |
|---|---|
| Required coverage list (ACP framing/correlation, mapping, 2+FIFO, isolation, recovery, MCP/Broker cases, approvals/grants, zstd/gaps/idempotency, chain tamper/CAS, screenshot, writeup/ZIP, skills, preflight) | **PASS** — authors' 592-test suite + verifier's 63-case independent suite cover every listed area |
| Zero-model-call real ACP smoke test | **PASS** — independently rerun |
| Working source for all in-scope modules | **PASS** (functions present and exercised) |
| Six project-local Skill files | **PASS** |
| Manager control + Worker execution MCP interfaces | **PASS** |
| Test fixtures/fake servers | **PASS** |
| Project metadata + no-install preflight | **PASS** |
| README + local operation instructions | **PASS** (checkable claims verified; see §6) |
| Architecture notes for unresolved Harness facts | **PASS** |
| Complete test commands/raw outputs/exit codes/environment snapshot | **PASS** (authors' raw logs + this report's raw logs/snapshots) |
| File/change manifest and Git commit SHA | **NOT VERIFIED — missing** (D4; HEAD unchanged, no manifest file) |
| Acceptance report with PASS/FAIL/BLOCKED/NOT VERIFIED | **NOT VERIFIED — missing** (D4; this verifier report is not the product acceptance report) |
| Explicit list of implemented-but-not-integrated functions | **PASS** — `ROUND_1_ARCHITECTURE_NOTES.md` §6 lists them |
| "Do not report MVP complete" | **PASS** — README says the opposite and marks Round 2 integration BLOCKED |

### `docs/ACCEPTANCE.md` A–I (Round 1-relevant summary)

| Gate group | Verdict |
|---|---|
| A. Conversation mode and Skills | **NOT VERIFIED** for `/ctf-solver` activation/persistence/new-conversation semantics (needs real Harness main conversation — Round 2); Skills presence/format **PASS**; First-Blood exclusion **PASS** (docs/product) |
| B. Manager, ACP, scheduling | **PASS** except "successful resume/recovery" — recovery-without-duplication **PASS**, successful resume **NOT IMPLEMENTED/NOT VERIFIED** (Round 2) |
| C. ctf-exec and Runtime | **PASS**, except the Tier-2-only Docker boundary rows: **BLOCKED** (Tier 2 unavailable); Docker-socket absence verified by code inspection, negative runtime proof **NOT VERIFIED** |
| D. Privacy, authorization, human control | mechanism **PASS**; canary **BLOCKED** (requires model call); grants/approvals/redirect/DNS/untrusted-code-blocked/human-Flag **PASS**; no target contacted by verifier tests **PASS** |
| E. Evidence and integrity | **PASS** (D1 is an internal ledger defect; hash-chain/SQLite/CAS/export/ids requirements pass) |
| F. Screenshot, Writeup, ZIP | **PASS** (fake capture); real desktop capture **NOT VERIFIED** |
| G. Product/environment separation | preflight/no-install/no-WSL-Docker/no-global-config **PASS**; `D:\CTFworker` unchanged **PASS**; `D:\CTF` untouched **NOT VERIFIED** (no baseline/never touched by verifier); CLI primary **PASS**; Cordis optional/no second loop **PASS** (not implemented, not required) |
| H. Local end-to-end MVP | synthetic execution→evidence→Writeup→ZIP **PASS**; 2+FIFO/continuation/pause/cancel/recovery **PASS**; session-log outbound-delivery proof **BLOCKED** |
| I. Tier 2 acceptance | **BLOCKED** (environment absent — correct) |
| J clean-room | no literal reuse/references **PASS**; full copied-code provenance review **NOT VERIFIED** |

---

## 6. Claims vs. proof

| Claim (location) | Verifier finding |
|---|---|
| "592 passed, 1 skipped" first pass (`round1-evidence/raw/all-tests-first-pass.txt`) | **Reproduced independently** (592/1, exit 0) |
| "zero-model-call real ACP smoke PASS" (`ROUND_1_ARCHITECTURE_NOTES.md` §2) | **Reproduced independently** (1 passed, exit 0, isolated temp home, gate asserted) |
| "privacy-gate mechanism verified in isolated profile, live profile untouched" | **Verified independently** (composed config contains `enabled: false` under the project patch; live `desktop` profile mtime unchanged; only temp home written) — but cited raw files are partly empty (D3) |
| Negative outbound-delivery canary | **BLOCKED, honestly reported** (requires a model call; ADR-020) — not a pass |
| Main-conversation `/ctf-solver` → Manager tools | **BLOCKED, honestly reported** — docs do not claim it works |
| Skills "observed discovered by the local Harness" | **NOT VERIFIED** — no raw evidence; format preconditions pass (D5) |
| "Model-mediated Worker / `session/prompt` BLOCKED by design" | **PASS** — client gate raises `ModelCallNotAuthorized` before any write; `continue_task` emits `model_call_suppressed` and never calls `prompt` (verified with a fake that would record it) |
| "Desktop capture implemented but NOT VERIFIED" | **Honest** — verifier used the explicit fake capturer; real desktop capture remains NOT VERIFIED |
| "No arbitrary host Shell / no Docker Socket" | **PASS by code inspection + tests** — no shell-string execution, no shell tool in MCP surfaces, fixed-argv probes only, Docker appears only as preflight `which` instrumentation |
| "Round 1 does not claim final MVP acceptance" | **Honest** — README §Status says so |
| `executions` row keeps request/result | **Overstated by implementation** — D1 |
| Task minimum fields include evidence-chain head | **Not met** — D2 |

---

## 7. Residual risks and verification limitations (fairness statement)

1. **No model call / no real Worker turn:** Round 1 forbids it (ADR-020). Model-mediated reasoning, live ACP permission round-trips, in-flight cancel, and per-session `mcpServers` mounting under a real model turn remain **NOT VERIFIED** (correctly deferred to Round 2).
2. **No real desktop capture:** the desktop capturer code was inspected but not executed (it would capture the verifier's desktop; docs mark it NOT VERIFIED). Explicit capture metadata/CAS/blank handling were verified with the deterministic fake capturer.
3. **No packet capture:** "no model call / no target traffic" is established by design + the client-side gate + the verifier's socket/subprocess guard, not by a network capture.
4. **`D:\CTF` untouched:** no baseline existed at verification start and the verifier never touched it; only `D:\CTFworker` was baseline-hashed as required.
5. **Clean-room copying:** literal-reference scan passes, but no provenance/licence review of external reference repositories is possible from here.
6. **`ctf_solver task` CLI** was not executed because it starts the real ACP client against the live profile (D6).
7. **Git staging state changed concurrently:** the Lead staged the repository during verification (HEAD unchanged); the verifier did not run state-changing git commands.

---

## 8. Overall verdict

Round 1 is an **honest, substantially verified implementation candidate** that passes the
core Round 1 product gates (Manager/ACP lifecycle, 2+FIFO scheduling, typed fail-closed
`ctf-exec`, approval/grant scope, evidence chain/CAS/deterministic export, Skills,
preflight, explicit screenshots, Writeup + reproducible evidence ZIP, zero-model-call real
ACP smoke). It correctly reports its real limits (main-conversation entrypoint BLOCKED,
negative-delivery canary BLOCKED, model-mediated Workers BLOCKED, Tier 2 unavailable,
desktop capture NOT VERIFIED) and does **not** claim MVP completion.

It is **not defect-free**: one medium durable-ledger defect (D1: `executions` request/denial
JSON lost), one low–medium product-contract gap (D2: Task `evidence_head` never persisted),
one evidence-quality defect (D3: empty cited raw files), and two deliverable/claim gaps
(D4: no Round 1 acceptance report / change manifest & commit; D5: unverified live Skill
discovery claim). None of them is a security-policy bypass; all are precisely located and
reproducible in `tests/test_verification_round1.py`. The verifier did not fix any of them.

**Verdict summary:** PASS for the implementable Round 1 gates; BLOCKED for the
explicitly-deferred privacy canary / main-conversation entrypoint / Tier 2 / model-mediated
gates; NOT VERIFIED for live Skill discovery, real desktop capture, `D:\CTF` untouched
baseline, clean-room provenance, and the missing Round 1 report/commit manifest.

---

## 9. Evidence index (SHA-256)

| File | SHA-256 |
|---|---|
| [`verifier-full-suite.txt`](verifier-full-suite.txt) | `d60f1531ff8346a113f855eb0c2108b620982307fbb33eec3f92b6fefab06d2e` |
| [`verifier-authors-only-suite.txt`](verifier-authors-only-suite.txt) | `a8c2039d669189eb63d3c394806a58da5e03139d5c2a65cf6708a6d4bb8138b3` |
| [`verifier-own-tests-final.txt`](verifier-own-tests-final.txt) | `5acf333a41cfa4b668beed1daf086c6d5f5a90bb82f25790f84ab54f09e5fdd9` |
| [`verifier-real-acp-smoke.txt`](verifier-real-acp-smoke.txt) | `6f7a7423c03292b0f30058dc80730c148687f7e20dd214a197338771786d78e4` |
| [`verifier-privacy-gate-dump-config.txt`](verifier-privacy-gate-dump-config.txt) | `bbe8096fc2096203de0949f154fcd93ed1942247b21d6e82c38a93bc83eb568d` |
| [`verifier-privacy-gate-result.txt`](verifier-privacy-gate-result.txt) | `4a8e97240e8ce646167e0ea8c715ad82e805f924b69dd8dbf0e131361222b6bf` |
| [`verifier-cli.txt`](verifier-cli.txt) | `c4439823c38b01c6b1b3ca17414f6dcc22c22dd4e1fee7a4c1265b6d82f8d68a` |
| [`verifier-environment-baseline.json`](verifier-environment-baseline.json) | `5fbf5c30a3274061764a09e64165505bcdb51ab62f95ac760ee135b56637b407` |
| [`verifier-environment-end.json`](verifier-environment-end.json) | `76afb995f741c2a0cc52b2cead166f617a74828af5a9a9782968e5e7e23b3763` |

Verifier-authored test files: [`tests/test_verification_round1.py`](../../tests/test_verification_round1.py),
[`tests/support/verification_helpers.py`](../../tests/support/verification_helpers.py).
