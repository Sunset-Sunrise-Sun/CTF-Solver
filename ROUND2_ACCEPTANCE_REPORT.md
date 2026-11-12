# CTF-Solver Round 2 — Minimal Delivery Fixes: Acceptance Report

**Date:** 2026-11-12 (Asia/Shanghai)
**Branch:** `fix/round2-minimal-delivery`, HEAD `d00cdbd5c45f1a7b2eb8afc683f2d0c7af9aa8bb`
(git worktree `D:\CTF-SOLVER\scratch\round2-minimal`), base `f30c9a24a0f341fadb0e08a77584902b1976c83d`
(Round 1 final, verified against bundle SHA-256 `c3ea4c93…3afd`).
**Verdict: PASS** (all Round 2 completion criteria met; two honest boundaries are listed in
§8: the Draft PR still cannot be pushed because GitHub is unreachable, and the committed
copies redact the temporary acceptance window PID per the task's "do not commit the test
PID/local config" rule).

---

## 0. Scope and baseline

Round 2 was executed exactly as "the last development round": on top of the Round 1 branch,
no product rebuild, no new Agent/framework, no third-party dependency, no DB migration, no
Worker ACP redesign, ADR-020 (`allow_model_calls=false`) unchanged, Lead remains the only
executor. Baseline verification before any edit:

- Round 1 bundle `dist/CTF-Solver-Lead-Session-Evidence.bundle` verified
  (`sha256=c3ea4c9374ef510a99fe6f6d5f35bf86aa036a66aeb09980e7ac0cc049af3afd`,
  complete history, ref `feat/lead-session-evidence` → `f30c9a2`).
- Round 1 worktree clean at `f30c9a2`; main checkout untouched
  (`21908de`, only the three pre-existing untracked user items).
- User files protected before development: `.dsh/mcp.servers.yml`,
  `CTF-Solver-HARNESS-INSTALLATION-ACCEPTANCE.md`, `solutions/` copied to
  `scratch/protected-baseline-round2/20261112-0945/` with a SHA-256 manifest
  (original MCP config SHA-256 `e3038979…46c2`).
- New isolated worktree `D:\CTF-SOLVER\scratch\round2-minimal`, branch
  `fix/round2-minimal-delivery` from `f30c9a2`; the main checkout was never switched.

---

## 1. What was changed (commit `d00cdbd`, 21 files +2266/−106)

### P0-1 — real target-window capture wiring (no new capture algorithm)
- `SolverConfig.capture_mode` now defaults to `real-window`; new
  `target_window_pid: int | None` (validated as a positive non-bool int). The default config
  remains constructible without a PID for non-capture code paths.
- `build_capturer(mode="real-window", *, target_pid=None)`: the real-window mode requires an
  explicit positive PID and otherwise raises `ConfigError` (fail closed); `desktop` keeps the
  legacy capturer, `fake`/`fake-blank` are test-only, unknown modes fail. The existing
  `WindowCapturer`/PrintWindow implementation is reused unchanged; there is no auto window
  discovery and no desktop fallback on capture failure.
- `wiring.py` passes the configured PID; `ctf_solver manager serve` and the Manager MCP
  server accept `--capture-mode` (default `real-window`) and `--target-window-pid <PID>`;
  `ctf_solver task` keeps `fake`. `ctf_screenshot_capture` keeps exactly 18 tools and its
  optional `scope` (handler default `None`).
- `ManagerService.take_screenshot(scope=None)`: exactly one capture attempt, no retry and no
  desktop fallback; `real-window` failure/blank is recorded honestly.
- Screenshot events now record `screenshot_id`, `capture_method`, `target_pid`, `scope`,
  `session_id`, `worker_id`, `step_id`, `width`/`height`, `sha256`, `captured_at`,
  `failure_reason`. No database column/table/migration was added.

### P0-2 — screenshot ownership
- For a Task with a Lead-session binding, the screenshot record/event use
  `worker_id = null` and `session_id = <Lead session id>`, and `scope="desktop"` is refused
  with a `ValidationError` (never silently downgraded). Worker-only Tasks keep the previous
  ownership/default behaviour.

### P0-3 — Writeup actually shows the work
- Section 3 now lists Harness-native Lead `tool_call` names (`Harness-native tool call
  (tool version not recorded separately)`) separately from Worker `ctf-exec`
  tool/version executions, and never claims "No tool executions were recorded" when real
  `tool_call` evidence exists.
- Successful screenshots are embedded as `![Screenshot <id>](screenshots/<id>.png)` with a
  metadata line (sha256, ISO capture time, WxH, `capture_method`, `target_pid`, `scope`,
  `session_id`); `WriteupBuilder.build` materialises the PNGs under
  `tasks/<task_id>/screenshots/` from the CAS so both the standalone `writeup.md` and the
  extracted ZIP render the image. Failed/blank/CAS-missing captures render
  `screenshot unavailable: …` and no link.
- P1-1 gap status: `unmatched_call`/`unmatched_result` gaps are classified as
  `resolved (matched by a later ingestion)`, `Expected capture-boundary gap` (the last
  `ctf_session_ingest` self-call), or `unresolved`; sections 5/7 split accordingly. The
  append-only DB events are never deleted or mutated.

### P0-4 — default delivery privacy policy
- New `ctf_solver/delivery/privacy.py` is the single projection shared by `events.jsonl`,
  the Writeup and the ZIP: default-deny allowlist (drops `assistant_message`, `passthrough`,
  job/command/session-title and unknown types), turn/step reduced to numeric metadata,
  Skill tool-result bodies replaced with
  `Skill loaded: <name> (content omitted by delivery privacy policy)`, real tool/execution/
  lifecycle/approval/grant/flag/screenshot/gap evidence retained.
- `export_events_jsonl(..., privacy_filtered=True)` defaults to the delivery view
  (raw view still available internally for verification).
- The evidence ZIP no longer contains raw session logs (`raw/session-*.jsonl.zstd`); the raw
  bytes remain in the local CAS. Manifest/deterministic rebuild/internal verification intact.
- P1-2 `ctf-solver/SKILL.md` now requires, after the category is known and before reading
  any challenge material, an actual native
  `skill({"name": "ctf-<category>"})` load (web/misc/reverse/crypto/pwn mapping), with
  stop-and-report on failure; discovery output is explicitly not a substitute. The five
  category Skills keep their professional methods and safety rules.

Lead-owned integration edits outside the three work streams: `core/protocols.py`
(`take_screenshot(scope: str | None = None)`), `scripts/round2_integration.py` (pass the
probe PID into `SolverConfig` instead of patching the capturer after wiring), and the wheel
member expectation in `tests/test_wheel_provenance.py` (new module → 66 members/65 RECORD
entries).

---

## 2. Tests, static checks, packaging

| Check | Result |
|---|---|
| Full suite (frozen HEAD `d00cdbd`, `python -m pytest -q`) | **1141 passed, 5 skipped, 1 failed** in 84.9 s |
| The one failure | `tests/test_verification_round1.py::test_protected_ctfworker_state_and_audit_hash_unchanged` — pre-existing environment drift (live `~/.dsh/profiles/desktop` mtime vs a 2026-11-09 snapshot). The independent verifier reproduced the **identical** failure at base `f30c9a2`: expected `1794246751302462400`, actual `1794409697473832700`. Not a Round 2 regression. |
| Focused Round 2 files | **149 passed** (verifier), 45–66 passed per owner sets |
| Independent verification matrices | 16/16 (contract/capture/privacy/writeup/gap/regression), 10/10 (extras), 11/11 (packaging/hygiene) — verdict **PASS** |
| Ruff (`python -m ruff check` on 20 changed/new Python files) | **0 new findings** vs base (frozen 28 pre-existing vs base 31); new files clean. Repo-wide lint debt is pre-existing and out of Round 2 scope. |
| Wheel (in-tree stdlib PEP 517 backend) | `ctf_solver-0.1.1-py3-none-any.whl`, **66 members, RECORD 65/65 verified**, determinism checked, sha256 `54e1bd2e6369faaf083fe0c8c7d8cef1b37ed1cbf886371ae1a68b6010b75952`; installed offline into the managed venv (`0.1.1 / schema 1.2`, `take_screenshot(scope: str | None = None)`, privacy module present) |
| Skills | `python -m ctf_solver skills --root <root>` → `ok=true, found=6, missing=[]` |
| MCP surface | exactly 18 `ctf_*` tools; `--target-window-pid` accepted; live `ctf_runtime_status` works |
| No new dependencies / no DB migration | `project.dependencies == []`; build-system `requires=[]`; schema unchanged (13 tables, version 1.2) |
| ADR-020 | `allow_model_calls=false` in the live Manager diagnostics |

---

## 3. Live Harness acceptance (real run, not unit tests)

A **fresh Harness conversation** (`b0020ecd-237d-4264-8b38-bf00c8917a01`, its own
`DSH_SESSION_ID`) acted as the Lead executor. The project MCP config was temporarily
switched to
`--capture-mode real-window --target-window-pid <TARGET_WINDOW_PID>` and hot-reloaded (all
Manager processes showed both arguments); the original config was restored afterwards and
its SHA-256 re-matched the backup exactly.

| Item | Observed value |
|---|---|
| Task | `t-121579912bf84b35b574f88c45e33a96` (“Synthetic Round 2 acceptance misc”, misc) |
| Lead session / binding | `b0020ecd-237d-4264-8b38-bf00c8917a01`, `bound_by=lead`, binding log sha `21a09288…5dc95` |
| `/ctf-solver` + category Skill loading | `skill(ctf-solver)` at events seq 1131 → `ctf_task_create` seq 1137 → **`skill(ctf-misc)` seq 1143** → first glob/read only at seq 1149/1157. The `ctf-misc` Skill was loaded before any challenge file was read. |
| Task execution | Lead used native Harness tools only (read/glob/pwsh/write); Worker did not solve anything and no model calls were made. |
| Ingest #1 | 42 frames / 79 records / 80 appended / 0 skipped / raw_sha256 `b159e91f…78ac0` / 1 expected self-ingest gap |
| Ingest #2 | 50 frames / 91 records / 13 appended / **79 skipped duplicates** / raw_sha256 `88d63862…fae3d` / 1 expected boundary gap |
| Evidence events at completion | 57 rows: `tool_call=13`, `tool_result=12`, `assistant_message=0`, `passthrough=0` (full-suite transcript was 34 calls / 34 results) |
| Process screenshot | `shot-70fe96b7ec9c478986920e4cc6db0161`; `status=ok`; **780×330**; `capture_method=real-window`; `target_pid=<TARGET_WINDOW_PID>`; `scope=window`; `worker_id=null`; `session_id=b0020ecd…a01`; `step_id=turn1-step9`; sha256 `cd4aa8db…4278d9f` |
| Screenshot content check | Image inspected by the Lead: contains only the temporary target window (title bar + unique marker `CTF-SOLVER-R2-CANARY-TARGET-WINDOW-20261112`), **not** the desktop (780×330 vs desktop 1707×1067 at this DPI) and not any DeepSeek Harness UI. The same bytes are in the CAS and the ZIP. |
| Standalone Writeup | `tasks/t-121579912bf84b35b574f88c45e33a96/writeup.md`, 18 623 B, sha256 `9ac91654…be164`; contains `![Screenshot shot-70fe…](screenshots/shot-70fe….png)` plus the metadata line (sha256, captured_at, 780×330, `capture_method real-window`, `target_pid <TARGET_WINDOW_PID>`, `scope window`, session_id); section 3 shows Harness-native calls; gap section shows the expected capture-boundary gap. |
| Standalone image | `tasks/<task_id>/screenshots/shot-70fe….png` exists and its sha256 equals the screenshot record. |
| Evidence ZIP | `tasks/t-121579912bf84b35b574f88c45e33a96/evidence.zip`, 26 731 B, sha256 `f258c4a4…c19847`; members exactly `events.jsonl`, `manifest.sha256`, `screenshots/shot-70fe….png`, `writeup.md`; **no `raw/` member**; manifest 3/3 entries verify, no extra/missing files. |
| Raw log preservation | Ingest raw logs remain in the local CAS (`88d63862…` 77 422 B and `b159e91f…` 73 927 B, hashes re-verified); the ZIP excludes them. |
| Notes/completion separation | `notes` still contains `R2-INTAKE-NOTES-CANARY-20261112` verbatim (192 chars); `completion_note` is the separate 102-char outcome note. |
| Evidence chain | independent `evidence verify-chain` → `ok=true, records=1198, head=9cc02980ec245ffcd3065f08d210bc348f423b32eb7411dcfa7adee2198b0405`, chain head equals the Task `evidence_head` |
| Privacy canaries in deliverables | reasoning canary `R2-REASONING-CANARY-20261112`, passthrough canary `A skill is a reusable set of task-specific instructions`, Skill body canary `Inventory before acting`: **absent** from Writeup, `events.jsonl` and every ZIP text member (0 hits). `assistant_message`/`passthrough` event types are **absent** from the export. The challenge-content canary `R2-CHALLENGE-CONTENT-CANARY-20261112` **is present** in the tool evidence (read result and `solution_notes.md` write call), proving the real evidence was kept. |
| Config restore / cleanup | original `.dsh/mcp.servers.yml` restored, SHA-256 `e3038979…46c2` == backup; Manager hot-reloaded back to `desktop` with no target PID; temporary WinForms window closed; temporary intake directory removed after archiving the source. |
| Environment after run | live Manager still works (18 tools, ACP ready, chain 1198); Skills still 6/6.

The acceptance executor deliberately kept no test PID or local config in the committed
evidence: committed copies use `<TARGET_WINDOW_PID>` (the actual value is only in the local
screenshot metadata/event and in the final delivery message).

---

## 4. How to configure a real CTF target window

```yaml
# <workspace>/.dsh/mcp.servers.yml  (project-scoped, user-local; do NOT commit)
servers:
  ctf-solver:
    transport: stdio
    command: "<venv>/Scripts/python.exe"
    args:
      - "-m"
      - "ctf_solver"
      - "manager"
      - "serve"
      - "--root"
      - "<workspace>"
      - "--lead-sessions-root"
      - "<DSH_HOME>/sessions"
      - "--capture-mode"
      - "real-window"
      - "--target-window-pid"
      - "<TARGET_WINDOW_PID>"
```

* `<TARGET_WINDOW_PID>` is the PID of the process that owns the challenge/program window to
  capture; it is required in `real-window` mode (the Manager refuses to start the capturer
  without a positive PID and never falls back to the desktop).
* Lead-bound Tasks always capture that target window; an explicit `scope="desktop"` is
  refused. Worker-only Tasks may still use the legacy desktop capturer when the Manager is
  configured with `--capture-mode desktop`.
* Choose the PID yourself for each challenge session; there is no automatic window discovery.

---

## 5. Round 2 completion checklist — classification

| # | Criterion | Verdict | Evidence |
|---|---|---|---|
| 1 | Existing Harness environment can use CTF-Solver | **PASS** | 18 tools, ACP ready, live flows, config hot reload |
| 2 | Lead is the only actual solver | **PASS** | Lead session evidence; Worker model calls blocked; 13 tool calls from Lead |
| 3 | Category Skill actually loaded | **PASS** | `skill(ctf-misc)` seq 1143 before first file read seq 1149 |
| 4 | Real tool calls/results in the evidence chain | **PASS** | `tool_call=13`, `tool_result=12`, chain 1198 records ok |
| 5 | Target-window screenshot really usable | **PASS** | `shot-70fe…`, 780×330, image inspected |
| 6 | Screenshot is not the whole desktop | **PASS** | 780×330 vs desktop 1707×1067; only the test window content |
| 7 | Screenshot ownership is the Lead | **PASS** | record `worker_id=null`, `session_id=<Lead>`, step `turn1-step9` |
| 8 | Writeup shows the real process | **PASS** | section 3 Harness-native calls + real args/results |
| 9 | Writeup embeds the screenshot | **PASS** | Markdown image + metadata; standalone and ZIP render |
| 10 | Historical gaps vs real unresolved gaps distinguished | **PASS** | tri-state logic + expected capture-boundary gap in the live Writeup; matrix coverage |
| 11 | Raw session log retained in local CAS | **PASS** | both raw hashes present and re-verified; not in ZIP |
| 12 | ZIP excludes raw log, reasoning, passthrough, Skill body | **PASS** | member list, 0 canary hits, 0 assistant/passthrough rows |
| 13 | ZIP file and manifest complete | **PASS** | 4 members, manifest 3/3 OK, deterministic |
| 14 | Evidence chain intact | **PASS** | ok=true, 1198 records, head matches task |
| 15 | Full regression has no new failures | **PASS** | 1141 passed / 5 skipped / 1 pre-existing drift, identical at base |
| 16 | No new third-party dependencies | **PASS** | `dependencies=[]`, build requires `[]`, stdlib only |
| 17 | Draft PR or verifiable Bundle delivered | **PASS (bundle)** / **BLOCKED (push)** | bundle verified + cloneable; GitHub unreachable from this environment, so the branch cannot be pushed/PR-opened here (see §8) |

---

## 6. Independent verification

The independent verifier (separate read-only worktree + clean detached base worktree at
`f30c9a2`) re-ran everything on the frozen commit `d00cdbd` and returned **PASS**:

- frozen state recorded, `git status --porcelain` empty before/after; no product/tests/git
  edits by the verifier; it did not touch the parallel live acceptance run.
- full suite 1141 passed / 1 failed (identical baseline drift at base) / 5 skipped;
  focused Round 2 files 149 passed; matrices 16/16, 10/10, 11/11; skills 6/6;
  wheel 66/65 RECORD, deterministic, sha256 `54e1bd2e…`;
  Ruff delta 0 new findings; no new deps; no DB migration; 18 tools; ADR-020 preserved;
  Lead binding/Worker path/notes-completion regressions intact.
- Report + raw matrices: `round2-minimal-evidence/raw/verifier-r2/` (committed with this
  report).

---

## 7. Repository changes and delivery

- Code/tests/docs commit `d00cdbd` (21 files, +2266/−106), no local config, session log,
  database, screenshot runtime data or Flag values committed.
- Delivery evidence: `round2-minimal-evidence/` (text only; curated raw logs, verifier
  report, acceptance executor report, config-restore proof, wheel logs, sanitized copies).
- Draft PR equivalent: full-history git bundle
  `D:\CTF-SOLVER\dist\CTF-Solver-Round2-Minimal-Delivery.bundle` containing
  `feat/lead-session-evidence` (Round 1) and `fix/round2-minimal-delivery` (Round 2);
  `git bundle verify` + clone checks in the final delivery message. Proposed base:
  `release/v0.1.1-final` (the remote branch whose tree equals the Round 1 v0.1.1 baseline
  `21908de`; `main` also works — the branch is main-descended). PR description:
  `round2-minimal-evidence/DRAFT_PR.md`.

---

## 8. Honest boundaries

1. **Draft PR push is BLOCKED in this environment**: `github.com:443` is unreachable
   (`git ls-remote` fails, no `gh`). The bundle + PR description are the reviewable
   equivalent; pushing and opening the Draft PR is a network operation for the owner.
2. **Temporary target-window PID is not committed** (per the task rule); committed reports
   use `<TARGET_WINDOW_PID>`. The actual acceptance value is shown in the final delivery
   message and remains in the local screenshot metadata.
3. Desktop capture is intentionally unusable for Lead-bound Tasks by design; a production
   setup must configure `real-window` + a real target PID. The restored (original) local MCP
   config uses `desktop`, so a Lead-bound screenshot in this restored environment would be
   refused — this is the required fail-closed behaviour, not a defect.
4. One Lead session binds one Task, and the evidence window is the whole bound session
   (Round 1 limitation, unchanged; multi-Task windowing remains deferred).
5. HTTP evidence is result-level; very long tool output may be Harness-spilled
   (preview-only) — unchanged from Round 1.
6. Repo-wide Ruff debt (143 findings at base) is pre-existing; Round 2 introduces 0 new
   findings on its changed files.
7. The installed managed venv now contains the Round 2 wheel (that is the environment
   integration evidence). Rollback: reinstall the v0.1.1 release wheel or the Round 1 wheel
   from the local release assets documented in `docs/LEAD_SESSION_EVIDENCE.md`.
