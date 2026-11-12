# Independent Verification Report 鈥?Round 2 minimal delivery (FINAL 鈥?PASS)

| | |
|---|---|
| Task | `task-8` (shared board, owner `verifier-r1` as independent verifier) |
| Spec | `D:\CTF-SOLVER\scratch\round2-plan\INTERFACE_CONTRACT.md` (authoritative Round 2 A/B/C) |
| Artifact under test | `D:\CTF-SOLVER\scratch\round2-minimal`, branch `fix/round2-minimal-delivery` |
| Frozen HEAD | `d00cdbd5c45f1a7b2eb8afc683f2d0c7af9aa8bb` |
| Frozen tree | `5ab908deea2b901229d8850e371f421a3613eba1` |
| Base (Round 1 final) | `f30c9a24a0f341fadb0e08a77584902b1976c83d` in clean detached worktree `scratch/round2-plan/base-checkout` |
| Worktree cleanliness | `git status --porcelain` 鈫?**empty** (verified before and after all runs; verifier wrote only under `scratch/round2-plan/verifier-r2/`) |
| Environment | Windows, Python 3.14.7, pytest 9.1.1, ruff 0.14.10, `zstandard` 0.25.0; no network; no new deps |
| Verification mode | independent, read-only wrt product/tests/git; no commits; live Harness E2E run in parallel was **not** used as evidence and was not interfered with |

## 1. VERDICT

**PASS.**

All Round 2 contract sections A (real-window capture wiring + Lead screenshot
ownership), B (delivery privacy projection) and C (Writeup images/section 3, gap
tri-state, Skill loading rule) are implemented and behave as specified; the Round 1
regression constraints are intact; packaging/hygiene and determinism checks pass. The
full suite is green except for the single acknowledged, base-identical environment-drift
failure.

- Full suite: **1141 passed, 1 failed, 5 skipped in 82.16 s** 鈥?the only failure is
  `tests/test_verification_round1.py::test_protected_ctfworker_state_and_audit_hash_unchanged`,
  reproduced identically at base `f30c9a2` (搂9). No other failure.
- Focused Round 2 files: **149 passed**.
- Independent matrices: contract/capture/privacy/writeup/gap/regression **16/16 PASS**;
  remaining contract details **10/10 PASS**; packaging/hygiene **11/11 PASS**.
- In-tree wheel: `ctf_solver-0.1.1-py3-none-any.whl`, **66 members, RECORD verified
  65/65**, deterministic rebuild, SHA-256 `54e1bd2e6369faaf083fe0c8c7d8cef1b37ed1cbf886371ae1a68b6010b75952`.
- Skills: `python -m ctf_solver skills --root .` 鈫?`ok=true, found=6, missing=[], problems=[]`.
- Ruff: **0 new findings** introduced by Round 2 on the 20 changed/new Python files
  (frozen 28 pre-existing findings vs base 31; no new rule/code counts).
- No DB migration/schema drift, no new dependencies, no Harness plugin/agent/config change,
  `allow_model_calls=false` preserved, 18 MCP tools unchanged.

## 2. Exact commands and counts (frozen tree `d00cdbd`)

| # | Command (cwd `D:\CTF-SOLVER\scratch\round2-minimal`) | Result | Raw output |
|---|---|---|---|
| 1 | `python -m pytest -q` | **1141 passed, 1 failed, 5 skipped, 82.16 s** (only failure = baseline drift) | `r2_full_pytest.txt` |
| 2 | `python -m pytest tests/test_delivery_screenshot.py tests/test_lead_task_flow.py tests/test_manager_service.py tests/test_mcp_manager_server.py tests/test_cli.py tests/test_delivery_privacy.py tests/test_evidence_store.py tests/test_delivery_writeup_bundle.py tests/test_skills.py -q` | **149 passed, 9.33 s** | `r2_focused_pytest.txt` |
| 3 | `python -m ctf_solver skills --root .` | `ok=true, found=6`, no BOM/problems | `r2_skills.txt`, `r2_skills_final.json` |
| 4 | `python scratch\round2-plan\verifier-r2\r2_matrix.py` | **16/16 PASS** | `r2_matrix.txt`, `r2_matrix.json` |
| 5 | `python scratch\round2-plan\verifier-r2\r2_extras.py` | **10/10 PASS** | `r2_extras.txt`, `r2_extras.json` |
| 6 | `python scratch\round2-plan\verifier-r2\r2_packaging_hygiene.py` (+ `r2_ruff_compare.py`) | **11/11 PASS**, ruff delta **0 new** | `r2_packaging_hygiene.txt`, `r2_packaging_hygiene.json`, `r2_ruff_compare.txt`, `r2_ruff.txt` |
| 7 | base-checkout: `python -m pytest tests/test_verification_round1.py::test_protected_ctfworker_state_and_audit_hash_unchanged -q` | **1 failed** with identical assertion values | `r2_baseline_drift_base.txt` |
| 8 | base-checkout vs frozen: `_schema_dump_base.py` / `_schema_dump_frozen.py` (SQLite PRAGMA comparison) | **identical schema** (13 tables, 2 triggers, version 1.2) | `r2_schema_compare.json` |

Skipped tests (5, environment/protocol only, identical to Round 1): 2 Windows-symlink
intake cases, 2 Windows symlink/junction resolution cases, 1 opt-in real-ACP smoke test.

## 3. Contract A 鈥?real-window capture + screenshot ownership

- **A1 config** (`ctf_solver/core/config.py`): `capture_mode: str = "real-window"` and
  `target_window_pid: int | None = None` (`:111-112`); `CAPTURE_MODES =
  {real-window, desktop, fake, fake-blank}` (`:25`); mode membership rejected with
  `ConfigError` (`:126-129`); PID validated as positive non-bool int when provided
  (`:132-139`); a default `SolverConfig()` with no PID still constructs (verified M01).
- **A2 factory** (`ctf_solver/delivery/screenshot.py`): `build_capturer(mode="real-window",
  *, target_pid=None)` (`:477`); real-window requires a positive explicit PID via
  `_validated_target_pid` (`:461-495`) and never silently builds a desktop capturer;
  `desktop` 鈫?`DesktopCapturer` (Worker legacy); `fake`/`fake-blank` 鈫?  `FakeScreenCapturer`; unknown mode 鈫?`ConfigError` (`:495`). `WindowCapturer`
  keeps `name="real-window"` and `target_pid` (`:314,323,326`); PrintWindow script
  unchanged.
- **A3 wiring** (`ctf_solver/wiring.py:167`):
  `build_capturer(config.capture_mode, target_pid=config.target_window_pid)`.
- **A4 CLI/MCP**: `ctf_solver manager serve` defaults `--capture-mode real-window` with
  choices `{real-window, desktop, fake, fake-blank}` and `--target-window-pid`
  (`ctf_solver/cli.py:283,291`); forwarded to the server (`:37`). MCP server same defaults
  and `target_window_pid=args.target_window_pid or None`
  (`ctf_solver/mcp/manager_server.py:427,435,497`); real-window startup without a PID
  fails closed (`ConfigError`, verified as a non-zero MCP-server exit in PKG10).
  `task` CLI keeps `capture_mode="fake"` (`cli.py:123`, N02). `ctf_screenshot_capture`
  keeps `scope` optional with handler default `None` (`manager_server.py:291-316`).
- **A5 service** (`ctf_solver/manager/service.py:1885`): signature
  `take_screenshot(task_id, *, step_id=None, scope=None)`;
  `_screenshot_owner` (`:1845`) gives a Lead-bound Task `worker_id=None` and
  `session_id=binding.session_id`, otherwise legacy Worker/task fallback;
  `_resolve_screenshot_scope` (`:1861`) refuses `desktop`/unknown scopes for a Lead-bound
  Task with `ValidationError` before any capture (`:1873`) and maps `None鈫?window"`;
  Worker default is `window` only for the real-window capturer else `desktop`; exactly one
  `capturer.capture(...)` call 鈥?no retry/desktop fallback. `screenshot_captured`/
  `screenshot_failed` payloads carry `capture_method`, `target_pid`, `scope`, `status`,
  `session_id`, `worker_id`, `step_id`, `width`, `height`, `sha256`, `captured_at`,
  `failure_reason` with the same owner as the `ScreenshotRecord` (`:1938-1960`). Step-id
  derivation/`validate_step_id` preserved. No DB columns/tables/migrations.
- **Independent evidence**: M01鈥揗08 PASS (config/CLI/factory fail-closed, Lead ownership,
  Worker legacy ownership, Lead desktop refusal before capture, single-attempt no
  fallback, full event metadata); MCP handler default/flows N03.

## 4. Contract B 鈥?delivery privacy projection

- **B1** `ctf_solver/delivery/privacy.py`: single pure projection;
  `DELIVERY_EVENT_TYPES` allowlist (`:36`) denies `assistant_message`, `passthrough`,
  job/command records and all unknown types; `turn_start/turn_end/step_start/step_end`
  keep only numeric `{"turn","step"}` (`:220-224`); `tool_result` for the Harness `skill`
  tool (or a result correlated to a known skill call by `call_id`) has its
  `content_preview` replaced by the fixed policy notice and `content_item_types` removed,
  keeping hashes/sizes/error/exit code (`sanitize_tool_result`, `:167-198`;
  `SKILL_RESULT_POLICY_TEMPLATE`, `:75`); other tool results keep their real preview;
  `project_event` (`:201`) emits the fixed identity shape in order,
  `filter_events` (`:242`) is deterministic and order-preserving.
- **B2** `ctf_solver/evidence/store.py:702`: `export_events_jsonl(..., privacy_filtered:
  bool = True)`; default applies `filter_events` via lazy import (`:728-733`); `False`
  exports raw committed rows for internal/test use only; deterministic canonical
  JSON/trailing LF/`ExportInfo` shape preserved. `ctf_events_export` 鈬?filtered (N06).
- **B3** `ctf_solver/delivery/bundle.py`: raw session-log collection removed
  (`_collect_raw_sources` deleted; explicit comment at `:208`); no `raw/` member ever;
  `events.jsonl` is the filtered export; screenshots/`ctf-exec` outputs only for
  successful captures; post-build internal `verify_zip` + `DeliveryError` retained
  (`:234-240`); deterministic member order/timestamps preserved.
- **Independent evidence**: M09鈥揗13 PASS 鈥?four canaries (assistant reasoning,
  passthrough prompt, Skill body, turn payload) confirmed **present in raw committed
  evidence** and **absent from the Writeup, the filtered `events.jsonl`, and every text
  member of the evidence ZIP**; dropped types absent; turn payload numeric-only; Skill
  result is the policy placeholder while a genuine tool result text is retained; no
  `raw/` member and the raw log bytes are absent from every ZIP member; raw CAS object
  intact (`evidence.read_artifact(raw_sha)` equals the ingested bytes); chain verifies
  (37 events for the synthetic task); ZIP rebuild byte-identical SHA-256
  `da494786a5fafc3f27f59c2d697dca6146bf0c1d36d2aacd1cba676d2c8e74ba`.

## 5. Contract C 鈥?Writeup display, images, gap status, Skill rule

- **C1** `ctf_solver/delivery/writeup.py:588` `_section_versions`: Worker
  `execution_started/completed/failed` records keep tool+version counts; Harness-native
  `tool_call` events are counted/listed separately with the "Harness-native tool call
  (tool version not recorded separately)" wording, and a tool covered by a Worker
  execution record says the version is listed above; the "No tool executions were
  recorded" text appears only when neither source exists. Verified M15 (both sources
  present, no false empty statement).
- **C2** Markdown images: successful capture renders
  `![Screenshot <id>](screenshots/<id>.png)` plus an indented metadata line with
  `sha256`, `captured_at` (ISO), dimensions, `capture_method`, `target_pid`, `scope`,
  `session_id` from the matching `screenshot_captured/_failed` event payload, with
  explicit `not recorded` when absent (`_screenshot_metadata_line`, `:197`;
  `_append_screenshots`, `:426`). `WriteupBuilder.build` materialises the linked bytes to
  `<task_dir>/screenshots/<id>.png` before writing `writeup.md` (`:445`, `:912-920`).
  Failed/blank/unreadable captures render `screenshot unavailable: <reason>` and no image
  link (`:400-424`). Verified M12 (standalone file + ZIP member resolve, bytes equal CAS,
  failed capture has no image link) and N09 (missing metadata renders `not recorded`).
- **C3** Gap tri-state: `_gap_states` (`:266`) derives `resolved (matched by a later
  ingestion)`, `Expected capture-boundary gap` (last `ctf_session_ingest` call whose own
  result cannot be in the snapshot), or `unresolved`; section 5 lists each gap with its
  status, section 7 lists only unresolved + the explicitly labelled expected boundary
  (`:852`); DB/events remain append-only, no extra ingestion calls. Verified M14.
- **C4** `.dsh/skills/ctf-solver/SKILL.md:169-186`: hard step after category is known and
  **before reading/analysing challenge material**; explicit native `skill({"name":
  "ctf-...})` mapping table for web/misc/crypto/reverse/pwn; stop analysis if the Skill
  cannot be loaded; discovery output explicitly **not a substitute**; frontmatter,
  `/ctf-solver` and "persist" phrasing retained. Verified N01.

## 6. Round 2 unit matrix 1鈥?6 (independent mapping)

| # | Lead matrix item | Independent check | Result |
|---|---|---|---|
| 1 | real-window PID plumbing (config/CLI/MCP/wiring/factory) | M01, M02, M03, N02, PKG10 | PASS |
| 2 | missing/invalid PID refusal | M01, M03, PKG10 (server exit) | PASS |
| 3 | no desktop fallback after window failure | M07 (1 attempt, failed recorded, no desktop scope) | PASS |
| 4 | Lead-bound Task refuses desktop | M06 (refused before capture), N03 (MCP handler) | PASS |
| 5 | Lead/Worker screenshot ownership | M04 (Lead: worker_id NULL, session_id binding), M05 (Worker legacy) | PASS |
| 6 | screenshot event metadata | M08 (all required keys + same owner as record) | PASS |
| 7 | Markdown image + standalone `tasks/<id>/screenshots/` + ZIP path | M12, N09 | PASS |
| 8 | privacy canaries absent from Writeup/events.jsonl/all ZIP text members | M09 (+ raw presence proof) | PASS |
| 9 | no `raw/` ZIP member; raw log bytes excluded | M11, N10 | PASS |
| 10 | raw CAS present, chain verifies | M11 (raw object equals ingested bytes; chain ok) | PASS |
| 11 | gap tri-state | M14 | PASS |
| 12 | ZIP manifest + determinism | M13, N10 | PASS |
| 13 | Writeup section 3 Lead vs Worker reporting | M15 | PASS |
| 14 | Skill loading hard rule | N01 | PASS |
| 15 | Round 1 regressions (Lead binding/ingest, Worker path, notes/completion_note, 18 tools, allow_model_calls=false, no migration) | M16, PKG02, N05 | PASS |
| 16 | packaging/hygiene (wheel RECORD 66/65, ruff no new findings, no new deps, UTF-8/no-BOM, forbidden strings) | PKG03鈥揚KG09, N07 | PASS |

All 16 items PASS; the 26 additional independent checks (M01鈥揗16 = 16, N01鈥揘10 = 10,
PKG01鈥揚KG11 = 11) are green (16/16, 10/10, 11/11).

## 7. Round 1 regression constraints (verified unchanged)

- Lead session binding/validation/resolution + `source=lead` ingest: PASS (M16).
- Worker-only session-log path and `source=worker`: PASS (M16).
- `tasks.notes` (intake) vs `tasks.completion_note` (outcome) split preserved through the
  completion-pending/finalize path: PASS (M16).
- 18 MCP tools with unchanged names: PASS (M16); `allow_model_calls=True` rejected by
  `ConfigError`/ADR-020: PASS (M16).
- No DB migration/schema drift: **identical schema at base `f30c9a2`** 鈥?13 tables,
  identical columns/indexes/triggers, `schema_version=1.2` (PKG02).
- Zero new dependencies: `[project].dependencies == []`, empty build-system `requires`,
  no lock/manifest change, all 32 added import statements are stdlib/local/existing
  (PKG03, PKG04).
- No Harness plugin/agent/profile/config change: `.dsh` diff is only the ctf-solver
  `SKILL.md`; no `mcp.servers.yml` change (N07).
- Raw evidence chain/CAS still intact after delivery: PASS (M11).

## 8. Packaging and hygiene

- In-tree stdlib-only PEP 517 backend (`tooling/wheelbuild.py`) builds
  `ctf_solver-0.1.1-py3-none-any.whl`: **66 members, RECORD verified, 65/65 members
  checked**, no problems; a second build produced the same filename and SHA-256
  (`54e1bd2e鈥) 鈫?deterministic (PKG08).
- Skills discovery: `ok=true`, `found=6`, UTF-8/no BOM, no problems (PKG09).
- Ruff on the 20 changed/new Python files vs base: frozen 28 findings (all pre-existing),
  base 31, **0 new findings introduced by Round 2** (PKG07; `r2_ruff_compare.json`).
- Forbidden placeholder tokens (`TODO`, `FIXME`, `XXX`, `TBD`, `NotImplemented`,
  `placeholder`, `not implemented`): absent from the 12 changed product/skill files
  (PKG05). Changed product/test/skill files valid UTF-8 without BOM (PKG06).

## 9. Baseline-drift proof (non-product, explicitly reported)

`tests/test_verification_round1.py::test_protected_ctfworker_state_and_audit_hash_unchanged`
fails in the frozen tree and fails **identically** in the clean base `f30c9a2` worktree:
expected `~/.dsh/profiles/desktop` mtime `1794246751302462400`, actual
`1794409697473832700` ("the live Harness profile directory was modified during
verification"). Frozen full-suite failure list contains exactly this one test; the base
run reproduces the same assertion values. Raw: `r2_baseline_drift_base.txt`,
`r2_full_pytest.txt`. Not a Round 2 regression.

## 10. Deviations / limitations / risk notes

1. **Privacy allowlist wider than B1's kept list (documented reconciliation):**
   `DELIVERY_EVENT_TYPES` also keeps `execution_started/completed/failed/denied`
   (`ctf_solver/delivery/privacy.py:42-45`). Contract C1 requires the Worker tool/version
   section (`execution_*`) in a Writeup that now renders through the shared projection;
   their payloads are tool/argv/status/output-preview evidence, not model reasoning, and
   the canary tests confirm confidential session-message types are dropped. No canary or
   confidential type leaks; noted as an intentional contract reconciliation.
2. **`project_event(event, skill_names=None)`** carries an optional second parameter
   (`privacy.py:201`) beyond the frozen one-argument signature; the one-argument call form
   remains valid, and `filter_events` supplies the label context. Backwards compatible.
3. **Lead-bound scope resolution is capturer-type independent** per contract A5
   (`None 鈫?"window"`). Under a non-production configuration (`capture-mode=desktop` or
   `fake`) a Lead-bound Task would record `scope="window"` while the legacy/fake capturer
   executes; production wiring defaults to `real-window` + explicit PID and the live
   acceptance path uses it. Residual misconfiguration risk, not a contract violation.
4. **Pre-existing lint debt** exists in changed files (28 findings) but **no new findings**
   were introduced (base had 31); not a Round 2 regression.
5. **Environment skips** (5) are identical to Round 1 and unrelated to Round 2 changes
   (no elevation for symlink tests; real-ACP smoke is opt-in).
6. **Files outside the A/B/C owner write scopes changed** and were reviewed:
   `ctf_solver/core/protocols.py` (`take_screenshot` scope now `str | None = None`, matches
   A5), `scripts/round2_integration.py` (uses the new config PID plumbing instead of
   monkeypatching the capturer 鈥?correct wiring), `tests/test_wheel_provenance.py`
   (expected wheel member/checked counts 66/65 after the new module). No behaviour
   weakening observed.
7. The verifier used its own independent fixtures/harnesses and did **not** depend on the
   parallel live Harness end-to-end acceptance run.

## 11. Verifier artifacts (`scratch\round2-plan\verifier-r2\`)

- Harnesses: `r2_matrix.py`, `r2_extras.py`, `r2_packaging_hygiene.py`,
  `r2_ruff_compare.py` (+ generated `_schema_dump_base.py` / `_schema_dump_frozen.py`).
- Raw outputs: `r2_full_pytest.txt`, `r2_focused_pytest.txt`, `r2_skills.txt`,
  `r2_matrix.txt`, `r2_extras.txt`, `r2_packaging_hygiene.txt`, `r2_ruff.txt`,
  `r2_ruff_compare.txt`, `r2_mcp_startup.txt`, `r2_baseline_drift_base.txt`.
- Machine-readable: `r2_matrix.json`, `r2_extras.json`, `r2_packaging_hygiene.json`,
  `r2_ruff_compare.json`, `r2_wheel.json`, `r2_schema_compare.json`,
  `r2_skills_final.json`.
- Synthetic working data: `work/` (capture/privacy/regression stacks, wheel builds,
  schema dumps); the frozen worktree was never modified (`git status` clean).

*Report generated by verifier-r1 (independent verifier) from the frozen tree at HEAD
d00cdbd; product/tests/git were not modified by the verifier. The verifier's report is
written outside the frozen worktree.*

