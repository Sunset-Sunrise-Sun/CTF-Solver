# Round 2 Final Acceptance Remediation Report

**Status:** remediation candidate ready for final independent acceptance
**Branch:** `fix/round2-acceptance-remediation` (local only; no push, no PR, no merge)
**Base:** Round 2 `feat/round2-harness-integration` @ `d38845366075c57f5840127b93bfd58c9c9e24f3`
**Round 1 branch preserved:** `feat/round1-complete-product-core` @ `e40f76f317ec3f3186e0120744af2f5924d32721`
**Remediation implementation commit:** `0872b14681039a142c83aa6bf269be372190031b`
**Report/final commit:** the child commit containing this report and the regenerated Git-blob manifest (no push).
**Scope:** repair the four P0 defects and the evidence/manifest P1 defects found by the
independent acceptance review. This is **not** a third development round: no architecture,
product scope or two-round decision changed.

---

## 1. Executive summary

| Defect | Before | After |
|---|---|---|
| P0-1 approval scope | grant TTL/`max_calls` were passed only at grant-creation time and were **not** in the approved action digest; a caller could widen the human-approved scope. | Approval payload and digest bind Task, profile, host/port/protocol/method/path prefix **and** `grant_ttl_s`/`max_calls`; the human summary shows all of them; grants read the immutable approved values; post-approval widening/tampering/replay/cross-Task fail closed. |
| P0-2 terminal injection | `_require_summary()` only stripped text and `_say()` printed raw content; untrusted fields could inject terminal control sequences/line breaks. | Untrusted fields are strictly normalized before entering the payload; C0/C1/ESC/ANSI/OSC/CR-LF/bidi/format chars, traversal/query path forms, over-long values are rejected. Displayed summary is exactly the hashed payload; console output is also escaped as defense in depth. |
| P0-3 privacy launch | only the standalone `--dump-config` helper used `--patch`; the real Manager ACP launch (`default_acp_factory`) did **not** pass the project privacy patch. | Default Manager launch is the absolute `dsh --profile acp --patch <project>/config/acp/cordis.patch.yml` argv with isolated `DSH_HOME`, failing closed if the patch is missing/relative; integration verifies both the live argv (A) and the isolated effective config (B). |
| P0-4 completion lifecycle | `TaskStatus.COMPLETED` existed but the Manager had no completion interface; E2E Writeups showed `running`/`unknown`. | `ManagerService.complete_task()` + MCP `ctf_task_complete` implement prechecks, close-session-before-slot-release, grant revocation, terminal persistence, evidence event/head, FIFO promotion and close-failure rollback. Synthetic E2E ends `completed` with real `ended_at`/`result_state` and final Writeup/ZIP. |
| P1 MCP mount evidence | handshake was written at process start (spawn-only proof). | Handshake is written only after the ACP-spawned MCP child answers `initialize`, then records `tools/list` names/PID/Task/token hash/protocol; integration verifies PID ancestry against the ACP server and distinguishes the independent `tools/call` process. |
| P1 logs/manifest | `*.log` ignored key logs; manifest hashed CRLF working-tree bytes and had wrong counts/2 unexplained mismatches. | Narrow evidence-log exceptions added; key logs committed. `FINAL_FILE_MANIFEST.txt` now hashes **canonical Git blob bytes**, is self-excluded, corrected to 261 entries, and verifies 100% in a clean clone. |

Real zero-model-call Harness integration: **43/43 checks PASS** (was 30 before this patch).
Full tests: **978 passed / 4 documented skips** (default) and **979 passed / 3 skips**
with the zero-model-call real ACP smoke. A strict clean clone of the implementation
commit reproduces **978 passed / 4 skipped** and a canonical wheel.

No model call, no `session/prompt`, no real CTF target, no challenge execution, no
WSL/Docker, no install/upgrade, no Harness global config change, no Cordis plugin.

---

## 2. P0-1 — complete approval scope binding

### Implementation

`ctf_solver/manager/approval_grant_service.py` now canonicalizes a `remote_target`
approval as:

```json
{"task_id": "t-...", "profile": "synthetic-local",
 "target": {"host": "...", "port": 8443, "protocol": "https",
            "method": "POST", "path_prefix": "/api/challenge"},
 "grant_ttl_s": 120, "max_calls": 3}
```

Every field participates in `policy.models.action_digest`. The approval's own
`expires_at` (approval decision lifetime) remains a separate concept from the network
grant `grant_ttl_s`; tests cover both independently.

`create_grant_from_approval()`:

- re-derives the stored payload and its digest and rejects tampering (including TTL/call
  widening in SQLite) before any consumption;
- requires the payload Task to equal the approval Task;
- reads TTL and max_calls **from the approved payload**;
- accepts optional `ttl_s`/`max_calls` arguments only as strict-integer compatibility
  checks that must equal the approved values;
- rejects `bool`, float, numeric string, zero/negative and oversized values;
- keeps the atomic one-shot consumption (`create_grant_from_approval` in the store), so
  concurrent grant creation has exactly one winner.

The human confirmation summary includes target:port, protocol, method, path prefix,
profile, grant TTL and max calls (in addition to Task/approval/digest).

### Negative tests (`tests/test_security_approval_grant.py`,
`tests/test_round2_remediation_security.py`)

TTL change after approval; max_calls increase; profile change; path/host/port/protocol/
method change; cross-Task approval use; replay; SQLite payload/digest/TTL/call tampering;
6-thread concurrent grant creation (one success, others `StateError`); bool/float/string/
non-positive/oversized values; missing TTL/calls; approval TTL vs grant TTL separation.
All fail closed; no approval is consumed and no grant is inserted on failure.

---

## 3. P0-2 — terminal-injection-safe human confirmation

### Implementation

New `ctf_solver/security/textsafe.py`:

- `normalize_field(...)`: rejects non-strings, C0/C1/DEL/surrogates, ESC/ANSI/OSC,
  CR/LF, Unicode bidi/format controls, line/paragraph separators, excessive length and
  out-of-grammar host/profile/path/method/protocol values. Only the normalized value
  enters the approval payload/digest.
- `require_displayable(...)`: validates the complete summary (bounded; no control/format
  chars) and fails closed rather than silently deleting characters.
- `terminal_safe(...)`: escapes unsafe characters as `\xNN`/`\uNNNN`; the console
  channel applies it to every output line as defense in depth.

`approval_grant_service` normalizes host (lower-case, IP-literal normalization), profile
(token grammar), protocol (allowlist), method (upper-case letters), path prefix
(absolute URL path; no `..`, query or fragment), task id and numeric scope. The
confirmation channel validates the summary again and rejects malformed/unsafe text with
`ConfirmationError`.

### Tests

ESC `\x1b[2J`, ANSI colour, OSC title, CR/LF injection, Unicode bidi override, NUL,
over-long profile/host/path, malicious host/path/method/protocol, and display-vs-payload
consistency (the console received the normalized values; raw input never appears). Real
physical TTY interaction is **NOT VERIFIED**: the automated harness is non-interactive
and no human is present to type the confirmation phrase; injected-TTY tests cover the
positive path and non-TTY/MCP contexts are tested to fail closed.

---

## 4. P0-3 — privacy patch in the real ACP launch

### Implementation

- `ctf_solver/core/config.py`: `SolverConfig.privacy_patch_path` resolves the absolute
  project patch `config/acp/cordis.patch.yml`.
- `ctf_solver/acp/launch.py`: `build_privacy_patch_args()` requires an absolute existing
  patch; `build_acp_command(..., privacy_patch=...)` appends
  `--patch <absolute>` after `--profile acp`.
- `ctf_solver/wiring.py`: the default Manager factory refuses to launch when the project
  patch is missing/relative and builds `dsh --profile acp --patch <abs>` (COMSPEC-wrapped
  for `.cmd`). Explicit `--acp-command` remains a complete caller-supplied argv for fake
  ACP tests only. The isolated project `DSH_HOME` remains unchanged.

### Evidence (real, zero model calls)

From `round2-evidence/raw/round2-integration.log` / `round2-privacy-gate-result.json`:

- **A. Actual Manager argv:**
  `[C:\Windows\system32\cmd.exe, /c, ...\dsh.cmd, --profile, acp, --patch,
  D:\CTF-SOLVER\config\acp\cordis.patch.yml]` — absolute project patch, isolated
  `DSH_HOME` under `.ctf-solver-data/r2-dsh-home`.
- **B. Effect in that isolated home:** running the same argv with `--dump-config`
  (exit 0) composes a profile containing `- id: session-log-deepseek` and
  `enabled: false`.

This is configuration evidence. The real negative outbound-delivery canary still
requires an official model request and remains **BLOCKED**; config evidence is not
reported as delivery verification.

---

## 5. P0-4 — normal Task completion lifecycle

### Implementation

`ManagerService.complete_task(task_id, result_state=..., note=...)`:

1. validates the result-state token (non-empty, safe grammar, not `unknown`);
2. supports completion from `running/paused/blocked/awaiting_approval`; terminal Tasks
   return an idempotent snapshot;
3. prechecks: Worker/session ownership mapping; no unfinished execution; no pending
   approval; ingested session log (unless an explicit test-only override is passed);
   intact evidence chain and persisted evidence head; no unresolved ACP security
   diagnostics and no unresolved evidence errors;
4. marks the Task as completing so new executions/flags are refused;
5. **closes the ACP session first**; on failure it records a diagnostic, returns a
   structured `AcpError`, keeps the Task status and the Worker slot, and writes no
   completion event;
6. only after confirmed close: revokes active grants, stops the Worker (slot release),
   persists `completed` + `result_state` + real `ended_at`, emits `task_completed`,
   refreshes `evidence_head`, and promotes the FIFO queue;
7. MCP exposes `ctf_task_complete` (schema requires `task_id`/`result_state`); it cannot
   bypass any Manager check; `ipc_exec` refuses `task_completing`/terminal Tasks;
   candidate flags are refused after completion; restart recovery only touches active
   Tasks, so completed Tasks stay completed.

### Tests (`tests/test_manager_completion.py`, real E2E)

9 deterministic tests: normal completion, slot release, FIFO promotion, unfinished
execution rejection, pending approval rejection, missing session-log rejection, session
close failure keeps Task+slot, idempotent repeat, execution/flag refusal after
completion, completed task survives restart, and the MCP tool contract.

Real synthetic E2E final state:
`status=completed`, `result_state=solved_flag_candidate`, real `ended_at`,
`session_closed=true`, `slot_released=true`, Worker stopped, evidence chain intact.
Writeup now contains `- Status: `completed`` and
`- Result state: `solved_flag_candidate`` (no `running`/`unknown`); the evidence ZIP
contains the final `writeup.md`, `manifest.sha256`, `events.jsonl`, session-log artifact
and screenshot. Normal completion and restart recovery are separate checks; after restart
the completed E2E Task is still `completed` while the still-running FIFO Task is
`interrupted` (no duplicate sessions).

---

## 6. P1 — protocol-level MCP mount evidence

`ctf_solver/mcp/exec_server.py` no longer writes a handshake at process start. New
`HandshakeRecorder` is invoked by `McpServer` hooks:

- after the actual MCP `initialize` request is answered: writes PID, Task, Worker-token
  SHA-256, server/protocol version, `initialize_received=true`;
- after `tools/list`: records the real tool names (`["ctf_exec"]`) and
  `tools_list_received=true`.

Writes are atomic (`.tmp` + replace) and evidence failure never changes the protocol.
The integration script verifies the handshake PID's OS ancestor chain contains the ACP
server PID and that the separately started MCP `tools/call` process has a different PID.
The E2E `tools/call` is therefore explicitly attributed to an **independent** MCP stdio
process; same-child `tools/call` is **NOT VERIFIED** under the zero-model-call gate and is
not claimed.

---

## 7. P1 — committed evidence logs and Git-blob manifest

- `.gitignore` keeps the global `*.log` rule and adds narrow exceptions:
  `!round1-evidence/raw/*.log` and `!round2-evidence/raw/*.log`. The previously
  uncommitted `round2-integration.log` and fresh-clone logs are now tracked; transient
  debug logs remain ignored.
- Count correction (final acceptance review): at commit `c45299d` the repository had
  **262 tracked files**; the manifest excludes itself explicitly, so it lists
  **261 entries**. The earlier report text saying 255 was wrong and is corrected here.
  The manifest header no longer cites a manifest/report commit (that would create a
  circular reference); it cites only the implementation commit `0872b14`, which exists
  in history.
- `round2-evidence/FINAL_FILE_MANIFEST.txt` regenerated from **Git blob bytes** via
  `git cat-file` (canonical LF), self-excluded, header/entry counts corrected. It has
  **261 entries** and 0 mismatches when checked against the Git blobs; a clean clone
  reproduces the same bytes and verifies 100%.
- The earlier CRLF-worktree hash mismatch and the off-by-one counts are documented as
  fixed; there are no unexplained entries.

---

## 8. Verification evidence and commands

| Run | Result | Exit | Evidence |
|---|---|---|---|
| Full suite, default | **978 passed, 4 documented skips, 0 failed** | 0 | `round2-evidence/raw/remediation-full-default.txt`, `junit-remediation-default.xml` |
| Full suite + zero-model-call real ACP smoke | **979 passed, 3 skips, 0 failed** | 0 | `round2-evidence/raw/remediation-full-with-real-acp.txt`, `junit-remediation-with-real-acp.xml` |
| Real Harness integration (zero model calls) | **43/43 PASS** | 0 | `round2-evidence/raw/round2-integration.log`, `round2-integration-summary.json`, privacy gate JSON |
| Security remediation tests | 80 passed (security + new P0-1/P0-2) | 0 | `round2-evidence/raw/remediation-security-post2.txt` |
| Completion lifecycle tests | 9 passed | 0 | `round2-evidence/raw/remediation-completion1.txt` |
| Strict clean clone of implementation commit `0872b14` | **978 passed / 4 skipped**; wheel built and verified in clone | 0 | `round2-evidence/raw/fresh-clone-20261110T130959Z.{json,log}`, `remediation-fresh-clone-console.txt` |
| Canonical wheel (clean-clone build) | `ctf_solver-0.1.0-py3-none-any.whl`, **215,106 B**, SHA-256 `9AAF9286BC451A397698D718534A885B5CCEDCEA6C3E1FC6BC9014627E2F558C`, 64 members | 0 | `round2-evidence/raw/remediation-canonical-wheel-build.json` |
| Git-blob manifest | 261 entries, 0 mismatches vs Git blobs; clean-clone verification 100% | 0 | `round2-evidence/FINAL_FILE_MANIFEST.txt` |

Canonical commands:

```powershell
python -m pytest tests -q -p no:cacheprovider
$env:CTF_SOLVER_ENABLE_REAL_ACP = '1'; python -m pytest tests -q -p no:cacheprovider
python scripts/round2_integration.py
python scripts/fresh_clone_check.py
python scripts/build_wheel.py
```

The working-tree wheel build differs from the clean-clone wheel only because the
development worktree contains CRLF text while Git blobs/clean checkout are LF; the
**canonical clean-clone wheel** (`9AAF9286…`) is the acceptance artifact. Rebuilding from
the implementation commit in a clean clone reproduces it exactly.

---

## 9. Acceptance matrix

| Requirement | Verdict |
|---|---|
| P0-1 full approval scope (Task/profile/target/TTL/max_calls in digest) + negative tests | **PASS** |
| P0-2 terminal injection rejection + display == hashed payload + real TTY | **PASS** (injected-TTY/offline); real physical TTY **NOT VERIFIED** |
| P0-3 privacy patch in actual Manager ACP launch (A) + effective isolated config (B) | **PASS (A/B configuration evidence)**; external-delivery canary **BLOCKED** (no model request) |
| P0-4 normal completion lifecycle, close-before-release, E2E `completed`, restart separation | **PASS** |
| P1 protocol-level ACP child initialize/tools-list evidence + PID ancestry | **PASS**; same-child `tools/call` **NOT VERIFIED** (zero-model gate) |
| P1 evidence logs committed; Git-blob manifest 261 entries verified 100% in clean clone | **PASS** |
| Security negative matrix (policy/approval/schema/exec/intake/session-log) | **PASS** |
| 2 Workers + FIFO, restart recovery, synthetic E2E, Writeup/ZIP, wheel/fresh clone | **PASS** |
| Main-conversation `/ctf-solver` → Manager tools | **BLOCKED** (no supported project-scoped MCP registration; owner decision) |
| Session-log negative delivery canary | **BLOCKED** (requires model request; not authorized) |
| Model-mediated Worker / `session/prompt` | **BLOCKED by design** (ADR-020) |
| Tier 2 OS isolation / real targets / challenge execution | **BLOCKED** (not in this environment) |

---

## 10. Git / delivery

- Branch `fix/round2-acceptance-remediation`; implementation commit `0872b14`
  (**60 files changed, 5,526 insertions(+), 323 deletions(-)**).
- Round 1 `e40f76f` and Round 2 `d388453` unchanged; PR #1 untouched (Draft/open);
  nothing pushed.
- Final Git bundle: `D:\CTF-SOLVER-review\CTF-Solver-Round2-Acceptance-Remediation.bundle`
  (SHA-256 and size recorded in the final message/report addendum).
- `D:\CTFworker` untouched; no installs/changes to Harness global config; runtime data
  removed from the tree after evidence collection.

## 11. Remaining blockers (unchanged, owner decisions)

1. Main-conversation `/ctf-solver` → Manager control MCP entrypoint: **BLOCKED**; no
   supported project-scoped registration path. Options remain owner-scoped (dedicated
   profile registration, thin Host Plugin bundle, or out-of-band local Manager).
2. External-delivery canary: **BLOCKED** until a model request is authorized; real CTF
   content must not be processed before that gate passes.
3. Model-mediated Worker (`session/prompt`, model tools/call): **BLOCKED by design**.
4. Real physical-console approval typing: **NOT VERIFIED** (requires a human at a TTY).
5. Same-child ACP `tools/call`: **NOT VERIFIED** under the zero-model-call gate.
6. Tier 2 OS isolation / real targets: **BLOCKED** (separate environment track).

Round 2 remediation stops here; no third development round was started. Waiting for final
independent acceptance.
