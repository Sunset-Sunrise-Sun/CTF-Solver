# Draft PR (Round 2 minimal delivery)

**Status: prepared, NOT pushed — BLOCKED by no network access to GitHub in this environment.**
`git ls-remote origin` fails (`github.com:443` unreachable) and `gh` is not installed. The
branches and a full-history bundle are ready; push/open the Draft PR from a network-enabled
machine.

## Proposed PR

- **Title:** `fix(round2): real target-window capture, delivery privacy, Writeup images`
- **Head:** `fix/round2-minimal-delivery` (commit `d00cdbd` code/tests/docs + evidence commits)
- **Base:** `release/v0.1.1-final` — the remote branch whose tree equals the Round 1 v0.1.1
  baseline `21908de` (verified by comparing remote refs first; do not reset/overwrite the
  mainline). `main` also works (the branch is main-descended). Round 1's
  `feat/lead-session-evidence` (`f30c9a2`) is the direct parent of this branch and is included
  in the bundle.
- **Draft:** yes (owner review before merge)

## Summary

Round 2 minimal fixes on top of the Round 1 Lead-session evidence integration:

- **P0-1 real target-window capture wiring:** `capture_mode` defaults to `real-window` and
  requires an explicit positive `--target-window-pid`; `build_capturer` fails closed without
  a PID, reuses the existing `WindowCapturer`/PrintWindow implementation, and never falls
  back to the desktop. CLI/MCP/wiring plumb the PID; screenshot events record
  capture_method/target_pid/scope/owner/step/dimensions/sha256/time/failure reason without a
  DB migration.
- **P0-2 ownership:** Lead-bound Tasks record `worker_id=null` / `session_id=<Lead>`, refuse
  `scope=desktop`; Worker-only Tasks keep the legacy path.
- **P0-3 Writeup:** section 3 distinguishes Harness-native Lead tool calls from Worker
  `ctf-exec` executions; successful screenshots are Markdown-embedded with metadata under the
  real `turn{T}-step{S}` and materialised to `tasks/<id>/screenshots/` (standalone + ZIP);
  failed/missing captures are marked honestly.
- **P0-4 delivery privacy:** one shared projection (`delivery/privacy.py`) for Writeup,
  `events.jsonl` and ZIP — default-deny drops reasoning/passthrough/job/command/unknown
  event types, reduces turn/step to numeric metadata, replaces Skill bodies with a policy
  notice; ZIP never contains raw session logs (raw stays in local CAS); manifest/determinism
  preserved.
- **P1-1 gaps:** resolved / unresolved / `Expected capture-boundary gap` classification
  without mutating the append-only evidence.
- **P1-2 Skills:** the Core Skill now requires an actual native
  `skill({"name": "ctf-<category>"})` load after the category is known and before reading
  challenge material; failures stop analysis.

## Testing

- Full suite on the frozen commit: **1141 passed, 5 skipped, 1 failed** — the sole failure is
  the pre-existing `test_protected_ctfworker_state_and_audit_hash_unchanged` environment
  drift, reproduced identically at base `f30c9a2`; no Round 2 regression.
- Independent verifier: **PASS**; matrices 16/16 (contract/capture/privacy/writeup/gap/
  regression), 10/10 extras, 11/11 packaging/hygiene; focused Round 2 files 149 passed;
  wheel 66 members / RECORD 65/65; Ruff 0 new findings; no new dependencies; no DB migration;
  18 MCP tools; ADR-020 `allow_model_calls=false` preserved.
- Live Harness acceptance (fresh conversation as Lead): real target-window screenshot
  (780x330, only the window, `capture_method=real-window`), Lead-owned screenshot record,
  Writeup with real tool calls + embedded image, privacy-filtered ZIP (no `raw/`, canaries
  absent, manifest OK), raw log preserved in CAS, chain 1198 records ok. Details:
  `ROUND2_ACCEPTANCE_REPORT.md`.
- Reproduction config (never commit a real PID): `.dsh/mcp.servers.yml` with
  `--capture-mode real-window --target-window-pid <TARGET_WINDOW_PID>`.

## Risk / rollback

- Additive product change; Worker-only Tasks and the 18-tool surface keep their behaviour;
  no DB migration; the only behaviour change is deliberate (Lead-bound screenshots require
  a real target window and refuse desktop capture).
- Rollback: revert the branch; reinstall the v0.1.1 release wheel (or the Round 1 wheel) in
  the managed venv; the database schema is unchanged by Round 2 (still 1.2).

## Push/open (from a network-enabled machine)

```powershell
git clone <network clone of the repo> CTF-Solver.git
git -C CTF-Solver.git fetch "<path>\CTF-Solver-Round2-Minimal-Delivery.bundle" "refs/heads/*:refs/heads/*"
git -C CTF-Solver.git bundle verify "<path>\CTF-Solver-Round2-Minimal-Delivery.bundle"
git push origin fix/round2-minimal-delivery feat/lead-session-evidence
# open a Draft PR: base release/v0.1.1-final (or main), head fix/round2-minimal-delivery
```

Bundle: `D:\CTF-SOLVER\dist\CTF-Solver-Round2-Minimal-Delivery.bundle` (SHA-256 recorded in
the final delivery message and verified with `git bundle verify` + clone check).
