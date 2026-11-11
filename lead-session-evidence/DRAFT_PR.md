# Draft PR (delivery artifact)

**Status: prepared, NOT pushed — BLOCKED by no network access to GitHub in this
environment.** `git ls-remote origin` fails (`github.com:443` unreachable) and `gh` is
not installed. The branch and the bundle are ready; push/open the Draft PR from a
network-enabled machine.

## Proposed PR

- **Title:** `feat(lead-evidence): bind the Lead Harness session as the Task evidence source`
- **Base:** `release/v0.1.1-final` (remote branch whose tree equals the local v0.1.1
  tree `21908de`; if the repository mainline is preferred, use `main` — the branch is
  `main`-descended and 59 commits ahead, all of them the already-accepted v0.1.1
  hardening/release series plus this one feature commit)
- **Head:** `feat/lead-session-evidence` (local commit `340d6b5` product code/tests/
  Skills/docs; subsequent commits add only the `lead-session-evidence/` acceptance
  trail)
- **Draft:** yes (owner review required before merge)
- **Diff at the feature commit:** 35 files, +3344 / −209

## Summary

Round 1 Lead-session evidence integration (ADR-022), additive on accepted v0.1.1:

- schema 1.2: `tasks.completion_note` + one-time `session_bindings` table, additive
  `1.1→1.2` migration (and a proven `1.0→1.1→1.2` chain; the legacy
  `executescript`-in-transaction migration defect is fixed with individual statements);
- `SessionLogResolver` gains an explicitly configured live `lead_sessions_root`, a
  `source=auto|worker|lead` selector and a one-time, Manager-verified Lead binding
  (safe path component, unique log, no symlink/junction, realpath containment, header
  `id` match, header `cwd` match against the Manager root); new fail-closed reason
  codes;
- `ManagerService`: `ctf_task_create(lead_session_id=...)` with pre-persistence
  validation, `ctf_session_ingest(source=...)`, session-specific completion
  auto-ingest (fail closed), derived `turn{T}-step{S}` screenshot binding, runtime
  status fields; the MCP surface keeps exactly the 18 existing tools;
- delivery: desktop-screenshot WinForms load fix + robust diagnostics decoding;
  Writeup renders Lead-initiated tool steps, intake notes once, completion note in a
  separate subsection, screenshots by exact/derived step id; evidence ZIP verifies its
  own manifest and includes the raw Lead log from CAS;
- intake `notes` and outcome `completion_note` are independent in every lifecycle write
  path (a live defect found during acceptance and covered by a regression test);
- Skills: Lead-native executor/evidence contract, 18-tool list, hard category routing,
  unified evidence paragraph; docs: ADR-022, README, Installation Guide §6.5, Local
  Operation, `docs/LEAD_SESSION_EVIDENCE.md`.

No new third-party dependencies. No model-driven Worker / `session/prompt` change
(ADR-020 untouched). No Round 2 work.

## Testing

- Full suite (Windows, Python 3.14.7): **1114 passed, 5 skipped, 1 pre-existing
  environment-drift failure** (`test_protected_ctfworker_state_and_audit_hash_unchanged`
  compares the live `~/.dsh/profiles/desktop` mtime to a 2026-11-09 snapshot; it fails
  identically on the untouched base `21908de` — reproduced by the independent verifier
  in a separate worktree).
- Independent verifier matrices: contract/deps 24/24, security/service 29/29
  (injection/duplicate/header/cwd/root negatives, completion-note regression,
  worker-resolution parity with base), migration/determinism 12/12 (real 1.1 DB
  snapshot migrates to 1.2 with rows/chain preserved; writeup and ZIP are
  byte-identical across two builds; forced manifest failure raises).
- Live environment: rebuilt wheel installed offline in the managed venv; project-scoped
  MCP bridge hot-reloaded the Manager; two live Harness Lead-session end-to-end runs
  (one main-conversation run that also found the P1-1 note defect, one fresh-session
  accepted run after the fix) produced real evidence chains, desktop screenshots,
  Writeups and evidence ZIPs (details + hashes in
  `lead-session-evidence/ACCEPTANCE_REPORT.md`).

## Risk / rollback

- Additive DB migration only (`ALTER TABLE ADD COLUMN` + `CREATE TABLE/INDEX`); no row
  rewrite, no table rebuild. Existing Worker-only behaviour and the 18-tool surface are
  unchanged; a Task without `lead_session_id` behaves exactly as before.
- `source=auto` prefers a Lead binding, so only Lead-bound Tasks change evidence
  source; `source=worker` keeps the legacy path.
- Rollback: revert the branch; the live venv can be restored with the v0.1.1 release
  wheel; the database is backward-incompatible only in the sense that v0.1.1 code
  would see schema 1.2 — restore the pre-round DB snapshot if a true v0.1.1 rollback is
  needed (the round's DB changes are additive, and the evidence chain was verified).

## How to push/open (from a network-enabled machine)

```powershell
git clone --mirror <network clone or existing repo> CTF-Solver.git
git -C CTF-Solver.git fetch <path to CTF-Solver-Lead-Session-Evidence.bundle> "refs/heads/*:refs/heads/*"
git -C CTF-Solver.git bundle verify <bundle>
git push origin feat/lead-session-evidence
# then open a Draft PR: base release/v0.1.1-final (or main), head feat/lead-session-evidence
```

Bundle: `D:\CTF-SOLVER\dist\CTF-Solver-Lead-Session-Evidence.bundle`
(SHA-256 recorded in the final delivery message; `git bundle verify` exit 0).
