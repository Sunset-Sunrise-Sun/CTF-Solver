# Lead-Session Evidence Round 1 — evidence index

This directory is the delivery evidence for the Round 1 Lead-session evidence
integration (branch `feat/lead-session-evidence`, commit `340d6b5`, on top of the
v0.1.1 tree `21908de`). Product code, tests, Skills and docs are in the same branch;
this directory only contains the verification/acceptance trail.

- **Acceptance report:** [`ACCEPTANCE_REPORT.md`](ACCEPTANCE_REPORT.md)
- **Draft PR description / delivery status:** [`DRAFT_PR.md`](DRAFT_PR.md)
- **Design + usage:** [`../docs/LEAD_SESSION_EVIDENCE.md`](../docs/LEAD_SESSION_EVIDENCE.md)
- **Architecture decision:** ADR-022 in [`../docs/DECISIONS.md`](../docs/DECISIONS.md)
- **Independent verifier report:** [`raw/VERIFIER_REPORT.md`](raw/VERIFIER_REPORT.md)
  (raw matrix outputs under `raw/verifier-*.txt` / `.json`)

## What was delivered

| Deliverable | Status | Where |
|---|---|---|
| Lead identity integration (Lead session bound once to a Task; Manager-verified) | PASS (live) | `ctf_solver/manager/session_logs.py`, `store.py`, `service.py`, MCP `lead_session_id` |
| Evidence ingestion from the real Lead session log | PASS (live; 2 incremental ingests, idempotent) | resolver `source=auto\|worker\|lead`, unchanged evidence pipeline |
| Writeup from real Lead tool calls | PASS (live; 150 steps in run 1, 11 steps in run 2; Lead-initiated labels; notes once; separate completion note) | `ctf_solver/delivery/writeup.py` |
| Process screenshot | PASS (live; desktop capture fixed root cause, 2560x1600 PNG in CAS, sha256 recorded) | `ctf_solver/delivery/screenshot.py` |
| Evidence ZIP | PASS (live; 5 members incl. raw Lead log + events + writeup + screenshot + verifying manifest; two builds byte-identical) | `ctf_solver/delivery/bundle.py` |
| Runs in the existing DeepSeek Harness environment | PASS (installed wheel + project-scoped Workspace MCP Bridge + hot reload; live MCP tool calls) | see report section 6 |
| All necessary tests | 1114 passed, 5 skipped, 1 pre-existing environment-drift failure (reproduced on base commit) | `raw/tests-final.txt`, `raw/verifier/FINAL_full_pytest.txt` |
| Draft PR | Branch + bundle prepared; **push is BLOCKED (no network access to GitHub in this environment)** | `DRAFT_PR.md` |

## Raw evidence (curated, text only; runtime imagery stays out of Git)

| File | Content |
|---|---|
| `raw/tests-base-commit-baseline.txt`, `raw/tests-final.txt` | full suite on base `21908de` and final tree (JUnit XML deliberately stays out of Git: the repo's committed-JUnit gate requires privacy-redacted, failure-free XML, while the honest run contains the documented pre-existing baseline-drift failure) |
| `raw/verifier/FINAL_*.txt`, `raw/verifier/phase2_*` | independent verifier suite runs and raw matrices |
| `raw/VERIFIER_REPORT.md` | independent verification report and verdict |
| `raw/bundle-clone*.txt`, `raw/bundle-artifact.txt` | Draft-PR bundle verify/clone/focused-test evidence |
| `raw/live-runtime-status.json` | final live Manager status observed through the MCP surface |
| `raw/live-run-1-verification.txt` | run 1 artifact verification (writeup/zip/manifest/CAS/chain/screenshot) |
| `raw/live-run-1-binding-events.txt` | run 1 binding + task_created/lead_session_bound events |
| `raw/live-run-1-notes-defect-evidence.txt` | run 1 P1-1 defect evidence (`notes == completion_note`) |
| `raw/live-run-2-verification.txt` | accepted run 2 verification (notes preserved, Lead labels, ZIP, binding, chain) |
| `raw/evidence-chain-verify.txt` | independent chain recomputation (1097 records, ok) |
| `raw/manager-db-schema-1.2.txt` | live 1.1→1.2 migration result (tables/columns/rows preserved) |
| `raw/wheel-build-v*.txt`, `raw/wheel-install-v*.txt`, `raw/wheel-verify-v1.txt` | wheel builds (stdlib backend), installs, RECORD/import verification |
| `raw/installed-wheel-final.txt`, `raw/installed-package-manifest-final.txt` | final installed package identity/hashes |
| `raw/mcp.servers.yml.original`, `raw/mcp.servers.yml.final` | project MCP config before/after (Lead sessions root added) |
| `raw/verifier/*` | independent verifier matrices/raw outputs (see `raw/VERIFIER_REPORT.md`) |

Large runtime artifacts (`evidence.zip`, `writeup.md`, `screenshot.png`, session log,
Manager DB) intentionally stay outside Git under
`tasks/<task_id>/` and `.ctf-solver-data/`; their hashes are in the report.

## Reproduction (tested environment)

```powershell
# 1. Full regression (Windows, Python 3.14.7, no new dependencies)
cd D:\CTF-SOLVER\scratch\lead-round1
python -m pytest -q

# 2. Wheel build + install (in-tree stdlib PEP 517 backend, offline)
python -c "import sys; sys.path.insert(0, 'tooling'); import wheelbuild; print(wheelbuild.build_wheel_for_repo('.', 'dist'))"
<venv>\Scripts\python.exe -m pip install --no-index --no-deps --force-reinstall dist\ctf_solver-0.1.1-py3-none-any.whl

# 3. Project-scoped Manager MCP (Workspace MCP Bridge reads this file)
#    <workspace>/.dsh/mcp.servers.yml  ->  --lead-sessions-root <DSH_HOME>/sessions

# 4. Live Lead flow (from the Harness conversation; $env:DSH_SESSION_ID in its native shell)
ctf_task_create(..., conversation_id=$env:DSH_SESSION_ID, lead_session_id=$env:DSH_SESSION_ID)
ctf_session_ingest(task_id)            # source auto -> bound Lead session
ctf_screenshot_capture(task_id)        # desktop; Manager derives turn{T}-step{S}
ctf_task_complete(task_id, result_state=..., note=...)
ctf_writeup_build(task_id); ctf_events_export(task_id); ctf_evidence_zip(task_id)
```
