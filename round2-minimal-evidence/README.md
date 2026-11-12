# Round 2 minimal delivery — evidence index

Delivery evidence for the final CTF-Solver development round (branch
`fix/round2-minimal-delivery`, base `f30c9a24a0f341fadb0e08a77584902b1976c83d` = Round 1):
real target-window capture wiring, Lead screenshot ownership, Writeup process display with
embedded screenshots, delivery privacy policy, and gap display.

- **Acceptance report:** [`../ROUND2_ACCEPTANCE_REPORT.md`](../ROUND2_ACCEPTANCE_REPORT.md)
- **Draft PR artifact:** [`DRAFT_PR.md`](DRAFT_PR.md)
- **Design/usage:** `docs/LEAD_SESSION_EVIDENCE.md` §8, `INSTALLATION_GUIDE.md` §6.5/§7
- **Round 1 evidence:** `lead-session-evidence/` (branch `feat/lead-session-evidence`)

## Verdict summary

| Item | Result |
|---|---|
| Live Harness end-to-end acceptance (fresh conversation as Lead) | **PASS** — Task `t-121579912bf84b35b574f88c45e33a96`, Lead session `b0020ecd…7a01` |
| Category Skill loaded before material | **PASS** — `skill(ctf-solver)` seq 1131 → `ctf_task_create` 1137 → `skill(ctf-misc)` 1143 → first read 1157 |
| Target-window screenshot | **PASS** — `shot-70fe96b7…0161`, 780x330, `capture_method=real-window`, sha256 `cd4aa8db…4278d9f`; only the target window |
| Lead ownership | **PASS** — `worker_id=null`, `session_id=<Lead>` |
| Writeup with real calls + embedded image | **PASS** — 18 623 B, sha256 `9ac91654…be164` |
| Evidence ZIP privacy + completeness | **PASS** — 4 members (no `raw/`), manifest 3/3 OK, sha256 `f258c4a4…c19847`, canaries absent |
| Raw session log preserved in local CAS | **PASS** — `88d63862…`, `b159e91f…` re-verified |
| Evidence chain | **PASS** — ok=true, 1198 records, head `9cc02980…0405` |
| Full suite | 1141 passed, 5 skipped, 1 pre-existing environment-drift failure (identical at base) |
| Independent verifier | **PASS** (matrices 16/16, 10/10, 11/11) |
| Draft PR | Bundle prepared; **push BLOCKED** (no GitHub network access) |

## Raw evidence

| File | Content |
|---|---|
| `raw/tests-final.txt` | full suite on the frozen tree |
| `raw/tests-baseline.txt` | full suite on the untouched Round 1 base (same one environment-drift failure) |
| `raw/acceptance-executor-report.md` | the live Harness acceptance executor's first-hand report (skill order, ingests, screenshot, Writeup/ZIP hashes, privacy checks, chain) |
| `raw/live-acceptance-lead-verification.txt` | Lead-side independent re-verification of the live artifacts (ZIP members/manifest, canaries, standalone image, raw CAS, chain) |
| `raw/acceptance-challenge/` | the synthetic acceptance challenge source (text) |
| `raw/config-restore-and-cleanup.txt` | temporary MCP config hash before/after, restore SHA match, target window closed, temp intake removed |
| `raw/target-window-capture-probe.txt` | pre-wiring probe proving `WindowCapturer` captures only the target window (780x330) |
| `raw/wheel-build.txt`, `raw/wheel-verify.txt`, `raw/wheel-install.txt`, `raw/installed-wheel-check.txt` | wheel build (66 members/65 RECORD), install, installed identity |
| `raw/ruff-changed-files-round2.txt`, `raw/ruff-changed-files-round1-base.txt` | Ruff delta input (0 new findings) |
| `raw/verifier-r2/` | independent verifier report + raw matrices |

The temporary acceptance target-window PID and the temporary local MCP config are
deliberately **not committed**: committed copies use `<TARGET_WINDOW_PID>`. Runtime
artifacts (screenshot PNG, Writeup, evidence ZIP, raw session log, Manager DB) live under
`D:\CTF-SOLVER\tasks\<task_id>\` and `.ctf-solver-data\` and are referenced by path/hash in
the acceptance report.

## Reproduce

```powershell
# full regression on the frozen branch
cd <repo>\scratch\round2-minimal
python -m pytest -q

# wheel build/verify/install (in-tree stdlib backend, offline)
python -c "import sys; sys.path.insert(0, 'tooling'); import wheelbuild; print(wheelbuild.build_wheel_for_repo('.', 'dist'))"
<venv>\Scripts\python.exe -m pip install --no-index --no-deps --force-reinstall dist\ctf_solver-0.1.1-py3-none-any.whl

# live target-window configuration (user-local, never committed)
# <workspace>/.dsh/mcp.servers.yml -> --capture-mode real-window --target-window-pid <TARGET_WINDOW_PID>
# then, from the Harness Lead conversation:
#   skill({"name":"ctf-solver"}) -> ctf_task_create(lead_session_id=$env:DSH_SESSION_ID)
#   -> skill({"name":"ctf-<category>"}) -> native analysis tools
#   -> ctf_session_ingest -> ctf_screenshot_capture (no scope) -> ctf_session_ingest
#   -> ctf_flag_candidate -> ctf_task_complete -> ctf_writeup_build / ctf_events_export / ctf_evidence_zip
```
