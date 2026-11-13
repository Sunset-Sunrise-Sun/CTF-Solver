# Community Beta test report template

Copy this file, fill in the actual results, and attach it to a GitHub issue (use the
"Beta test report" issue form) or send it to the maintainer. **Do not include real flags,
credentials, session logs, private challenge material, personal paths or screenshots you
do not want public.**

## 1. Environment

| Item | Value |
|---|---|
| Date | |
| OS / build | e.g. Windows 11 23H2 (22631.xxxx) / Ubuntu 24.04 |
| Architecture | x64 / arm64 |
| Python | e.g. 3.14.7 (from `python -V`) |
| Install method | clone + `setup_windows.ps1` / source `pip install` / wheel |
| Harness build | version/commit as shown by Harness |
| Workspace MCP Bridge plugin | installed? version |
| Workspace path shape | (do not paste your real path; describe e.g. "short local dir under user profile") |
| Sandbox / permission mode | should be `workspace-write` (never `danger-full-access`) |

## 2. Installation checks

| # | Check | Result (PASS/FAIL/BLOCKED) | Evidence summary |
|---|---|---|---|
| 1 | `python -m venv .venv` works | | |
| 2 | `pip install --no-build-isolation --no-deps .` works offline | | |
| 3 | `python -m ctf_solver version` prints `ctf-solver 0.1.1` | | |
| 4 | `ctf_solver skills --root <ws>` returns `ok:true`, `missing:[]`, 6 found | | |
| 5 | `scripts/gen_mcp_config.py` writes `.dsh/mcp.servers.yml` | | |
| 6 | 18 `mcp__ctf-solver__*` tools visible in a Harness conversation | | |
| 7 | `ctf_runtime_status` reports isolated Manager + `allow_model_calls:false` | | |
| 8 | `python -m pytest tests -q -p no:cacheprovider` | | |

## 3. Functional checks

| # | Check | Result | Notes |
|---|---|---|---|
| 9 | Create Task with `lead_session_id` (one-time binding) | | |
| 10 | Import supplied files from `challenge-uploads/`; hashes recorded | | |
| 11 | Candidate flag recorded, not submitted | | |
| 12 | `ctf_session_ingest` ingests bound Lead session log | | |
| 13 | `ctf_task_complete` succeeds; status `completed` | | |
| 14 | `ctf_writeup_build` produces `writeup.md` | | |
| 15 | `ctf_events_export` produces `events.jsonl` | | |
| 16 | `ctf_evidence_zip` produces ZIP with matching `manifest.sha256` | | |
| 17 | Evidence chain head / `chain_status.ok` | | |
| 18 | Fresh root isolation: new SQLite/CAS only under the new root | | |

## 4. Known issues reproduced

Tick the entries from `KNOWN_ISSUES.md` that you reproduced (KI-1 … KI-15) and add
details.

## 5. Problems and observations

- Unexpected failures (with the exact command and output excerpt; redact paths):
- Docs gaps:
- Suggestions:

## 6. Privacy confirmation

- [ ] This report contains no flags, credentials, tokens, session logs, databases,
      private challenge materials or unredacted personal paths.
- [ ] I understand this is a proprietary public Beta under `LICENSE`, not open source.
