# QUICKSTART — from install to a delivered Writeup

This walkthrough starts after [INSTALL.md](INSTALL.md) steps 1–6 are complete: the package
is in a venv, six Skills are deployed, and the project-scoped `.dsh/mcp.servers.yml` is
generated. Commands are PowerShell.

## 1. Start Harness on the project workspace

Open the repository directory (or the workspace where you deployed the Skills and the MCP
config) as a **DeepSeek Harness workspace**, then start a conversation.

The project-scoped Workspace MCP Bridge loads `<workspace>\.dsh\mcp.servers.yml` for
sessions whose working directory is that workspace. The Manager MCP tools should appear as
`mcp__ctf-solver__*` — **18 tools**. If you see zero tools, fix the environment before
continuing: [TROUBLESHOOTING.md](TROUBLESHOOTING.md) section 1.

A quick positive check inside the conversation is to call `ctf_runtime_status`; the reply
reports `allow_model_calls: false`, the Manager `ipc_url`, the SQLite path and the evidence
chain head.

## 2. Load the Skills

Type `/ctf-solver` (or explicitly ask to enter CTF mode). The Core Skill is loaded, then
the category Skill is loaded **before** any challenge material is read:

- Web → `ctf-web`
- Misc → `ctf-misc`
- Crypto → `ctf-crypto`
- Reverse → `ctf-reverse`
- Pwn → `ctf-pwn`

If the category Skill cannot be loaded, the Agent must stop the analysis rather than
improvise.

## 3. Put challenge material in the intake directory

Files are imported by the Manager, not read from arbitrary host paths. Place the supplied
files under the Manager root's intake directory, relative to the workspace:

```text
<workspace>\challenge-uploads\<your-challenge-files>
```

Absolute host paths are rejected by the Task intake. Keep any answer/verifier files out of
this directory before creating a Task.

## 4. Create the Task

Ask the Agent to create the challenge Task. The Manager verifies and binds this Lead
conversation's real session id (`$env:DSH_SESSION_ID`) exactly once, so the conversation's
Harness session log becomes the evidence source. Example prompt:

> Create a new misc Task: title "My Challenge", category misc, source "local", and import
> `challenge.txt` and `README.txt` from the intake directory. Bind this Lead session.

The equivalent MCP call is `ctf_task_create` with:

- `title`, `category`, `conversation_id` (stable for this conversation);
- `lead_session_id` = the real session id from `$env:DSH_SESSION_ID`;
- `supplied_files` = paths **relative to `challenge-uploads\`**, never absolute paths.

The Manager imports, hashes and isolates the files into the Task workspace and records the
task-creation evidence boundary. Only records after that boundary are ingested.

## 5. Solve with the Lead and record the candidate

The Lead conversation performs the analysis with native Harness tools (file inspection,
shell, local computation) inside the Task workspace. The Agent records a **candidate**
Flag with `ctf_flag_candidate`; it never submits a Flag and never claims user or platform
confirmation.

Sensitive actions follow the approval model:

- untrusted challenge code execution, software installation and remote target access need
  a Task-scoped **human** approval;
- approvals are requested by the Agent (`ctf_approval_request`) and can only be decided by
  a human on a local interactive console — never through MCP;
- network grants are created only by a human from a confirmed `remote_target` approval.

## 6. Ingest, complete, and export the deliverables

When the analysis is done:

1. **Ingest** the bound Lead session log: `ctf_session_ingest` (the caller cannot pass a
   path or an arbitrary session id). Gaps are reported explicitly, not hidden.
2. **Complete** the Task: `ctf_task_complete` with a concrete `result_state` such as
   `solved_flag_candidate` or `no_flag`. The Manager verifies preconditions (no unfinished
   execution, no pending approval, session log ingested, intact chain) before completing.
3. **Build the Writeup**: `ctf_writeup_build` → `<task-dir>\writeup.md`.
4. **Export the events**: `ctf_events_export` → `<task-dir>\evidence\events.jsonl`.
5. **Build the evidence ZIP**: `ctf_evidence_zip` → `<task-dir>\evidence.zip` containing
   `writeup.md`, `events.jsonl` and a `manifest.sha256`.

Typical layout after completion:

```text
<workspace>\tasks\<task_id>\
  work\                   # Task workspace (imported inputs + Agent artifacts)
  writeup.md              # chronological Writeup generated from committed evidence
  evidence\events.jsonl   # deterministic derived event export
  evidence.zip            # writeup + events + manifest
```

Verify a ZIP offline at any time:

```powershell
python -c "import sys,zipfile,hashlib; z=zipfile.ZipFile(sys.argv[1]); m={l.split()[1].lstrip('*'):l.split()[0] for l in z.read('manifest.sha256').decode().splitlines() if l.strip()}; bad=[p for p,h in m.items() if hashlib.sha256(z.read(p)).hexdigest()!=h]; print('manifest OK' if not bad else ('MISMATCH: '+','.join(bad)))" .\tasks\<task_id>\evidence.zip
```

## 7. CLI-only alternative (no MCP bridge)

The same Manager can be driven from a terminal without the Harness MCP bridge, for local
smoke tests. These commands start the real wiring and make no model calls:

```powershell
# Read-only environment report
python -m ctf_solver preflight --root .\ctf-solver-root

# Local Task creation; supplied files must be under <root>\challenge-uploads\
python -m ctf_solver task create --root .\ctf-solver-root `
    --title "Synthetic misc" --category misc --conversation-id local `
    --supplied-file challenge.txt
python -m ctf_solver task list --root .\ctf-solver-root
python -m ctf_solver task status --root .\ctf-solver-root --task-id <task-id>
```

ACP startup failures are explicit (`reason_code=acp_unavailable`) instead of silently
queueing a Task. The CLI path never bypasses the approval/decision gates.

## 8. Next steps

- Known limitations and verification gaps: [KNOWN_ISSUES.md](KNOWN_ISSUES.md).
- Environment problems: [TROUBLESHOOTING.md](TROUBLESHOOTING.md).
- Share how it went on another machine: [docs/release/COMMUNITY_TEST_TEMPLATE.md](docs/release/COMMUNITY_TEST_TEMPLATE.md).
