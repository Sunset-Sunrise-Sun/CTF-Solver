# TROUBLESHOOTING — known environment problems

Everything here is about the environment, not challenge solving. If a fix would require
weakening security (disabling the sandbox, `danger-full-access`, global profile edits,
unprotected ACP), it is **not** a supported fix; report the problem instead.

## 1. Harness shows 0 CTF-Solver MCP tools

Symptoms: no `mcp__ctf-solver__*` tools, or `ctf_*` calls fail as unknown tools.

Check, in order:

1. **Workspace MCP Bridge plugin** — the project-scoped bridge plugin
   (`@momojie-s/dsh-workspace-mcp`) must be installed in the running Harness profile.
   Without it, project `.dsh/mcp.servers.yml` files are ignored. The Beta does not install
   it.
2. **Config location** — the file must be `<workspace>\.dsh\mcp.servers.yml` (project
   scope). A user-profile/global file is not used for the project-scoped bridge.
3. **CWD match** — the conversation's working directory must be that same workspace. The
   bridge only loads configs for the matching project root.
4. **YAML validity and command path** — run the Manager command from the config manually
   in a terminal; it must start (stdio servers wait for protocol input). A wrong
   `command` path is the most common cause. Use the venv interpreter, not `python` from an
   unrelated environment.
5. **Restart the session** — config hot-load is not guaranteed in every Harness build.
   Start a new conversation after changing `.dsh/mcp.servers.yml`.

Prove the server side independently: regenerate the config
(`python scripts/gen_mcp_config.py --help`), then run the command from the config by hand.
If the process starts and only waits on stdio, the config is probably fine and the bridge
is the problem.

## 2. Tools disappear after editing the config

Re-check YAML indentation (spaces, not tabs) and the `args` list. Then start a new
conversation. Do not edit the global Harness profile as a workaround.

## 3. Workspace nesting: the wrong `.dsh` wins

Harness treats the nearest ancestor containing `.git` as the project root, or the workspace
cwd when there is no `.git`. If you open `C:\outer\inner`, and `C:\outer` has a `.git` or
another `.dsh`, the ancestor config/Skills can win over `inner\.dsh`.

Fix: open the intended project root directly (the directory that contains `.dsh`), or
flatten the nesting. Confirm with the Agent which workspace/session cwd it actually sees.

## 4. Windows ACL problem: "grantWrite" / access denied on the workspace

Symptoms: writes or directory creation fail even though the folder looks writable; as a
non-elevated user, an ACL check reports `WRITE_OWNER` missing.

The DSH sandbox grants the current user write access through a bounded ACL operation; the
one entitlement that is often missing on a non-elevated account is `WRITE_OWNER` (`WO`).
Check:

```powershell
icacls "<workspace>"
$acl = Get-Acl "<workspace>"; $acl.Access | Format-Table IdentityReference,FileSystemRights,AccessControlType
```

A minimal, owner-level fix is to grant only `WO` to the current user/SID on the workspace
folder (not Full Control, not the parent):

```powershell
icacls "<workspace>" /grant "*S-1-5-21-...-1001:(WO)"
```

Use your own SID from `whoami /user`. Do not grant Full Control or take ownership of
unrelated directories. If you are not the owner and cannot grant `WO`, choose a workspace
you own (for example under your user profile).

## 5. Low Integrity / sandboxed interpreter

Symptoms: the Manager cannot create `.ctf-solver-data` (`WinError 5`), cannot write
`tasks\`, or child processes are labeled Low Integrity.

Typical cause: the Python interpreter (or the extracted archive) carries a Low Integrity
label or Mark-of-the-Web inheritance, e.g. a venv created from a downloaded ZIP or a
Python installed under a folder with an unusual integrity label.

Check the label and the process integrity:

```powershell
icacls "<python.exe>"          # look for a Low mandatory label
Get-Process -Id $PID | Select-Object Id,ProcessName
```

Fix by copying the project/Python into a normal folder you own (for example the repo under
`%USERPROFILE%`), re-creating the venv there, and unblocking downloaded files
(`Unblock-File`). Avoid running the Manager from a Low Integrity location; do not remove
integrity labels globally from system tooling.

## 6. `acp_unavailable` when creating a Task

The Manager could not start the managed Harness ACP server (`dsh --profile acp --patch
<package-resource>`). The command now fails explicitly instead of storing a permanently
queued Task. Check:

- `ctf_runtime_status` / the error's `acp_error` field;
- that DeepSeek Harness is installed and `dsh` is discoverable, or set
  `CTF_SOLVER_ACP_COMMAND` to the exact launcher path (test-only boundary; it still gets
  the mandatory `--profile acp --patch ...` arguments);
- the resolved privacy patch path (section 7).

No public flag exists to point the Manager at an arbitrary, unprotected ACP command.

## 7. `ConfigError: ... privacy patch is missing`

The installed package is incomplete: `ctf_solver/resources/acp/cordis.patch.yml` must be
present in the installed wheel. Check:

```powershell
python -c "from ctf_solver.core.config import SolverConfig; print(SolverConfig().privacy_patch_path)"
```

If the path does not exist, reinstall the official wheel from the Beta. Never create a
fake unprotected profile as a workaround.

## 8. zstd / session-log decode errors

`session.v4.jsonl.zstd` evidence is decoded with the standard-library
`compression.zstd` (Python 3.14+) or the optional `zstandard` package (Python 3.11–3.13).
With neither backend, ingestion fails closed with `UnsupportedCompressionError` instead of
silently reading only the first frame.

```powershell
python -c "import sys; print(sys.version)"
# Python 3.11-3.13: install the optional dependency into the same venv
# python -m pip install zstandard
```

## 9. The source checkout shadows the installed package

Symptom: `python -m ctf_solver version` reports the source tree, or a database schema
error mentions `unsupported database schema version '1.2'; expected '1.1'`.

Cause: running from inside the source checkout puts `ctf_solver/` before site-packages.

Fix: check `ctf_solver.__file__`, then use `python -P -m ctf_solver ...` or run from a
neutral directory. Do not delete the installed wheel.

## 10. Approval console fails closed ("not a TTY")

Approval decisions and grant creation require a real local interactive TTY. Agent/MCP
pipes, redirected stdin and service contexts fail closed by design. Run the exact command
in an interactive terminal:

```powershell
python -m ctf_solver approval confirm --root <root> --approval-id <approval-id>
python -m ctf_solver grant create --root <root> --approval-id <approval-id> ...
```

There is no MCP tool that decides an approval. An Agent can only request one.

## 11. Manager IPC / stale process problems

The Manager opens a loopback IPC endpoint per root and runs an ACP child. If a previous run
was killed, retry once after the process exits; check for zombie `python`/`dsh` processes
that still hold `.ctf-solver-data\manager.sqlite`. Use a different `--root` for a clean
experiment rather than deleting evidence from a root you still need.

## 12. Target-window screenshot fails

Lead-bound Tasks require `--capture-mode real-window --target-window-pid <PID>`; the PID
must belong to the process that owns the window. `desktop` scope is refused for Lead-bound
Tasks, there is no desktop fallback, and there is no automatic window discovery. If
capture is not possible in your environment, the failure is recorded honestly and the
Writeup marks the screenshot as missing — see [KNOWN_ISSUES.md](KNOWN_ISSUES.md).

## 13. Skills are not discovered by Harness

The six folders must be at `<project root>\.dsh\skills\<name>\SKILL.md`. Run
`python -m ctf_solver skills --root <project root>`; it reports missing or malformed
Skills with exit code 1. Discovery of Skills does **not** register the Manager MCP — those
are two separate steps (INSTALL.md steps 5 and 6).

## 14. Sandbox denies a file operation

The normal `workspace-write` sandbox covers the session workspace. Keep Task data,
challenge intake, venv, and Manager roots inside a workspace you own; avoid paths outside
it. A denial is a policy boundary, not a bug to bypass: do not switch to
`danger-full-access`. If an operation must be wider, ask the human to decide.

## 15. Harness version differences

The Beta was exercised with a specific Harness build (ACP profile/plugin surface). Newer
or older builds may change plugin loading, project-scoped MCP bridging or session-log
format. If the project config loads but tool discovery fails, report your Harness build
with the community template instead of patching global settings.
