# Round 2 Security Remediation Record

**Status:** implemented and verified on branch `feat/round2-harness-integration`
**Date:** 2026-11-10
**Authority:** the owner's Round 2 remediation instructions + `docs/ROUND_2_INTEGRATION_TASK.md`.

This record documents the security changes ordered after the independent Round 1 review:
the model can only *request* approvals, cannot decide them or create grants, cannot
choose arbitrary session-log file paths, and cannot rely on schema-description-only
MCP validation. Every change below is backed by deterministic negative tests; real
local-TTY behaviour is called out as NOT VERIFIED rather than claimed.

## 1. Approval and network-grant authorization (P0)

**Threat.** Round 1 exposed `ctf_approval_decide` (approval_id/approved/approver strings)
and `ctf_grant_create` (caller-supplied approver string) to the model. A model could
therefore self-approve or self-authorize network access by typing an "approver".

**Remediation.**

- Removed `ctf_approval_decide` and `ctf_grant_create` from the Manager MCP surface.
  The exposed surface is now request/list/revoke only. Tests assert the exact tool set
  and that calls to the removed tool names are rejected as unknown tools.
- New `ctf_solver/security/confirmation.py`: `ConsoleConfirmationChannel`, the only
  approval decision channel. It is usable only on an interactive local console TTY
  (and refuses agent/MCP/worker contexts identified by `CTF_SOLVER_IPC_URL` /
  `CTF_SOLVER_WORKER_TOKEN`). It displays the action summary and the approval digest
  prefix and requires the human to type `CONFIRM <digest[:8]>` (or `REJECT`); non-TTY,
  EOF, wrong phrase and exhausted attempts all fail closed. The OS user comes from
  `getpass.getuser()`; there is no caller-supplied approver parameter anywhere.
- New `ctf_solver/manager/approval_grant_service.py`: `request_approval`,
  `confirm_approval`, `create_grant_from_approval`, `revoke_grant`, list helpers.
  `create_grant_from_approval` requires an APPROVED, unexpired, unconsumed
  `remote_target` approval for the same Task, re-derives the target digest from
  (host, port, protocol, method, path prefix, competition profile) and requires it to
  equal the approved digest, then atomically consumes the approval and inserts the
  grant with `approval_id`/`confirmation_id`/`confirmation_os_user`.
- SQLite schema 1.1 adds approval confirmation columns, grant approval-binding columns
  and a `task_inputs` table (with a 1.0→1.1 migration).
- `ManagerService.decide_approval`/`create_network_grant` remain as explicit fail-closed
  stubs raising `StateError` (defence in depth if a caller invokes the old API).
- Local human CLI (not MCP): `python -m ctf_solver approval list|confirm|reject` and
  `python -m ctf_solver grant create --approval-id ... | list | revoke`.

**Negative tests** (`tests/test_security_*.py`, `tests/test_round2_security_integration.py`):
model-supplied approver/`"false"`/`"true"` strings cannot decide; no MCP decision or
grant-creation tool exists; replay, expiry, cross-Task use, digest mismatch and
double-consumption fail closed; approval without local-console confirmation is
unconsumable; grant creation without a confirmed approval fails.

**NOT VERIFIED:** a real physical console prompt (keyboard input on an actual TTY). The
positive path uses an injected TTY/fake input under test; the non-TTY and
agent/MCP-context paths are tested to fail closed.

## 2. Session-log ingestion path (P0)

**Threat.** `ctf_session_ingest` accepted an absolute file path from the model, allowing
arbitrary local file reads through evidence ingestion.

**Remediation.**

- MCP tool `ctf_session_ingest` now accepts only `task_id` (+ optional `worker_id`
  cross-check). The schema rejects any `path`/extra property.
- New `ctf_solver/manager/session_logs.py::SessionLogResolver` locates the log only from
  the Manager's own Task/Worker/session registry:
  `<managed DSH_HOME>/sessions/<slug>/<sessionId>/session.v4.jsonl.zstd`.
  It validates Task and Worker mapping, optional worker match, single unambiguous match,
  realpath containment, symlink/junction-free components, and that the first decoded
  zstd frame's session header id equals the registered session id.
- Stable failure codes: `unknown_task`, `no_worker`, `unknown_session`, `log_missing`,
  `ambiguous_session_log`, `symlink_rejected`, `path_escape`, `header_mismatch`,
  `sessions_root_missing`. The Manager never echoes a local path back through the tool.
- The Manager/CLI default to a project-local isolated `DSH_HOME`, so the sessions root
  is known and never the live user profile.

**Negative tests:** other Task/Worker, nonexistent session, ambiguous duplicate session
directories, symlinked/escaped log roots and headers mismatch; a queued Task without a
Worker is refused before touching any file; the old `path=` signature no longer exists.

## 3. MCP argument schema enforcement (P1)

**Threat.** `McpServer._validate_arguments()` only checked required keys, trusting the
tool description for types/enums/bounds.

**Remediation.** New `ctf_solver/mcp/schema.py` implements a deterministic JSON-Schema
subset (`type` incl. bool≠int, `enum`, `const`, `required`, `properties`,
`additionalProperties`, `items`, `min/maxItems`, `min/maxLength`, `pattern`,
`min/maximum`, `exclusive*`, `anyOf`) and `mcp/protocol.py` validates every
`tools/call` payload before dispatch. Malformed schema and payload failures are
distinguishable (`-32602` with structured errors). 72 validator tests + protocol and
exec-server negative tests cover wrong types, bad enums, extra fields and non-array
argv.

**Limitation:** this is a documented subset; security-critical constraints are still
enforced server-side by the Broker (allowlist/argv/path/tier), not by the schema layer.

## 4. ACP permission event attribution (P1)

`ManagerService._on_permission_request` no longer treats `sessionId` as a Task id. It
reverse-maps the session through `ManagerStore.get_worker_by_session`; known sessions
produce a `acp_permission_rejected` event on the correct Task/Worker, unknown sessions
produce a system diagnostic (`acp_permission_unknown_session`) and are never attributed
to a wrong Task. Host-tool permission requests remain rejected by default.

## 5. ACP launch arguments (P1)

`manager_server.main()` previously parsed the discovered launcher into
`config.acp_command` without appending `--profile acp`, so a default launch could omit
the audited profile. Now:
- omitting `--acp-command` leaves `acp_command=None` → `wiring.default_acp_factory`
  discovers the installed launcher and uses the audited `dsh --profile acp` argv
  (a `.cmd` launcher is wrapped as `[COMSPEC, /c, dsh.cmd, --profile, acp]`);
- an explicit `--acp-command` is treated as a complete command (used by fake-ACP and
  integration tests, never rewritten);
- `ctf_solver/acp/launch.py` centralizes the argv builder with tests covering both
  launcher shapes and a live `.cmd` argument pass-through.

Real zero-model-call integration confirmed the actual argv and that the installed Harness
ACP server reached `protocolVersion 1` (`round2-evidence/raw/round2-integration.log`).

## 6. Challenge-file intake (P1)

New `ctf_solver/intake.py::IntakeService` imports challenge files only from the
project-scoped intake root (`challenge-uploads/`, git-ignored). Absolute paths, drive
paths, traversal, NUL/control characters, symlinks/reparse points, non-regular files,
duplicates and count/size-limit violations are rejected; accepted files are copied into
`tasks/<task_id>/work/inputs/` and recorded with SHA-256, size, media type and source
path (`task_inputs` table, `task_created` evidence payload). The Writeup lists the real
imported materials with hashes. No arbitrary host file read or shell is introduced.

**Negative tests:** traversal/absolute/symlink/outside/limits/duplicates, and two Tasks
receiving isolated copies (modifying one cannot affect the other).

## 7. Breaking API/interface changes (Round 1 → Round 2)

| Round 1 | Round 2 |
|---|---|
| MCP `ctf_approval_decide` | removed; local console CLI only |
| MCP `ctf_grant_create` | removed; local console CLI from a confirmed approval |
| `ManagerService.decide_approval(...approver=...)` | raises `StateError` (no Agent decision path) |
| `ManagerService.create_network_grant(...approver=...)` | raises `StateError`; use `create_grant_from_approval` |
| `ManagerService.ingest_session_log(task_id, path=...)` | `ingest_session_log(task_id, *, worker_id=None)` registry-only |
| `ManagerStore.decide_approval` | `record_approval_confirmation(...)` |
| `AgentBase` approval without confirmation | cannot be consumed (fail closed) |

## 8. Verification summary (see the Round 2 acceptance report for full logs)

- Security tests: `tests/test_security_*.py` 45 passed.
- Lead security/integration regressions: `tests/test_round2_security_integration.py` 13 passed.
- Integrity modules: 154 passed, 1 documented Windows-symlink skip.
- Intake/packaging: 60 passed, 2 documented Windows-symlink skips.
- Full suite and real-Harness integration evidence are recorded in the acceptance report.
