# Execution Contract: ctf-exec

**Status:** approved interface contract; implementation pending  
**Date:** 2026-11-10

## 1. Purpose

ctf-exec is the single structured execution interface exposed to CTF Workers through MCP. It connects Manager → Broker → Runtime and returns auditable execution records.

It exists specifically to avoid exposing an unrestricted host Shell to an Agent or MCP caller.

## 2. Non-goals

- No arbitrary PowerShell/CMD command-string interface.
- No raw Docker API or Docker Socket access from a Worker.
- No direct execution bypass around Manager/Broker.
- No automatic software installation.
- No unrestricted target network access.
- No automatic Flag submission.

## 3. Request contract

A request contains:
- task_id, worker_id, step_id;
- tool_name and approved tool-version constraint;
- argv as an array of arguments;
- working_directory;
- input_files with path and SHA-256;
- output_paths;
- optional network_grant_id and approval_id;
- timeout/resource limits.

This is a typed request, not a free-form shell string. The tool catalogue is Manager-owned. The Worker cannot select an arbitrary executable outside the allowlist.

## 4. Response contract

Every call returns at least:

| Field | Meaning |
|---|---|
| task_id / worker_id / step_id | Operation ownership and workflow position |
| tool_name / tool_version | Actual tool and version |
| argv | Actual argument vector |
| working_directory | Actual cwd |
| input_files / output_files | Paths and hashes/CAS references |
| started_at / ended_at | Actual timestamps |
| exit_code | Process exit code, if started |
| stdout / stderr | Actual bytes or CAS refs plus bounded previews |
| screenshot_paths | Explicit screenshots associated with this Step |
| network_grant_id | Grant used, if any |
| status | completed / failed / timed_out / denied / blocked / unknown |

The Manager distinguishes a denied call (not executed) from a process that started and failed.

## 5. Validation and authorization

Before execution, Broker validates:
1. Task and Worker exist and are runnable.
2. Worker is mapped to the Task's ACP session.
3. Tool is allowlisted and installed at an approved version.
4. argv satisfies the tool-specific schema and cannot invoke shell expansion.
5. cwd and file paths are contained in authorized roots.
6. operation is allowed in the current execution tier.
7. required approval exists and is valid.
8. network target/port/action matches the Task grant.
9. timeout/resource limits are within policy.

Fail closed on validation error.

## 6. Human approval gates

Explicit approval is required before executing untrusted challenge code, installing software/changing the toolchain, or accessing a remote CTF target.

Approval is scoped to the proposed action and Task. It does not authorize other Tasks, targets, ports, tools, or later actions.

While Tier 2 OS isolation is unavailable, approval alone is insufficient to execute untrusted challenge code on the host. Such calls must be blocked/deferred until isolation is accepted.

The user, not the Agent, confirms and submits a Flag.

## 7. Runtime and Docker boundary

When Tier 2 is available:
- Broker is the sole controlled Docker API caller.
- Worker/MCP callers never receive Docker Socket mounts, Docker credentials, or raw Docker API access.
- Runtime launches only an approved image/configuration.
- Task workspace mounts are least-privilege.
- resource limits, network policy, cleanup, and evidence collection are enforced by Runtime/Broker.

The latest audit reports Docker Engine/gVisor are not installed. Do not claim this path works yet.

## 8. Network policy

Public research and public documentation lookup may use the public internet. Competition target traffic requires a Task-specific authorization grant bound to target host/IP, port, protocol/method/action, expiry, and call count. Out-of-scope destinations are rejected. Loopback/private addresses require explicit challenge scope. Redirects and DNS resolution are revalidated.

## 9. Evidence

Every call produces a durable event whether allowed, denied, failed, or completed. Record original request, normalized tool/argv/cwd, approval/grant references, tool version, timestamps, exit code, stdout/stderr bytes or CAS refs, input/output hashes, screenshot refs, and error/denial reason.

Append to evidence/events.jsonl and Manager's SQLite hash chain. Store raw outputs/files in CAS.

## 10. CLI/headless and GUI

Prefer CLI/headless tools. GUI automation is not an execution dependency for the MVP. GUI is auxiliary and primarily used for explicit screenshots of important program-running steps. Keyboard/mouse injection was unreliable in the audit.

## 11. Acceptance

See ACCEPTANCE.md for execution, authorization, evidence, and local end-to-end gates.