# Acceptance Criteria

**Purpose:** objective gates for implementation claims and release readiness.  
**Date:** 2026-11-10

A test is not passed because code exists or an agent says it should work. Record the command, environment, fixture, actual result, and evidence reference for every accepted gate.

## A. Conversation mode and Skill

- [ ] `/ctf-solver` explicitly activates the mode.
- [ ] The mode remains active across subsequent turns in the same conversation.
- [ ] Attachments and “continue” messages do not require the command again.
- [ ] A clearly new challenge creates a new Task; a continuation does not.
- [ ] Ambiguous task switching asks one concise clarification.
- [ ] A new conversation requires explicit mode entry.
- [ ] The project Skill is discovered from `.dsh/skills/ctf-solver`.
- [ ] `SKILL.md` is valid UTF-8 without BOM.
- [ ] Exiting CTF mode does not delete or corrupt persisted Tasks.

## B. Task isolation and scheduling

- [ ] Every Task has a unique ID, workspace, and ACP session ID.
- [ ] ACP `session/new` receives the correct `cwd=tasks/<id>/work`.
- [ ] Writes and artifacts from Task A cannot appear in Task B's workspace through Manager-managed operations.
- [ ] Manager maintains its own active-session registry; it does not depend on `session/list` for active sessions.
- [ ] At most two Workers are active.
- [ ] Additional Tasks are scheduled FIFO.
- [ ] A completed/failed/quiescent Worker releases exactly one slot.
- [ ] Manager restart does not silently duplicate or lose queued Tasks.
- [ ] Shared ACP Server failure marks all affected Tasks interrupted, not completed.

## C. ACP Client and lifecycle

- [ ] ND-JSON framing handles partial reads, multiple messages, large messages, and EOF.
- [ ] JSON-RPC request IDs are unique and responses/events are correlated correctly.
- [ ] Startup, initialize, session creation, prompt, event handling, close, and shutdown are tested.
- [ ] Malformed messages, timeouts, server exit, and stdin/stdout errors fail visibly.
- [ ] Active session IDs are persisted before Task execution is reported as started.
- [ ] Successful resume/recovery is tested; resume error paths alone are insufficient.
- [ ] Cancel behavior is tested with an actual in-flight job.
- [ ] Task is not marked cancelled until process/job quiescence is confirmed.

## D. P0 privacy and security gates

- [ ] `dsh-session-log-deepseek` is disabled or CTF sessions are excluded through a verified supported mechanism.
- [ ] A synthetic canary placed in a CTF session is absent from outbound `dsh_session_log` delivery.
- [ ] The Manager broker denies network by default.
- [ ] A grant is scoped to Task, target, port, action, expiry, and call count.
- [ ] A grant for Task A cannot authorize Task B.
- [ ] A grant for one host/port/method cannot authorize another.
- [ ] Redirects, DNS resolution, loopback/private IPs, and alternate ports are checked.
- [ ] Broker failure, expired grant, and missing scope fail closed.
- [ ] Raw MCP tools cannot bypass the Manager broker.
- [ ] Untrusted challenge binaries/scripts/macros/exploit payloads are blocked while Tier 2 is unavailable.
- [ ] No challenge credentials or broad host secrets are inherited by Worker processes.
- [ ] Competition rules are checked before network or state-changing actions.

## E. Evidence and integrity

- [ ] Multi-frame zstd logs are decoded completely; tests include more than one frame.
- [ ] `tool/call` and `tool/result` are correlated by `callId`.
- [ ] `seq` order and gaps are preserved.
- [ ] Job registration/settlement status and approval events are captured.
- [ ] Raw session-log bytes and original artifacts are retained in CAS.
- [ ] Ingestion is idempotent.
- [ ] A missing/truncated frame creates an explicit evidence gap.
- [ ] Tampering with an event or artifact is detected by the hash chain/manifest check.
- [ ] Hash-chain limitations are documented; no digital-signature claim is made.
- [ ] Unmatched tool calls/results are retained as gaps, not discarded.

## F. Screenshot and writeup

- [ ] Screenshot capture is an explicit tool call.
- [ ] Capture metadata includes Task, ACP session, step, scope, and timestamp.
- [ ] Screenshot bytes are non-empty and stored in CAS with SHA-256.
- [ ] Failed/blank captures are recorded as failures.
- [ ] No continuous or silent desktop capture occurs.
- [ ] Writeup command/argument/output excerpts come from evidence records.
- [ ] Writeup embeds only verified screenshot/artifact references.
- [ ] Failed attempts and important negative results are preserved.
- [ ] Unverified steps and environment gaps are clearly marked.
- [ ] A SHA-256 manifest is generated and independently checked.

## G. Local end-to-end MVP

- [ ] A synthetic local challenge completes intake → plan → permitted execution → verification → writeup.
- [ ] The test does not contact public targets.
- [ ] Two concurrent Tasks and at least one FIFO-queued Task are exercised.
- [ ] A Task can be continued after a normal turn boundary.
- [ ] A Task can be resumed after Manager restart, or the limitation is explicitly surfaced.
- [ ] Session-log outbound delivery is proven disabled for the test.
- [ ] All artifacts and evidence are reproducible from the exported package.

## H. Tier 2 acceptance (P1)

Before running arbitrary challenge-provided code:

- [ ] The isolated runtime starts from a clean, disposable image.
- [ ] Challenge workspace is mounted with least privilege.
- [ ] Host filesystem and credentials are not exposed.
- [ ] Network is disabled or restricted to the approved CTF scope.
- [ ] Process, memory, CPU, disk, and time limits are enforced.
- [ ] Container/VM cleanup is verified after success, timeout, and crash.
- [ ] Escape and cross-Task access tests pass.
- [ ] Toolchain versions and image digest are recorded.

## Reporting rule

Every acceptance report must distinguish **PASS**, **FAIL**, **BLOCKED**, and **NOT VERIFIED**. A blocked test is not a pass. A previously audited primitive is not proof that the integrated product works.