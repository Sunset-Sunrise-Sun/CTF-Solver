# Acceptance Criteria

**Purpose:** objective gates for implementation claims and release readiness.  
**Date:** 2026-11-10

A test is not passed because code exists or an agent says it should work. Record command, environment, fixture, actual result, and evidence reference for every accepted gate.

## A. Conversation mode and Skills

- [ ] /ctf-solver explicitly activates the mode.
- [ ] Mode persists across subsequent turns in the same conversation.
- [ ] Attachments and “continue” do not require the command again.
- [ ] A clearly new challenge creates a new Task; continuation does not.
- [ ] Ambiguous task switching asks one concise clarification.
- [ ] A new conversation requires explicit mode entry.
- [ ] Core Skill and all five category Skills are discovered from project bundles.
- [ ] Skill files are UTF-8 without BOM.
- [ ] First Blood scanning is not part of the MVP.

## B. Manager, ACP, and scheduling

- [ ] Manager implements ACP Client over stdio ND-JSON / JSON-RPC 2.0.
- [ ] One Task receives one ACP session and tasks/<id>/work cwd.
- [ ] Task/Worker/session/workspace mapping is persisted.
- [ ] Manager maintains its own active-session registry; it does not depend on session/list.
- [ ] At most two Workers are active; additional Tasks are FIFO.
- [ ] Worker slot release and failure recovery are deterministic.
- [ ] Shared ACP Server failure marks affected Tasks interrupted, not completed.
- [ ] Successful resume/recovery is tested.
- [ ] Task is not marked cancelled until job/process quiescence is confirmed.

## C. ctf-exec and Runtime

- [ ] Workers can call typed ctf-exec through MCP.
- [ ] No arbitrary host Shell tool is exposed to Workers.
- [ ] Requests contain Task/Worker/Step, tool/version, argv, cwd, inputs/outputs, and timeout.
- [ ] Broker validates Task ownership and workspace containment.
- [ ] Tool allowlist and tool-version/preflight checks are enforced.
- [ ] Actual timestamps, exit code, stdout/stderr, and artifact refs are returned.
- [ ] Denied calls are distinguished from executed-but-failed calls.
- [ ] Worker/MCP callers cannot access Docker Socket or raw Docker API.
- [ ] When Tier 2 is installed, Broker is the sole controlled Docker API caller.

## D. P0 privacy, authorization, and human control

- [ ] dsh-session-log-deepseek is disabled or CTF sessions excluded through a verified supported mechanism.
- [ ] A synthetic canary from a CTF session is absent from outbound dsh_session_log delivery.
- [ ] Public research/documentation access is distinct from competition-target traffic.
- [ ] Remote target access requires a Task-scoped host/port/action grant.
- [ ] A grant for Task A cannot authorize Task B or another host/port/method.
- [ ] Redirects, DNS resolution, loopback/private IPs, and alternate ports are checked.
- [ ] Missing scope, expired grant, or Broker failure blocks the action.
- [ ] Human approval is required for untrusted-code execution, software installation, and remote target access.
- [ ] Untrusted challenge code remains blocked while Tier 2 is unavailable.
- [ ] Flag confirmation/submission remains a human action.
- [ ] No CTF target is contacted by integration tests.

## E. Evidence and integrity

- [ ] Multi-frame zstd logs are decoded completely.
- [ ] tool/call and tool/result are correlated by callId.
- [ ] seq order/gaps, job status, approvals, and command events are preserved.
- [ ] Raw session-log bytes and original artifacts are retained in CAS.
- [ ] evidence/events.jsonl is append-only.
- [ ] SQLite evidence chain is idempotent and tamper-evident.
- [ ] Missing/truncated frames create explicit evidence gaps.
- [ ] Tampering with an event/artifact is detected.
- [ ] Hash-chain limitations are documented; no signature claim is made.

## F. Screenshot, Writeup, and evidence ZIP

- [ ] Important program-running screenshots are requested through explicit capture.
- [ ] Capture metadata includes Task/Worker/Step/session/scope/time.
- [ ] Screenshot bytes are non-empty and stored in CAS with SHA-256.
- [ ] Failed/blank captures are recorded as failures.
- [ ] No continuous or silent desktop capture occurs.
- [ ] Writeup commands/argv/output excerpts come from evidence records.
- [ ] Writeup preserves real operation order, hypotheses, failures, and negative results.
- [ ] Writeup embeds only verified screenshots/artifacts.
- [ ] Unknown/blocked/unverified steps are clearly marked.
- [ ] Evidence ZIP includes selected artifacts and manifest.sha256.
- [ ] Manifest is independently checked.
- [ ] PDF conversion is left to a later handoff.

## G. Product/environment separation

- [ ] Product preflight reports missing tools and versions.
- [ ] Product does not silently install software.
- [ ] Existing D:/CTF project and Harness profile/config are not modified without explicit authorization.
- [ ] CLI/headless is the primary execution path; GUI is auxiliary.
- [ ] Cordis hooks remain thin/optional; no second agent loop is introduced.

## H. Local end-to-end MVP

- [ ] A synthetic local challenge completes intake → plan → permitted execution → verification → Writeup.
- [ ] No public CTF target is contacted during tests.
- [ ] Two concurrent Tasks and at least one FIFO-queued Task are exercised.
- [ ] Continuation, new Task, pause, cancellation request, and recovery are tested.
- [ ] Session-log outbound delivery is proven disabled for the test.
- [ ] No raw Shell, raw MCP, or Docker Socket bypass exists.
- [ ] User confirmation is required before Flag submission.
- [ ] Markdown Writeup and evidence ZIP are reproducible from stored evidence.

## I. Tier 2 acceptance (separate P1 environment track)

Before running arbitrary challenge-provided code:
- [ ] Isolated runtime starts from a clean, disposable image.
- [ ] Challenge workspace is mounted least-privilege.
- [ ] Host filesystem and credentials are not exposed.
- [ ] Network is disabled or restricted to approved CTF scope.
- [ ] Process, memory, CPU, disk, and time limits are enforced.
- [ ] Cleanup is verified after success, timeout, and crash.
- [ ] Escape and cross-Task access tests pass.
- [ ] Toolchain versions and image digest are recorded.

## Reporting rule

Every acceptance report must distinguish PASS, FAIL, BLOCKED, and NOT VERIFIED. A blocked test is not a pass. An audited primitive is not proof that the integrated product works.