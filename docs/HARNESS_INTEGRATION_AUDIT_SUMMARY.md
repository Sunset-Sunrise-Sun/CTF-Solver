# Harness Integration Capability Audit — Summary

**Full report:** internal Harness capability audit (not part of this release).  
**Size:** 46,444 bytes  
**SHA-256:** `955136d156a878fc932243081cc42d72575bc4f65510dc03163cb689d7fe5373`  
**Audit status:** read-only; no commit/push was performed by the audit.

> This repository document is a summary of the findings supplied by the project owner in the conversation. It is not a copy of the full 46,444-byte report. Import the original report after its contents are made available to the repository workflow.

## 1. Executive conclusion

**Scheme A is implementable in the audited Harness version**, subject to the architecture facts and security constraints below.

1. Harness is an **ACP Server**, not an ACP Client. The shipped installation has `dsh-acp` but no `dsh-subagent-acp` client. Manager Core must implement an ACP Client or use a separately audited ACP host/runner.
2. A Cordis Host Plugin can provide the thin integration skeleton: register tools, intercept tool lifecycle hooks, subscribe to session events, and respond to approval requests. It is fully trusted host code and is not sandboxed.
3. Evidence collection is feasible from persistent session logs and live events, but Harness logs have no hash chain or signature. Manager must ingest them into its own SQLite hash chain and CAS.
4. Harness permissions are not sufficient as the CTF security boundary. Manager must add task/target/action-scoped authorization and OS isolation remains a separate requirement.

## 2. Verified demonstrations

| Area | Audit result |
|---|---|
| ACP lifecycle | `dsh --profile acp` completed **22/22 checks PASS**; isolated DSH_HOME; zero model calls; 3.1 seconds |
| ACP sessions | Three independent sessions with different workspaces; list excluded active sessions; close isolation tested; three resume error paths tested; stdin EOF exited 0 |
| MCP mounting | Dummy stdio server mounted through `session/new.mcpServers`; server discovery, initialization, and tool listing succeeded |
| MCP tool call | `tools/call` required a model call and was BLOCKED; not verified |
| Session log | 1.4 MB, 1,819 zstd frames, 3,040 events decoded; fields and associations present |
| Session event details | `tool/call` ↔ `tool/result` correlatable by `callId`; `job/*` status available; `seq` strictly increasing |
| Screenshot | `CopyFromScreen` produced a nonblank 2560×1600 capture; `PrintWindow` flag 2 worked for the Harness window; flag 0 was black |
| Screenshot ownership | PID→HWND enumeration works, but a Worker has no independent window; attribution needs an explicit capture call plus time window and session event |
| Skill discovery | Project-level `.dsh/skills` bundle discovered at rank 100; UTF-8 BOM caused silent ignore |

These are mechanism demonstrations, not end-to-end product acceptance.

## 3. Critical security findings

### 3.1 Session-log external delivery

`dsh-session-log-deepseek` is enabled by default and sends incremental session log data as `dsh_session_log` with official API requests. The audit observed a `delivery-accepted` event.

This is a **P0 release blocker** for real CTF content. Disable the plugin or add a verified exclusion, then prove with a negative outbound-delivery test that a synthetic canary from a CTF session is not sent.

### 3.2 Harness permission boundary

Harness provides coarse sandbox modes and ask/never/one-time approval choices, but not TTL or per-Task/target/port/action constraints. The Manager broker must enforce those constraints.

The audit also found that `web_fetch` can reach loopback/private addresses despite comments suggesting otherwise. Network is deny-by-default and must be constrained outside the model.

### 3.3 Host Plugin and MCP

Cordis Host Plugins and MCP servers run outside the Harness sandbox. Treat both as privileged host components. Expose only Manager-declared tools and pass every action through the policy broker.

### 3.4 OS isolation status

- WSL2 is installed, but Ubuntu 24.04 is **Stopped**.
- Docker Engine and gVisor are **not installed**.
- Tier 2 isolation is therefore not available or accepted.

The current non-OS-isolated MVP boundary is temporary and prohibits execution of untrusted challenge-provided code on the host.

## 4. Shared-process and cancellation risks

- One ACP process hosts all sessions in the demonstrated setup, creating a shared failure domain.
- `session/list` does not list active sessions; Manager's own registry must be authoritative.
- ACP cancel stops a turn but does not provide verified force-kill of all underlying processes/jobs.
- Manager must persist Task/session mappings and must not mark cancellation complete until quiescence is confirmed.

## 5. Environment/toolchain gaps

The audit reports that Java/Ghidra, GDB, pwntools, SageMath, Wireshark/tshark, radare2/rizin and other CTF tools are missing or incomplete. The exact environment snapshot is in the full local report.

The latest WSL2 state above supersedes older environment notes that described WSL2 as not installed.

## 6. Explicitly NOT VERIFIED / BLOCKED

The audit did not issue `session/prompt` and made zero model calls. It did not access a target or install/configure components. The following remain unverified:

- real Worker writes and cross-workspace write isolation;
- real in-flight cancel/close behavior;
- complete permission request/approval round trip;
- MCP `tools/call`;
- full `session/update` behavior/integrity;
- production Manager ACP Client behavior;
- session-log external-delivery disable/exclusion;
- production evidence pipeline and crash recovery;
- reliable Java/Qt/GPU screenshot capture.

Do not report these as working until independently tested.

## 7. Side effects and untouched local work

The audit was read-only. It did not modify source, configuration, profiles, plugins, MCP servers, or Skills; did not install software; did not start WSL/Docker; and did not access a CTF target. Temporary artifacts remained under `%TEMP%\ctf-solver-harness-audit\`.

The separate A0-2 migration state in the legacy local workbench contains **110 uncommitted imported files** and was not touched by this audit. The new local audit report is an additional untracked file. Do not clean, reset, stage, or overwrite those local files as part of this documentation initialization.