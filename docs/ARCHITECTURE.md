# Architecture

**Status:** approved logical architecture; implementation details remain subject to acceptance tests  
**Date:** 2026-11-10

## 1. Architecture principle

DeepSeek Harness remains the model/agent runtime. CTF-Solver adds a control plane around Harness:

- conversation-mode entry and Task intake;
- bounded Worker scheduling;
- one independent ACP session and workspace per Task;
- policy and approval brokering;
- session/event ingestion;
- tamper-evident evidence storage;
- explicit screenshot capture;
- reproducible writeup generation.

There must not be a second CTF-specific model loop. The Manager may schedule and resume Harness sessions, but it does not independently reimplement planning/reasoning.

## 2. Logical component diagram

```text
┌──────────────────────────────────────────────────────────────┐
│ DeepSeek Harness interactive conversation                    │
│                                                              │
│  /ctf-solver ──► project Skill (mode + workflow instructions) │
│                         │                                    │
│                         ▼                                    │
│             thin Cordis Host Plugin / CTF tools              │
└─────────────────────────┬────────────────────────────────────┘
                          │ typed Manager calls
                          ▼
┌──────────────────────────────────────────────────────────────┐
│ CTF-Solver Manager Core                                      │
│                                                              │
│  Conversation/Task Registry ── FIFO Scheduler (max 2)         │
│              │                                               │
│              ├── Policy Engine + external per-call broker    │
│              ├── ACP Client                                  │
│              ├── Event + session-log ingestor                │
│              ├── Screenshot capture/attribution              │
│              ├── SQLite evidence index + hash chain          │
│              ├── CAS artifact store                          │
│              └── Writeup/manifest generator                  │
└─────────────────────────┬────────────────────────────────────┘
                          │ stdio ND-JSON / JSON-RPC 2.0
                          ▼
              ┌───────────────────────────────┐
              │ dsh --profile acp             │
              │ Harness ACP Server            │
              │                               │
              │ session A: Task A workspace   │
              │ session B: Task B workspace   │
              │                               │
              │ Harness model/tool loop       │
              └───────────────────────────────┘
```

The Cordis Host Plugin is an integration adapter, not a second runtime. It may register CTF tools, subscribe to Harness events, intercept tool lifecycle hooks, and relay scoped approval requests. The plugin is fully trusted host code and is not protected by the Harness sandbox.

## 3. Component responsibilities

### 3.1 Project Skill bundle

Location in the target Harness project:

```text
.dsh/skills/ctf-solver/
├── SKILL.md
├── references/
│   ├── web.md
│   ├── misc.md
│   ├── crypto.md
│   ├── reverse.md
│   └── pwn.md
└── scripts/
    └── ...
```

Responsibilities:

- expose the explicit `/ctf-solver` entry;
- explain persistent conversation-mode behavior;
- route user requests to Manager tools;
- provide concise category-specific guidance through on-demand references;
- require evidence-backed claims and explicit unknowns.

The Skill is instruction content, not a security boundary. It must be UTF-8 without BOM; the audit observed that a BOM can cause silent discovery failure. Project-level skill discovery was verified at rank 100.

### 3.2 Cordis Host Plugin

Responsibilities:

- register a small, typed CTF tool surface for the Skill;
- relay tool calls to Manager Core;
- subscribe to relevant session/tool events;
- participate in approval request/response handling;
- expose explicit screenshot and Task-status operations where required.

The plugin must remain thin. It must not contain category-specific solving logic or its own model loop. Because Host Plugins are fully trusted and outside the sandbox, minimize dependencies, filesystem reach, and exposed methods; review every release.

The precise packaging/lifecycle arrangement for the Manager modules should be chosen to minimize IPC and operational complexity, while preserving the logical Manager boundary. Do not treat in-process code as sandboxed.

### 3.3 Manager Core

Manager Core is the authoritative control plane. It owns:

- conversation-mode and Task registry;
- Task IDs, workspace paths, ACP session IDs, and lifecycle state;
- 2-Worker concurrency and FIFO scheduling;
- scope profiles and per-call authorization;
- ACP client transport and lifecycle;
- session-log ingestion and event correlation;
- evidence hash chain and CAS;
- screenshot metadata/attribution;
- writeup and integrity-manifest generation.

The Manager is not a second agent loop. It may issue ACP protocol operations and manage Task state, but challenge reasoning remains in Harness.

### 3.4 ACP Client and Harness ACP Server

The audited Harness is an **ACP Server**, not an ACP Client. The shipped runtime did not provide a `dsh-subagent-acp` client. Manager Core must therefore implement the ACP Client transport or use a separately audited ACP host/runner.

The verified server mode is launched as:

```text
dsh --profile acp
```

Transport: stdio ND-JSON, JSON-RPC 2.0.

For each Task, Manager calls `session/new` with the Task's working directory:

```text
tasks/<task_id>/work
```

The Manager persists the returned ACP session ID and maps it to the Task. The initial design uses one managed ACP Server process with multiple independent sessions. This is session isolation, **not** process or OS isolation.

Important audited behavior:

- `session/list` does not include active sessions; it cannot be the Manager's authoritative active-Task registry.
- The Manager must persist active session IDs and Task mappings itself.
- A single ACP process hosts all sessions in the initial design, creating a shared failure domain.
- ACP cancel stops a turn but does not provide a verified force-kill of all underlying work.
- Resume error paths were tested; successful production recovery and in-flight close/cancel behavior remain acceptance items.

The Manager must not claim a Task is cancelled until it has confirmed that associated jobs/processes are quiescent. Otherwise use `cancel_requested`/uncertain status.

### 3.5 Policy and approval broker

Harness permissions alone are insufficient for CTF scope control. They expose coarse sandbox/ask/never modes and one-time approval decisions, but do not enforce TTL or per-Task/target/port/action constraints.

All sensitive actions must pass through the Manager broker. A grant should bind at least:

- Task ID;
- action/tool name;
- target host/IP and port, where applicable;
- protocol/method and optional path constraints;
- permitted operation;
- expiry and call count;
- approving user and decision record.

No network access is granted by default. A broad approval for one action must not silently authorize later actions or other Tasks.

### 3.6 MCP boundary

MCP is opt-in and not preconfigured in the audited profile. A dummy stdio MCP server was mounted through `session/new.mcpServers`, and discovery/initialization/tool listing succeeded. A real `tools/call` was not verified because it required a model call.

CTF-Solver must:

1. declare/allowlist MCP servers through Manager-owned configuration;
2. wrap MCP tools in typed Manager actions;
3. run each call through the same per-call policy broker;
4. record arguments, result, errors, and artifact references;
5. never expose a raw MCP bypass to a Worker.

MCP servers execute outside the Harness sandbox and must be treated as trusted host-side processes.

## 4. Evidence data flow

```text
Harness session JSONL.zstd ─┐
                             ├──► parser + event normalizer
Live Cordis/session events ──┘              │
                                            ▼
                                  callId / seq correlation
                                            │
                      ┌─────────────────────┴────────────────────┐
                      ▼                                          ▼
             SQLite append-only index                    CAS (SHA-256)
             task/event/approval/job                     raw outputs/files/
             chain_prev_hash + chain_hash                 screenshots/archives
                      │                                          │
                      └─────────────────────┬────────────────────┘
                                            ▼
                                  Writeup + manifest
```

The audit verified that session logs contain useful events, including `tool/call`, `tool/result`, `job/registered`, `job/settled`, approval events, command events, and monotonically increasing `seq` values. Tool calls and results can be correlated by `callId`.

The session log is zstd-compressed as concatenated independent frames. A single-frame Node decode returned only the first frame; Python `zstandard` streaming decode successfully read the complete audited log. Any production parser must scan/decode every frame and test against multi-frame fixtures.

Harness logs have no hash chain or signature. Manager ingestion must preserve raw source bytes and create its own append-only, tamper-evident chain. A local hash chain detects accidental or unauthorized edits relative to its stored head; it is not a digital signature or proof against an attacker who can rewrite the database and chain head.

## 5. Suggested local data layout

Runtime data must stay outside Git:

```text
.ctf-solver-data/
├── manager.sqlite
├── cas/
│   └── sha256/<prefix>/<digest>
├── sessions/
│   └── <acp-server-instance>/
├── exports/
└── temp/

tasks/
└── <task_id>/
    ├── work/                 # ACP session cwd; challenge working files
    ├── evidence/
    │   ├── events.jsonl     # normalized evidence references
    │   └── manifest.json
    └── writeup.md
```

The exact root may be configurable, but it must be outside tracked source paths or covered by strict ignore rules. Challenge attachments, credentials, screenshots, session logs, databases, and CAS objects must never be committed by default.

## 6. Evidence event contract

Each normalized evidence record should include:

- schema version;
- event ID and source event ID;
- Task ID, conversation ID, ACP session ID;
- sequence number and timestamp;
- event type;
- tool name and canonicalized arguments, when applicable;
- `callId` and correlated result reference, when applicable;
- exit code, `isError`, job status/cause/detail, when available;
- artifact CAS references and SHA-256 digests;
- previous chain hash and current chain hash;
- provenance and parser version.

The ingest path must be idempotent, detect sequence gaps, retain unmatched calls/results as explicit gaps, and preserve the original raw event data in CAS.

## 7. Screenshot attribution

The audit verified desktop capture with PowerShell `CopyFromScreen` and window capture with `PrintWindow` flag 2. A worker has no independent desktop window, so PID-to-HWND enumeration does not establish Worker ownership.

MVP rule:

- screenshots are captured only through an explicit capture call;
- the request includes Task ID, ACP session ID, step ID, capture scope (desktop or named window), and a timestamp;
- Manager records the capture event and CAS digest;
- association uses the explicit call plus a bounded time window and corresponding session event;
- never infer that a screenshot belongs to a Worker merely because a process exists;
- do not silently capture the user's desktop in the background.

Java/Qt/GPU application capture remains unverified. GUI keyboard/mouse injection was unreliable in the audit; prefer CLI tools and headless modes.

## 8. Failure and recovery

The Manager must persist Task/session mappings before relying on them. Because the ACP Server is a shared process and active sessions are absent from `session/list`, recovery must use the Manager database and verify each session explicitly.

Required failure handling:

- ACP Server exits: mark affected sessions as interrupted; do not mark Tasks complete.
- Manager restarts: reload Task/queue/session mappings from SQLite and reconcile against available ACP state.
- Session log is missing or corrupt: preserve the gap and mark evidence incomplete.
- zstd frame decode fails: do not silently accept a partial log.
- Worker turn cancellation: mark `cancel_requested` until job quiescence is verified.
- Screenshot capture fails or is blank: record failure; do not create a placeholder image or claim capture success.

## 9. Implementation boundaries

- No direct edits to Harness core.
- No custom second LLM loop.
- No raw MCP calls bypassing Manager.
- No reliance on Harness sandbox as OS isolation.
- No automatic upload of CTF session logs.
- No challenge data in Git.
- No production claim until the tests in [ACCEPTANCE.md](ACCEPTANCE.md) pass.