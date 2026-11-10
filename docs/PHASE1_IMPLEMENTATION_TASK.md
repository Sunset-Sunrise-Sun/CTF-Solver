# Phase 1 Implementation Task — Manager ACP Client

**Branch:** feat/phase1-acp-manager  
**Goal:** implement and validate the first Manager slice without changing the agreed product direction.  
**Execution mode:** local synthetic tests only; no model prompt and no CTF target access.

## 0. Read first

Before coding, read:
1. docs/PRODUCT_SPEC.md
2. docs/ARCHITECTURE.md
3. docs/DECISIONS.md
4. docs/SECURITY.md
5. docs/ACCEPTANCE.md
6. docs/HARNESS_INTEGRATION_AUDIT_SUMMARY.md
7. The complete local report at D:/CTFworker/docs/HARNESS_INTEGRATION_CAPABILITY_AUDIT.md

The full local report is 46,444 bytes with SHA-256:
955136d156a878fc932243081cc42d72575bc4f65510dc03163cb689d7fe5373

Do not infer details omitted from the summary. Use the full local report for exact ACP method names, executable launch details, environment variables, event/log paths, and verified behavior.

## 1. Protect existing local state

The audit owner reports that D:/CTFworker contains 110 uncommitted imported files from the separate A0-2 migration, plus the new untracked audit report. The audit did not touch those files.

Before any local operation:
- inspect git status, current branch, remotes, and recent commits read-only;
- record the 110-file inventory and current working-tree state;
- do not reset, clean, checkout over, stage, commit, stash, delete, rename, or overwrite those imported files;
- do not alter the full local audit report;
- if the local directory cannot safely accept the new remote history, create a separate clean clone/worktree for this branch and leave D:/CTFworker untouched.

This task authorizes changes to the CTF-Solver repository branch only. It does not authorize changes to the existing D:/CTF project, Harness profile/config, installed software, WSL, Docker, or system settings.

## 2. Scope

Implement only the Manager ACP Client and the minimum Task/session registry needed to prove independent per-Task ACP sessions.

In scope:
- robust stdio ND-JSON / JSON-RPC 2.0 client transport;
- explicit launch/supervision of the audited Harness ACP Server mode;
- initialize/handshake and the non-prompt lifecycle methods verified by the full audit;
- one session/new per Task with cwd=tasks/<task_id>/work;
- persist Task ID, Worker ID, ACP session ID, and workspace mapping;
- Manager-owned active-session registry (do not rely on session/list for active sessions);
- max two active Workers and FIFO queue;
- close/shutdown handling and truthful interrupted/cancel-requested states;
- structured logs and deterministic tests.

Out of scope for this phase:
- session/prompt or any model call;
- solving a real challenge;
- remote CTF target access;
- ctf-exec implementation;
- Docker/WSL setup or toolchain installation;
- Flag submission;
- standalone frontend;
- mandatory Cordis Host Plugin implementation;
- category Skill content.

## 3. ACP Client requirements

Implement the ACP Client from the protocol evidence in the local report. Do not assume a shipped ACP client package exists.

Transport requirements:
- stdio ND-JSON framing;
- handle partial stdout reads and multiple JSON messages;
- unique JSON-RPC request IDs and correct response correlation;
- distinguish protocol messages from stderr diagnostics;
- handle CRLF/LF, large messages, malformed JSON, EOF, timeout, and child-process exit;
- avoid deadlocks when stdout/stderr are both active;
- never treat a partial log/message as a successful response;
- provide explicit startup, ready, closing, stopped, and failed states.

Process requirements:
- launch the verified dsh ACP Server mode using the executable path and environment discovered in the full audit;
- do not assume dsh.exe is on PATH;
- use a dedicated DSH_HOME for tests where the audit requires it;
- do not change the user's normal Harness profile/config;
- record process PID, start/end time, exit code, and stderr diagnostics;
- ensure shutdown closes stdin and waits for the server to exit;
- do not silently kill a shared ACP process while another Task is active.

Protocol requirements:
- use only methods/fields confirmed by the full audit or protocol implementation;
- create one session per Task with the Task workspace as cwd;
- persist returned session IDs before reporting the Worker as ready;
- track active sessions in Manager storage because session/list omits active sessions;
- do not claim successful resume unless the real recovery path has passed tests;
- ACP cancel is turn cancellation only; do not claim it kills underlying jobs.

## 4. Task registry and scheduler

Minimum Task/Worker state:
- task_id
- worker_id
- acp_session_id
- workspace
- queue_position
- status
- created_at / updated_at
- last_error
- cancellation_state

Rules:
- no more than two active Workers;
- queued Tasks are FIFO;
- a Worker is bound to exactly one Task and one workspace;
- a Task cannot reuse another Task's session or workspace;
- a slot is released only after the Worker is terminal and associated work is known to be quiescent;
- when quiescence cannot be verified, preserve an uncertain/cancel_requested state.

Use SQLite as the authoritative persistent state store, consistent with the architecture. Choose a SQLite implementation available in the audited local environment; do not install a new database service. If a dependency is needed, explain and request approval rather than silently installing it.

## 5. Tests

### Unit tests with a fake ACP Server

Cover:
- fragmented ND-JSON messages;
- multiple messages in one read;
- response/event interleaving;
- request ID correlation;
- CRLF/LF;
- large message;
- stderr output;
- malformed JSON;
- EOF before response;
- timeout;
- child process exit;
- startup and graceful shutdown;
- duplicate/unknown response IDs.

### Task/scheduler tests

Cover:
- Task A and Task B receive different session IDs and workspaces;
- Task C waits while A and B are active;
- FIFO order is preserved;
- completing A starts C;
- failure of one session does not mark another Task complete;
- restart reloads the Task/session mapping without silently duplicating sessions.

### Real ACP smoke test — zero model calls

Use the isolated test setup described in the full audit:
- launch dsh --profile acp;
- initialize the server;
- create three sessions with distinct temporary workspaces;
- verify session IDs are distinct;
- verify active-session listing behavior;
- close one session and verify the others remain unaffected;
- test stdin EOF/shutdown behavior;
- record all outputs and exit codes.

**Do not send session/prompt. Do not trigger a model call. Do not access any CTF target.**

The audit's 22/22 ACP lifecycle checks are a baseline, not proof that the new Manager Client passes.

## 6. Deliverables

- implementation code;
- unit and integration tests;
- exact test commands and raw results;
- a short architecture note for any implementation choice not already fixed;
- an acceptance report with PASS / FAIL / BLOCKED / NOT VERIFIED;
- a list of files changed and proof that the 110 imported local files were untouched.

Do not mark the phase complete if real ACP smoke tests, persistence, or FIFO behavior are unverified.

## 7. Stop conditions

Stop and report instead of guessing if:
- the full audit report does not establish a required protocol detail;
- the installed dsh executable cannot be resolved safely;
- the local repository state cannot be protected;
- the ACP Server requires a profile/config change;
- a test would issue session/prompt or access a real target;
- a new software installation or environment change appears necessary.

Any change to the product contract requires an explicit proposal and approval.