# Product Specification

**Status:** approved baseline  
**Date:** 2026-11-10

## 1. Product definition

CTF-Solver is a semi-autonomous CTF solving extension for DeepSeek Harness. It preserves Harness as the reasoning/runtime layer and adds a Core Skill, five specialist Skills, a Manager, independent ACP Workers, a typed execution interface, policy/approval, evidence storage, and reproducible delivery.

It is not a standalone CTF platform, a new frontend, a multi-model race system, or a replacement agent runtime.

The MVP covers exactly five categories: Web, Misc, Crypto, Reverse, and Pwn. First Blood scanning is a separate future project and explicitly excluded.

## 2. Entry and conversation mode

The user explicitly enters /ctf-solver. The command is not auto-triggered by a binary, flag-like string, or generic security question.

After activation, CTF mode persists for the current conversation:
- challenge descriptions, archives, binaries, screenshots, URLs, hints, and environment details do not require repeating the command;
- 鈥渃ontinue鈥?and follow-up evidence refer to the active Task unless a clearly new challenge is introduced;
- a new challenge creates a new Task and does not overwrite the previous one;
- ambiguous continuation/task switching prompts one concise clarification;
- the user can exit with a natural-language request such as 鈥滈€€鍑?CTF 妯″紡鈥?

A new conversation requires explicit entry again. Durable Task records may be resumed explicitly, but a new chat must not silently assume an old Task is active.

Conversation mode and Task state are separate. Finishing a challenge does not automatically exit CTF mode.

## 3. Semi-autonomous operating model

The Agent may autonomously inspect challenge material, classify the task, check tool availability, form hypotheses, plan experiments, write helper scripts inside the Task workspace, run routine permitted tools through ctf-exec, iterate on actual outputs, and prepare evidence-backed deliverables.

Human approval is required before:
- executing an untrusted challenge binary or other untrusted code;
- installing software or changing the toolchain;
- accessing a remote CTF target or performing target-side actions.

Because the current environment has no accepted OS isolation tier, approval alone is not sufficient to run untrusted code on the host. Such execution remains blocked until Tier 2 isolation is installed and accepted.

Flag submission is always human-controlled. The Agent may identify and explain a candidate Flag, but the user verifies and submits it. Automatic submission is excluded.

## 4. Task and Worker model

Each challenge has a stable Task ID, independent workspace, and independent Harness ACP session.

Minimum Task fields: task_id, conversation_id, title, category, source, competition/scope profile, workspace, ACP session ID, status, timestamps, evidence-chain head, and result state.

One challenge per Task. Multiple files forming one challenge belong to the same Task; distinct challenges must not share workspaces, session IDs, or evidence.

Task lifecycle:
- created 鈫?queued 鈫?starting 鈫?running;
- running may transition to awaiting_approval or blocked;
- terminal states include completed, partial, failed, and blocked;
- cancellation first becomes cancel_requested and only becomes cancelled after process/job quiescence is confirmed.

A Task is not complete merely because the model stopped responding.

## 5. Scheduling

- Maximum active Workers: **2**.
- Additional Tasks enter a FIFO queue.
- One Worker maps to one Task and one independent ACP session/workspace.
- Manager is authoritative for queue order, active count, and Task/session mapping.
- Independent ACP sessions do not imply independent OS processes or OS isolation.

The initial design may use one managed ACP Server process for multiple sessions. This is a shared failure domain and must be surfaced.

## 6. Core Skill and five specialist Skills

Deliver one Core Skill plus five category Skills:

- Core: ctf-solver
- ctf-web
- ctf-misc
- ctf-crypto
- ctf-reverse
- ctf-pwn

The Core Skill owns intake, competition rules, Task lifecycle, and routing. Specialist Skills provide category-specific reasoning guidance and references. Skills are instruction content, not security boundaries; Manager/Runtime/Broker enforce permissions.

Project-level Skill bundles are discovered under the nearest Harness project root, for example .dsh/skills/. Use UTF-8 without BOM; the audit observed that a BOM can cause silent Skill discovery failure.

## 7. Network policy

The agreed policy distinguishes public research from competition targets:

- Public research and public documentation lookup may use the internet.
- Public research access does not authorize active probing or exploitation of the source host.
- Competition target access requires authorization for the specific Task and target, including host/port/action scope.
- Out-of-scope hosts, ports, and actions are rejected.
- Loopback/private destinations are not implicitly trusted; they require explicit scope when part of the authorized challenge.

## 8. Execution and environment

- CLI/headless tools are preferred.
- GUI is auxiliary and used primarily for required program-running screenshots; reliable GUI keyboard/mouse automation is not an MVP dependency.
- Runtime exposes a typed ctf-exec interface through MCP.
- Workers do not receive arbitrary host Shell access or Docker Socket access.
- Runtime/Broker validates Task, workspace, tool permissions, and network authorization.
- Environment/toolchain setup is separate from product development. Product performs preflight and reports missing tools; it must not silently install software or alter the legacy local CTF workbench project or Harness profile/config.

## 9. Evidence and Writeup

Capture actual execution data:
- Task / Worker / Step IDs;
- tool name and version;
- argv (not an opaque shell command string);
- working directory;
- input and output files;
- start/end timestamps;
- exit code;
- stdout and stderr;
- screenshot paths and digests;
- approval and network-grant references.

Maintain append-only evidence/events.jsonl, screenshot files, SQLite event/state index with hash chain, CAS raw bytes, and manifest.sha256. Never fabricate missing output.

The Markdown Writeup must follow the actual solving/operation order and be reproducible. Include challenge description, hypotheses and reasons for experiments, commands/argv and cwd, actual outputs/errors, failed attempts, important negative results, key program-running screenshots, verification evidence, and explicit unknowns/blocked steps.

This is a concise evidence-based account of analysis and operations, not a dump of hidden internal reasoning.

Deliverables:
1. Markdown Writeup.
2. Evidence ZIP with selected outputs, screenshots, intermediate artifacts, and manifest.sha256.
3. SHA-256 integrity manifest.

PDF conversion is a later handoff to another Agent, not part of the CTF-Solver core.

## 10. Out of scope

- Reuse of old CTF Workbench code, database, API, UI, services, or runtime components; CTF-Solver is a clean-room independent implementation.
- First Blood scanning/monitoring.
- New standalone frontend/dashboard.
- Replacement LLM runtime or second agent loop.
- Multi-model racing/swarm solving.
- Automatic Flag submission.
- Unrestricted target scanning/exploitation.
- Reliable GUI keyboard/mouse automation.
- Automatic software/toolchain installation.
- Arbitrary host Shell or direct Docker Socket access.

## 11. MVP success criteria

See ACCEPTANCE.md. The MVP must demonstrate persistent mode, independent ACP Tasks, 2-Worker FIFO, typed execution, scoped authorization, evidence integrity, session-log privacy, human Flag submission, and a reproducible Markdown Writeup plus evidence ZIP.
