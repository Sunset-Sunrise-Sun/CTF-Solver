# Product Specification

**Status:** approved baseline  
**Date:** 2026-11-10

## 1. Product definition

CTF-Solver is a DeepSeek Harness-native CTF solving extension. It adds a durable task/control/evidence layer around Harness; it is not a replacement model runtime, a separate CTF web platform, or a second autonomous agent loop.

The product is intended to support authorized CTF challenges and local challenge files across five categories:

- Web
- Misc
- Crypto
- Reverse
- Pwn

The product must preserve the user's ability to understand what is happening, approve sensitive actions, resume work, and inspect the evidence behind the final result.

## 2. Entry and conversation-mode behavior

### 2.1 Explicit entry

The user starts the mode by entering:

```text
/ctf-solver
```

The command is explicit. Do not auto-activate CTF mode merely because a message contains a binary, a flag-like string, or a security question.

### 2.2 Persistent within the current conversation

After activation, CTF mode remains active for the current Harness conversation:

- The user can send challenge descriptions, archives, binaries, screenshots, URLs, hints, and environment details without repeating the command.
- “Continue”, “try another approach”, and follow-up evidence refer to the active task unless the user clearly introduces another challenge.
- A clearly new challenge creates a new Task; it does not overwrite the previous Task.
- If the message could be either a continuation or a new challenge, ask one concise clarification rather than guessing.
- The user can leave the mode with a natural-language request such as “退出 CTF 模式”.

A new conversation is a new mode context and requires the explicit command again. Durable task records remain available for an explicit resume flow, but a new chat must not silently assume the old task is active.

### 2.3 Mode state is not task state

- **Conversation mode** says that this conversation is operating under CTF-Solver interaction rules.
- **Task state** describes one challenge and its Worker, workspace, ACP session, approvals, and evidence.

Finishing or pausing a challenge does not automatically exit conversation mode.

## 3. Task model

Each challenge has a stable Task ID and an independent workspace and Harness ACP session.

Minimum Task fields:

| Field | Purpose |
|---|---|
| `task_id` | Stable unique identifier |
| `conversation_id` | Conversation that initiated or resumed the task |
| `title` | Human-readable challenge name |
| `category` | Web / Misc / Crypto / Reverse / Pwn / Unknown |
| `source` | Attachment, local file, event platform, or user description |
| `scope_profile` | Competition rules, authorized targets, and permitted actions |
| `workspace` | `tasks/<task_id>/work` |
| `acp_session_id` | Harness session created for this task |
| `status` | Lifecycle state |
| `created_at`, `updated_at` | Timestamps |
| `evidence_head_hash` | Current task evidence-chain head |
| `result_state` | Verified / partial / not solved / blocked / unknown |

### 3.1 Task lifecycle

The initial lifecycle vocabulary is:

```text
created → queued → starting → running
                     ↘ awaiting_approval
                     ↘ blocked
                     ↘ cancel_requested
running → completed | partial | failed | blocked
cancel_requested → cancelled (only after quiescence is confirmed)
```

A task must not be marked `completed` merely because the model stopped responding. The Manager must evaluate the terminal state and evidence. If the system cannot confirm that an underlying job has stopped, it must retain `cancel_requested` or an equivalent uncertain state.

### 3.2 One challenge per Task

Multiple files that form one challenge belong to one Task. Distinct challenges receive distinct Tasks. The Manager must not mix artifacts, session IDs, or writeups between Tasks.

## 4. Worker scheduling

- Maximum active Workers: **2**.
- Additional Tasks enter a **FIFO** queue.
- One Worker maps to one Task and one independent ACP session.
- A Worker may use Harness tools and approved MCP wrappers through the Manager policy boundary.
- Independent ACP sessions do not imply independent OS processes or OS-level isolation.
- The Manager, not the model, is authoritative for queue order, active count, and Task-to-session mapping.

The first implementation uses a single managed ACP Server process with multiple task sessions unless later measurements justify a different process topology. This is a shared failure domain and must be documented and tested.

## 5. Solving workflow

1. **Intake:** collect the challenge statement and supplied artifacts.
2. **Rules and scope:** identify the competition/platform rules and authorized target scope before any network or state-changing action.
3. **Preflight:** classify the category, inventory files, check tool availability, and identify missing prerequisites.
4. **Plan:** create a short, evidence-oriented plan and identify actions requiring approval.
5. **Execute:** run permitted actions through Harness and the Manager's policy boundary.
6. **Observe:** capture actual tool arguments, outputs, exit codes, job states, and explicitly requested screenshots.
7. **Reason:** distinguish facts, hypotheses, failed attempts, and conclusions.
8. **Verify:** validate any proposed flag or exploit result against the actual challenge evidence. A guessed flag is not a solved challenge.
9. **Deliver:** produce a concise result summary, evidence references, a Markdown writeup, and a SHA-256 manifest.
10. **Persist:** save the Task state so the user can continue or resume it.

The Manager schedules and governs this workflow. Harness performs model reasoning; CTF-Solver must not implement a parallel model loop.

## 6. User-facing controls

The user should be able to:

- start the mode with `/ctf-solver`;
- add challenge material and continue without repeating the command;
- ask for current task/queue status;
- approve or reject a specific sensitive action;
- pause or request cancellation of a Task;
- continue a Task or start another Task;
- request a writeup or inspect the evidence;
- exit CTF mode.

No broad “approve all future actions” grant is implied by a single approval. Sensitive approvals are scoped to a concrete action and Task.

## 7. Deliverables

A completed or partial Task should provide:

1. **Result summary** — what was established and what remains unresolved.
2. **Flag/result** — only if actually found and verified; otherwise explicitly say not found or not verified.
3. **Writeup** — Markdown generated from evidence, with analysis narrative and reproducible commands.
4. **Evidence** — tool calls/results, relevant files, job outcomes, and explicitly captured screenshots.
5. **Integrity manifest** — SHA-256 hashes for delivered artifacts.
6. **Limitations** — missing tools, blocked actions, unverified steps, or environment constraints.

The writeup must preserve failed attempts and important negative results when they affect the reasoning. It must never fabricate command output, screenshots, flags, test results, or measurements.

## 8. Out of scope for the initial MVP

- Replacing Harness with a custom LLM/agent runtime.
- Racing multiple model providers or multi-model swarms.
- A standalone web dashboard or CTFd polling platform.
- Unrestricted autonomous scanning or exploitation of arbitrary public targets.
- Reliable GUI mouse/keyboard automation; current audit found input injection unreliable.
- Claiming OS isolation where only Harness file sandboxing exists.
- Copying whole third-party CTF frameworks or knowledge bases.

## 9. MVP success criteria

The MVP is successful only when the acceptance gates in [ACCEPTANCE.md](ACCEPTANCE.md) pass. In particular, the persistent mode, independent Task/session mapping, 2-Worker FIFO scheduler, per-call authorization, evidence integrity, session-log data handling, and writeup traceability must work together in an end-to-end local synthetic challenge.