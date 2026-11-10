# Reference Projects and Reuse Policy

**Purpose:** record useful engineering patterns without changing CTF-Solver's product direction.  
**Reviewed:** 2026-11-10

These projects are references, not dependencies. The current plan is to learn from their architecture and workflows, then implement only the pieces that fit the approved Harness-native design.

## 1. Reference matrix

| Project | Repository | Useful ideas | Deliberately not adopting |
|---|---|---|---|
| Agoni_ctf | [Agonionce/Agoni_ctf](https://github.com/Agonionce/Agoni_ctf) | Planner → ActionProposal → Policy/Approval → ToolRuntime; facts vs hypotheses; failed-attempt retention; checkpointed evidence provenance | A separate autonomous runtime, full workbench, and global experience-learning system |
| CTF Agent | [verialabs/ctf-agent](https://github.com/verialabs/ctf-agent) | Coordinator/solver separation and bounded per-challenge worker organization | Multi-model racing/swarm architecture and Docker-first framework as a direct dependency |
| CTF Learning Workspace | [kiwamizamurai/cctf](https://github.com/kiwamizamurai/cctf) | One challenge per iteration; queue + decision ledger; persistent state; platform profile and rules-first workflow | Claude-specific `/loop` and `/goal` as user-facing commands; CTF-Solver uses one `/ctf-solver` entry |
| 0xAF-Re | [overkazaf/re-agent](https://github.com/overkazaf/re-agent) | Planner/executor role separation, workflow visibility, session resume concepts, local RE tool integration | A standalone Go terminal agent and independent provider/model orchestration |
| ctf-skills | [ljagiello/ctf-skills](https://github.com/ljagiello/ctf-skills) | Specialist category Skills, prerequisites, on-demand tool installation, reusable technique references | Copying the full skill corpus or bulk payload collection |
| Open-ReverseLab | [LING71671/open-reverselab](https://github.com/LING71671/open-reverselab) | Scenario → signal → method → evidence chain; MCP tool mapping; executable reverse-engineering knowledge | Deploying its entire 100+ MCP tool stack or copying its GPL-licensed code |

## 2. Specific patterns to adapt

### 2.1 Evidence-driven reasoning (Agoni_ctf)

Keep facts, hypotheses, experiments, failed attempts, and conclusions as separate record types. Every important conclusion should link to the observation that supports it. This directly informs the Manager evidence schema.

### 2.2 Bounded coordinator and workers (CTF Agent)

Keep a clear Manager/Worker boundary and bound concurrency. CTF-Solver uses the agreed limit of two Workers and FIFO scheduling. It does not race different model providers or create multiple competing solver swarms.

### 2.3 Queue and decision ledger (cctf)

Persist Task status and an append-only decision/evidence history. A Task should be resumable without relying on the model's current context window. The useful abstraction is persistent task state, not the external framework's command syntax.

### 2.4 Specialist Skills and prerequisites (ctf-skills)

Use concise category references and explicit prerequisites. Check for tools before attempting a workflow; if a required tool is absent, explain the gap rather than inventing output. References should be loaded only when relevant.

### 2.5 Executable knowledge mapping (Open-ReverseLab)

Organize reverse-engineering notes around a challenge signal, method, evidence, and the tool that can reproduce the step. Keep this as a curated reference library rather than copying a large MCP stack.

## 3. License and provenance notes

License observations below are based on the repository root license files inspected on 2026-11-10. Re-check before any code reuse.

| Project | License observed | Reuse rule |
|---|---|---|
| Agoni_ctf | Apache-2.0 | Source reuse only with Apache notice/attribution and applicable license obligations |
| verialabs/ctf-agent | MIT | Source reuse only with MIT copyright and permission notice |
| kiwamizamurai/cctf | No root `LICENSE` file found in the inspected path | Treat source as all-rights-reserved; use ideas only unless license is clarified |
| overkazaf/re-agent (0xAF-Re) | MIT | Source reuse only with MIT copyright and permission notice |
| ljagiello/ctf-skills | MIT | Source reuse only with MIT copyright and permission notice |
| LING71671/open-reverselab | GPL-3.0 | Do not copy or derive code without an explicit GPL compatibility decision and compliance plan |

A repository being public does not grant permission to copy its source. Keep copied snippets (if any are later approved) traceable to the source file, commit, author, and license. Prefer original implementations of the patterns above.

## 4. Product-direction guardrail

These references must not change the approved product contract:

- CTF-Solver remains a DeepSeek Harness-native extension.
- `/ctf-solver` is the single explicit mode-entry command.
- The mode persists within the current conversation.
- Each challenge gets its own Task, workspace, and ACP session.
- Maximum two active Workers; FIFO queue.
- Harness remains the reasoning/tool runtime; no second model loop.
- Manager owns authorization, evidence, screenshots, and writeup delivery.