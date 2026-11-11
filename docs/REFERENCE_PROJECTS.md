# Reference Projects and Reuse Policy

**Purpose:** record useful engineering patterns without changing CTF-Solver's product direction.  
**Reviewed:** 2026-11-10

These projects are references, not dependencies. Learn from their architecture and workflows, then implement only what fits the approved Harness-native design.

## Reference matrix

| Project | Repository | Useful ideas | Not adopting |
|---|---|---|---|
| Agoni_ctf | https://github.com/Agonionce/Agoni_ctf | Planner → ActionProposal → Policy/Approval → ToolRuntime; facts vs hypotheses; failed-attempt retention; checkpointed evidence provenance | Separate autonomous runtime, full workbench, global experience-learning system |
| CTF Agent | https://github.com/verialabs/ctf-agent | Coordinator/solver separation and bounded per-challenge worker organization | Multi-model racing/swarm architecture |
| CTF Learning Workspace | https://github.com/kiwamizamurai/cctf | One challenge per iteration; queue + decision ledger; persistent state; platform profile and rules-first workflow | Claude-specific /loop and /goal as user-facing commands |
| 0xAF-Re | https://github.com/overkazaf/re-agent | Planner/Executor/Researcher separation; task queue/progress; approvals; session recovery concepts; evidence and local RE tool integration | Standalone Go terminal agent and independent provider/model orchestration |
| ctf-skills | https://github.com/ljagiello/ctf-skills | Five specialist Skill domains, prerequisites, on-demand tool installation, reusable technique references | Copying the full skill corpus or bulk payload collection |
| Open-ReverseLab | https://github.com/LING71671/open-reverselab | Scenario → signal → method → evidence chain; MCP tool mapping; executable reverse-engineering knowledge | Deploying its entire 100+ MCP tool stack or copying GPL-licensed code |

## Patterns to adapt

- **Agoni_ctf:** separate facts, hypotheses, experiments, failed attempts, and conclusions; link conclusions to supporting observations.
- **CTF Agent:** clear Manager/Worker boundary and bounded concurrency. CTF-Solver uses two Workers FIFO, not model races.
- **cctf:** persistent Task state and append-only decision/evidence history. Borrow the state pattern, not command syntax.
- **0xAF-Re:** separate planning, controlled execution, and research/evidence review; map these onto Harness Skills, Manager, and Runtime/Broker.
- **ctf-skills:** Core Skill plus five specialist category Skills; prerequisites and on-demand references.
- **Open-ReverseLab:** organize RE notes around challenge signal, method, evidence, and reproducible tool mapping.

## License and provenance notes

License observations are based on repository root license files inspected on 2026-11-10. Re-check before code reuse.

| Project | License observed | Reuse rule |
|---|---|---|
| Agoni_ctf | Apache-2.0 | Source reuse only with notices/attribution and applicable obligations |
| verialabs/ctf-agent | MIT | Retain MIT copyright and permission notice |
| kiwamizamurai/cctf | No root LICENSE file found in inspected path | Treat source as all-rights-reserved; use ideas only unless clarified |
| overkazaf/re-agent (0xAF-Re) | MIT | Retain MIT copyright and permission notice |
| ljagiello/ctf-skills | MIT | Retain MIT copyright and permission notice |
| LING71671/open-reverselab | GPL-3.0 | Do not copy/derive code without explicit GPL compatibility and compliance decision |

A public repository does not automatically grant permission to copy source. Prefer original implementations of the patterns above.

## Product-direction guardrail

- DeepSeek Harness remains the reasoning/runtime layer.
- /ctf-solver is the single explicit mode-entry command and persists within the current conversation.
- Core Skill + five specialist Skills.
- Each challenge has an independent Task, workspace, and ACP session.
- Maximum two active Workers; FIFO queue.
- Typed ctf-exec via MCP; no arbitrary host Shell or Docker Socket for Workers.
- Manager owns task state, authorization, SQLite/CAS evidence, Writeup, and evidence ZIP.
- Human approves sensitive actions and submits the Flag.
- First Blood scanning is separate and excluded from this MVP.