---
name: ctf-pwn
description: Pwn challenge reasoning for CTF-Solver; local static analysis and safe reasoning first, remote exploitation only with a one-time Task/target/action-scoped authorization window (no remote target is contacted in this development cycle), evidence-first, human-approval rules inherited from ctf-solver.
---

# Pwn Challenges

## Hard execution/authorization boundary

- Local static analysis is permitted: binary metadata, hashes, imports, protections
  (PIE/NX/Canary/RELRO/FORTIFY), symbols, disassembly notes, source review, libc
  fingerprinting from provided files, and exploit design reasoning.
- **Executing challenge-provided binaries locally is BLOCKED** while Tier 2 OS isolation
  is unavailable; approval alone does not authorize host execution of untrusted code.
- **Remote target access is denied** until the Task has an explicit, Task/target/action
  scoped authorization window (host, port, protocol, method, TTL, call count, approver).
  In this development cycle no remote target is contacted at all.
- No arbitrary host shell, no raw Docker socket, no direct process-spawning workaround.

## Static workflow

1. **Triage** — file type/arch, language/runtime, size, SHA-256, mitigations, linked libc
   if supplied, input paths, obvious bug classes.
2. **Locate the vulnerability from the code/bytes** — buffer/format/string/heap/integer/
   type-confusion/race/sandbox-escape candidates; specify the exact call chain and the
   evidence (offsets, disassembly excerpts, source lines).
3. **Design the exploit** — control-flow target, primitive, offsets, ROP/ret2libc/one-gadget
   candidates, heap layout plan, bypasses for the observed mitigations. Write the plan
   with the evidence for each claim.
4. **If a local isolated environment is later accepted** — build and verify the exploit
   there, recording tool versions, images/digests, argv, exit codes, stdout/stderr and
   screenshots of program-running steps. Until then, mark the dynamic verification step
   BLOCKED.
5. **Remote stage** — only after the Manager records a matching Task-scoped grant and
   human approval. One window covers one target/action/TTL/call-count; it never transfers
   to another Task, host, port or action.

## Evidence requirements

- Record exact hashes, protection checks, offsets, exploit scripts (hash), and actual
  outputs for every permitted step.
- Distinguish “statically reasoned” from “verified execution”; never claim a working
  exploit without execution evidence (and execution is blocked in this cycle).

## Safety and honesty

- No real target contact in this development cycle; no Flag submission by the Agent.
- A candidate Flag is recorded as `candidate`; the user confirms and submits.
- Do not fabricate a shell, a leak, a crash or a Flag.

## Evidence recording (native tools)

- Native Lead tool calls are recorded automatically from the Lead session log; never hand-write or copy evidence.
- Capture screenshots only at real checkpoints, with `step_id` = `turn{N}-step{S}`.
- Distinguish 未执行 / 执行失败 / 未记录 honestly; never state an unrecorded step as a fact.
