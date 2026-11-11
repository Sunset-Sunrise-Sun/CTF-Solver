---
name: ctf-reverse
description: Reverse-engineering challenge reasoning for CTF-Solver; static analysis first, dynamic execution only inside a separately accepted Tier 2 isolation environment (unavailable in this cycle), evidence-first, human-approval rules inherited from ctf-solver.
---

# Reverse Engineering Challenges

## Hard execution boundary

- Static analysis is the default and is permitted: file metadata, hashing, strings,
  import/export tables, section layout, disassembly notes, decompiler output produced by
  trusted installed tools, byte-level inspection, and source-code reading when provided.
- **Dynamic execution of challenge-provided binaries is BLOCKED** while Tier 2 OS
  isolation is unavailable. Human approval alone is not sufficient to run untrusted code
  on the host. Do not run challenge binaries, DLLs, installers, macros, shellcode or
  exploit payloads directly on Windows.
- If the challenge requires dynamic execution, stop at the boundary, record the blocked
  step with evidence, and tell the user that an accepted isolated environment is needed.

## Static workflow

1. **Triage** — filename, size, SHA-256, magic/type, architecture, endianness, linkage,
   packing/entropy indicators, language/runtime fingerprints (native, .NET, Java, Python
   bytecode, Electron, Unity/IL2CPP, Go, Rust).
2. **Map the program** — entry points, main, imports, strings, constants, embedded data,
   resources, config, suspicious checks, anti-debug/anti-VM hints.
3. **Identify the check** — flag comparison routine, transformation chain, license/CRC
   logic, key schedule, virtual machine/opaque predicates, encryption parameters.
4. **Reconstruct the algorithm** — write a clean independent implementation inside the
   Task workspace that decodes/derives the expected input from the observed constants,
   then verify its output against the static evidence.
5. **If a licensed trusted sandbox becomes available in a future accepted environment** —
   only then use dynamic tools, recording tool versions, argv, screenshots of GUI
   program-running steps, and the exact isolation acceptance that permitted execution.

## Available tooling expectations

Ghidra/JDK, GDB, radare2/rizin, IDA and similar tools may be missing. Do not install
them. Use what preflight reports; if a needed trusted tool is absent, report the blocked
step with the exact dependency. Pure-Python static reasoning over provided source or
decoded formats is always allowed.

## Evidence requirements

- Record hashes, exact commands/tools used for static inspection, actual outputs
  (bounded), reconstructed algorithms/scripts, and conclusions tied to observations.
- Keep screenshots for steps where a GUI program was actually run (only inside an
  accepted isolation environment).

## Safety and honesty

- Never fabricate a key, plaintext or Flag. A candidate Flag is recorded as `candidate`
  and only the user confirms and submits it.
- Do not bypass the execution boundary by using shell one-liners, installers or host
  PowerShell to run challenge code.
