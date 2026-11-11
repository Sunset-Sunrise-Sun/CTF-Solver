---
name: ctf-misc
description: Misc challenge reasoning for CTF-Solver; file/archive metadata and format inspection first, bounded local analysis, documented finite attempt budget for encrypted archives, evidence-first, human-approval rules inherited from ctf-solver.
---

# Misc Challenges

## Order of work

1. **Inventory before acting** — record each supplied file: name, size, SHA-256, detected
   type, magic bytes, archive listing (names, sizes, compression method, encryption
   flags) and embedded metadata. Never execute supplied files.
2. **Identify the format and structure** — binary/container headers, padding, trailing
   data, concatenated formats, steganography carriers, QR/barcode images, office/PDF
   structures, PCAP metadata, log formats, esoteric encodings.
3. **Form hypotheses** — e.g. “data hidden after PNG IEND”, “zip with known-plaintext
   attack”, “base32→xor→gzip chain”. For each, define the smallest permitted local check
   and record the actual result.
4. **Bounded local analysis** — use typed trusted tools inside the Task workspace
   (hashing, metadata, archive listing, text/hex/strings inspection, bounded decode
   steps). Write helper scripts inside the workspace when a chain of transformations is
   needed; record every actual argv/cwd/output.

## Encrypted archives and password puzzles

- Autonomously analyze likely password clues from the challenge text/files (title,
  description, filenames, metadata, common wordlists already present locally).
- Perform only **bounded local attempts** against the archive: choose a finite attempt
  budget, record the exact candidate list/source and the count tried.
- Do not launch unbounded brute force or use online cracking services.
- When the documented finite budget is exhausted, stop, report what was tried with the
  actual command/output evidence, and ask the user for a hint/password. Do not pretend
  the archive was cracked.

## Evidence requirements

- Record original hashes, exact transformation steps (input hash → command → output
  hash), and actual outputs. Keep intermediate artifacts inside the Task workspace and
  selected ones in the evidence ZIP.
- Text evidence is primary; use explicit screenshots only for GUI/program-running steps.

## Safety and honesty

- Never execute challenge-provided binaries/scripts/macros/installers on the host;
  Tier 2 isolation is unavailable in this development cycle.
- No network target access unless a Task-scoped grant exists (rare for misc challenges).
- Do not fabricate an extracted flag; candidate Flag state is `candidate` and only the
  user submits it.

## Evidence recording (native tools)

- Native Lead tool calls are recorded automatically from the Lead session log; never hand-write or copy evidence.
- Capture screenshots only at real checkpoints, with `step_id` = `turn{N}-step{S}`.
- Distinguish 未执行 / 执行失败 / 未记录 honestly; never state an unrecorded step as a fact.
