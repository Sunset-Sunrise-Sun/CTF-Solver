---
name: ctf-crypto
description: Crypto challenge reasoning for CTF-Solver; prefer mathematical structure and breakthrough analysis before brute-force computation, use trusted local computation tools with recorded evidence, human-approval rules inherited from ctf-solver.
---

# Crypto Challenges

## Order of work

1. **Collect the mathematical object** — extract parameters (moduli, exponents, curves,
   nonces, ciphertexts, keys, IVs, oracle behaviour), the scheme/algorithm, and the
   challenge's apparent weakness. Record exact values/hashes of supplied files.
2. **Identify the structure before computing** — look for reused nonces/IVs, low
   exponents, weak primes/close primes, common-factor RSA moduli, small subgroup,
   predictable randomness, faulty padding, linearity, known plaintext, length leaks,
   oracle queries, algebraic relations, lattice-friendly relations.
3. **Prefer a mathematical breakthrough over blind brute force** — write the relation or
   attack plan first, then implement the smallest computation that tests it. Brute force
   is acceptable only when bounded, justified, and recorded.
4. **Use trusted local computation** — helper scripts inside the Task workspace, typed
   trusted `ctf-exec` tools, integer arithmetic, hashing and encodings. Record the actual
   script hash, argv, cwd and output.

## Common families

- RSA: factorization weaknesses, small e/Coppersmith-style relations, common modulus,
  shared primes, partial key exposure, OAEP/PKCS#1 v1.5 issues, signature forgery.
- Block ciphers/modes: ECB patterns, IV/nonce reuse, CBC bit-flipping, padding oracles,
  CTR keystream reuse, GCM nonce misuse.
- Stream/PRNG/MT19937: state recovery from outputs, predictable seeds, LCG relations.
- Elliptic curves: invalid-curve/small-subgroup points, nonce reuse, parameter anomalies.
- Classical/encoding: substitution/Vigenère/homophonic patterns, XOR with known plaintext,
  base encodings, hash length-extension.
- ZK/commitments/protocols: transcript analysis, binding/hiding failures, protocol
  algebra.

## Evidence requirements

- Record the actual computation inputs, script/command, output, intermediate values
  needed to reproduce, and which hypothesis each step tested.
- When a script writes files, keep them in the Task workspace and include selected
  artifacts in the evidence ZIP.
- Mark failed hypotheses and negative results explicitly; do not erase them.

## Safety and honesty

- Do not fabricate plaintext, keys or a Flag: a recovered candidate Flag is recorded as
  `candidate` and only the user submits it.
- Do not use online cracking/oracle services for a real target; no remote target access
  without a Task-scoped grant.
- Do not install crypto libraries or tools; if a required library is missing, report the
  exact missing dependency as a blocked step instead.

## Evidence recording (native tools)

- Native Lead tool calls are recorded automatically from the Lead session log; never hand-write or copy evidence.
- Capture screenshots only at real checkpoints, with `step_id` = `turn{N}-step{S}`.
- Distinguish 未执行 / 执行失败 / 未记录 honestly; never state an unrecorded step as a fact.
