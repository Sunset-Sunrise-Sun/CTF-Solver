# CTF-Solver Beta 0.1.1 — release information

This directory is the **public Beta** of CTF-Solver for evaluation and community testing.
It is not a stable release, not an open-source release, and not yet cross-machine accepted.

- **Product:** CTF-Solver 0.1.1 (Lead-first CTF solving extension for DeepSeek Harness)
- **Beta source snapshot:** remediation commit
  `3798b2850ad2c72e3a8ae1db846dfcf92c06b638`, built on the clean-snapshot release
  candidate `4f5c70657b3c065c21c1c9c9ae7bd607f352b6ce`.
- **Validated wheel (internal acceptance artifact):** `ctf_solver-0.1.1-py3-none-any.whl`,
  SHA-256 `f226e110dabe6dd746db21eaa23f7ff2f01aba2fafb490b587203d9a2d7515d3`.
- **History:** the Beta branch is a clean public snapshot. It does not include internal
  development bundles, audit evidence directories, local configuration copies, session
  logs, databases, screenshots, challenge answers or flags.
- **License:** proprietary public Beta under the limited evaluation grant in `LICENSE`.
  The project is **not** open source; the owner is expected to confirm or replace the
  license before a stable release.
- **Third-party components:** none bundled and no runtime third-party dependency. The
  product and the six Skills are original project work; external projects in
  `docs/REFERENCE_PROJECTS.md` are design references only. Development-only `pytest` is
  not redistributed.
- **Validation:** Windows 11 + Python 3.14.7; wheel build and install verified; the
  in-tree test suite is deterministic and offline; Manager MCP surface = 18 tools.
  Cross-machine installation is **pending community testing**.
- **Scope note:** synthetic acceptance runs validate the delivery pipeline, not general
  real-competition solving capability. Tier-2 isolation, real targets and challenge-code
  execution are out of scope for this Beta.

## What is inside

- `ctf_solver/` — product package (Manager, ACP client, MCP servers, evidence, delivery,
  policy/broker, runtime, preflight, CLI).
- `.dsh/skills/` — the six project Skills (core + web/misc/crypto/reverse/pwn).
- `tests/` — deterministic offline tests and synthetic fixtures.
- `tooling/wheelbuild.py` — in-tree, stdlib-only PEP 517 wheel backend.
- `scripts/` — `setup_windows.ps1`, `deploy_skills.py`, `gen_mcp_config.py`, plus release
  verification helpers.
- `INSTALL.md`, `QUICKSTART.md`, `TROUBLESHOOTING.md`, `KNOWN_ISSUES.md` — user docs.

## Quick checks

```powershell
python -m ctf_solver version
python -m ctf_solver skills --root .
python -m pytest tests -q -p no:cacheprovider
python scripts/build_wheel.py --out dist
```

Installation, Harness integration and the project-scoped Manager MCP configuration are
described in `INSTALL.md` and `QUICKSTART.md`.

## Verification status

| Check | Result |
|---|---|
| Python package install (source + wheel, offline) | PASS on the acceptance machine |
| Six Skills deploy + `ctf_solver skills` validation | PASS |
| Project-scoped MCP config generation | PASS (fixture path) |
| Manager MCP tool surface | 18 tools |
| Database / workspace isolation | PASS (fresh isolated root) |
| Offline regression suite | PASS on the acceptance machine |
| Second machine / other Python / other Harness build | **PENDING COMMUNITY TEST** |
