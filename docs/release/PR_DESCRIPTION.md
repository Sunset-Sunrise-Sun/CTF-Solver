# Draft PR description — Beta: CTF-Solver 0.1.1 public beta

**Base:** `main`
**Head:** `release/beta-v0.1.1`
**State:** Draft (do not merge; for review and community testing)

## Summary

This PR publishes the reviewed CTF-Solver 0.1.1 **public Beta**: a Lead-first CTF solving
extension for DeepSeek Harness. The Beta is derived from the remediation commit
`3798b2850ad2c72e3a8ae1db846dfcf92c06b638` (F1 approval-console and F2 Lead-session-scope
fixes) on top of the clean-snapshot release candidate, and adds public documentation,
installer helpers and release materials.

The product architecture and the Lead-first model are unchanged: the Lead conversation
executes with native Harness tools; the Manager owns Tasks, approvals, evidence and
deliverables; there is no second model loop.

## What this PR contains

- Clean product tree: `ctf_solver/` package, six Skills under `.dsh/skills/`, deterministic
  tests, in-tree stdlib-only wheel backend, release verification scripts.
- New public docs: `README.md`, `INSTALL.md`, `QUICKSTART.md`, `TROUBLESHOOTING.md`,
  `KNOWN_ISSUES.md`, `RELEASE_INFO.md`.
- Project-level install helpers: `scripts/setup_windows.ps1`,
  `scripts/deploy_skills.py`, `scripts/gen_mcp_config.py` (no hardcoded developer paths,
  no sandbox weakening, no third-party installs).
- Public Beta license (`LICENSE`), release notes and community-test materials under
  `docs/release/`, plus a "Beta test report" issue form.
- Removal of internal-only acceptance evidence from the public Beta tree
  (`round1-evidence/`, `round2-evidence/`, internal final-acceptance report and internal
  scripts). History on the existing branches is not rewritten.

## Why a new branch instead of reusing the old snapshot

Earlier bundles and evidence directories contained internal run artifacts and local
paths. The Beta branch is a clean public tree built from the verified remediation commit;
it does **not** reuse those bundles and does not rewrite existing branches or releases.

## Verification

Offline, deterministic checks on the acceptance machine (Windows 11, Python 3.14.7):

- `python -m pytest tests -q -p no:cacheprovider` — full deterministic suite;
- wheel build via `scripts/build_wheel.py` and offline wheel install;
- `ctf_solver skills --root <workspace>` — 6/6 Skills valid;
- project-scoped MCP config generation and Manager MCP surface = 18 tools;
- fresh isolated Manager root: SQLite/CAS/tasks created under the new root only;
- evidence chain and ZIP manifest checks.

Cross-machine installation and other Harness/Python combinations are **pending community
testing** and are not claimed.

## Known limitations highlighted for reviewers

- target-window screenshots (F3) known issue / fail-closed;
- model-mediated Workers blocked (ADR-020); no Tier-2 isolation, no real targets,
  no challenge-code execution;
- real TTY approval and same-child ACP `tools/call` not verified;
- Workspace MCP Bridge plugin required (environment prerequisite);
- proprietary Beta license — owner confirmation expected before a stable release.

## Review checklist

- [ ] `main` and the Beta tree contain no secrets, personal paths, session logs,
      databases, bundles or challenge answers/flags.
- [ ] License and third-party redistribution statements are acceptable to the owner.
- [ ] The docs describe only verifiable behaviour; BLOCKED/NOT VERIFIED items stay marked.
- [ ] Installer scripts do not require admin rights or sandbox changes.
- [ ] `.gitignore` covers runtime data (`.ctf-solver-data/`, `tasks/`, `challenge-uploads/`,
      `.dsh/mcp.servers.yml`, dist, venv).
- [ ] CI/community testers can run the offline suite and the install verification.

## Merge plan

Draft only. Do not merge `main`, do not create a formal Release, do not delete or rewrite
existing branches. Community test results are collected first; a stable release decision is
separate.
