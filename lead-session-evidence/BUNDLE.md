# Draft PR bundle

The Draft PR branch is delivered as a git bundle at
`D:\CTF-SOLVER\dist\CTF-Solver-Lead-Session-Evidence.bundle` (outside Git).

- `git bundle verify` exit 0 and `git bundle clone` of
  `feat/lead-session-evidence` were checked (clean checkout; focused Lead/delivery/skills
  tests green) — see `raw/bundle-clone*.txt` and `raw/bundle-artifact.txt`.
- The bundle cannot contain its own hash: the SHA-256 of the final delivery bundle is
  recorded in the final delivery message, not inside this commit.
