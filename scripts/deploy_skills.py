#!/usr/bin/env python3
"""Deploy the six CTF-Solver Skills into a DeepSeek Harness project workspace.

Harness discovers project Skills from ``<project root>/.dsh/skills/<name>/SKILL.md``.
This helper copies only the six known Skill directories, preserves any same-name Skill
with a timestamped backup, and leaves the rest of ``.dsh`` untouched.

It performs no network access and does not touch global Harness configuration.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import shutil
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SKILL_NAMES = ("ctf-solver", "ctf-web", "ctf-misc", "ctf-crypto", "ctf-reverse", "ctf-pwn")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Copy the six CTF-Solver Skills into <workspace>/.dsh/skills."
    )
    parser.add_argument(
        "--workspace",
        default=str(REPO_ROOT),
        help="Harness project workspace that should receive the Skills.",
    )
    parser.add_argument(
        "--source",
        default=str(REPO_ROOT / ".dsh" / "skills"),
        help="Source Skills directory (default: this repository's .dsh/skills).",
    )
    parser.add_argument("--dry-run", action="store_true", help="Report actions only.")
    args = parser.parse_args(argv)

    workspace = Path(args.workspace).expanduser().resolve()
    source = Path(args.source).expanduser().resolve()
    if not workspace.is_dir():
        print(f"error: workspace does not exist: {workspace}", file=sys.stderr)
        return 2
    if not source.is_dir():
        print(f"error: source Skills directory not found: {source}", file=sys.stderr)
        return 2

    missing = [name for name in SKILL_NAMES if not (source / name / "SKILL.md").is_file()]
    if missing:
        print(f"error: source is missing Skill files: {', '.join(missing)}", file=sys.stderr)
        return 2

    target_root = workspace / ".dsh" / "skills"
    stamp = _dt.datetime.now().strftime("%Y%m%d%H%M%S")
    actions: list[str] = []
    for name in SKILL_NAMES:
        src = source / name
        dst = target_root / name
        if dst.exists():
            backup = dst.with_name(f"{name}.backup-{stamp}")
            actions.append(f"backup {dst} -> {backup}")
            if not args.dry_run:
                shutil.copytree(dst, backup)
                shutil.rmtree(dst)
        actions.append(f"copy {src} -> {dst}")
        if not args.dry_run:
            target_root.mkdir(parents=True, exist_ok=True)
            shutil.copytree(src, dst)

    for action in actions:
        print(action)
    if args.dry_run:
        print("dry-run: no files changed")
        return 0

    missing_target = [n for n in SKILL_NAMES if not (target_root / n / "SKILL.md").is_file()]
    if missing_target:
        print(f"error: Skills missing after copy: {', '.join(missing_target)}", file=sys.stderr)
        return 1
    print(f"deployed 6 Skills to {target_root}")
    print(f"verify with: python -m ctf_solver skills --root \"{workspace}\"")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
