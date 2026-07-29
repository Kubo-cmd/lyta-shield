#!/usr/bin/env python3
"""Commit and push the complete LYTA Shield worktree through Git.

Usage: python3 scripts/push-to-github.py <commit-message>
"""

import subprocess
import sys


def run(*command: str) -> None:
    subprocess.run(command, check=True)


def main() -> int:
    if len(sys.argv) != 2 or not sys.argv[1].strip():
        print("Usage: python3 scripts/push-to-github.py <commit-message>", file=sys.stderr)
        return 2
    run("git", "add", "-A")
    staged = subprocess.run(["git", "diff", "--cached", "--quiet"], check=False)
    if staged.returncode == 0:
        print("No changes to commit.")
        return 0
    if staged.returncode != 1:
        return staged.returncode
    run("git", "commit", "-m", sys.argv[1])
    run("git", "push", "origin", "HEAD")
    print("Committed and pushed through the configured origin.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
