#!/usr/bin/env python3
"""Load GitHub token for lyta-shield pushes.

Priority:
1. OP_GITHUB_TOKEN environment variable (set by 1Password CLI shell integration)
2. macOS security find-generic-password -s "lyta-shield-github-token" -w
3. gh CLI auth token
4. ~/.config/lyta-shield/github-token (not recommended; use keychain)

Returns the token on stdout and exits 0, or exits 1 with a message to stderr.
"""

import os
import subprocess
import sys
from pathlib import Path

TOKEN = os.environ.get("OP_GITHUB_TOKEN")
if TOKEN:
    print(TOKEN)
    sys.exit(0)

# macOS keychain
result = subprocess.run(
    ["security", "find-generic-password", "-s", "lyta-shield-github-token", "-w"],
    capture_output=True,
    text=True,
)
if result.returncode == 0 and result.stdout.strip():
    print(result.stdout.strip())
    sys.exit(0)

# gh CLI
result = subprocess.run(["gh", "auth", "token"], capture_output=True, text=True)
if result.returncode == 0 and result.stdout.strip():
    print(result.stdout.strip())
    sys.exit(0)

# Fallback local file
local = Path.home() / ".config" / "lyta-shield" / "github-token"
if local.exists():
    print(local.read_text().strip())
    sys.exit(0)

print("GitHub token not found. Options:", file=sys.stderr)
print("  1. 1Password: export OP_GITHUB_TOKEN=$(op read 'op://Private/lyta-shield-github-token/token')", file=sys.stderr)
print("  2. macOS keychain: security add-generic-password -s 'lyta-shield-github-token' -a 'lyta-shield' -w '<TOKEN>'", file=sys.stderr)
print("  3. gh CLI: gh auth login", file=sys.stderr)
sys.exit(1)
