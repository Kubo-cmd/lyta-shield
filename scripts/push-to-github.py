#!/usr/bin/env python3
"""Push lyta-shield changes to GitHub using token from keychain loader.

Usage: python3 scripts/push-to-github.py <commit-message>
"""

import base64
import json
import subprocess
import sys
from pathlib import Path

OWNER = "Kubo-cmd"
REPO = "lyta-shield"


def load_token():
    loader = Path(__file__).parent / "load-github-token.py"
    result = subprocess.run([str(loader)], capture_output=True, text=True)
    if result.returncode != 0:
        print(result.stderr, file=sys.stderr)
        sys.exit(1)
    return result.stdout.strip()


def latest_commit(token):
    import urllib.request
    req = urllib.request.Request(
        f"https://api.github.com/repos/{OWNER}/{REPO}/git/refs/heads/main",
        headers={
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        data = json.loads(r.read())
        return data["object"]["sha"]


def commit_tree(token, base_commit, message, files):
    import urllib.request

    base_tree = urllib.request.urlopen(
        urllib.request.Request(
            f"https://api.github.com/repos/{OWNER}/{REPO}/git/commits/{base_commit}",
            headers={
                "Authorization": f"token {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        ),
        timeout=30,
    ).read()
    base_tree = json.loads(base_tree)["tree"]["sha"]

    tree_items = []
    for path, content in files.items():
        blob = urllib.request.urlopen(
            urllib.request.Request(
                f"https://api.github.com/repos/{OWNER}/{REPO}/git/blobs",
                data=json.dumps({
                    "content": base64.b64encode(content).decode(),
                    "encoding": "base64",
                }).encode(),
                headers={
                    "Authorization": f"token {token}",
                    "Accept": "application/vnd.github+json",
                    "Content-Type": "application/json",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
            ),
            timeout=30,
        ).read()
        blob = json.loads(blob)
        mode = "100755" if path in ("bin/lyta-shield", "scripts/load-github-token.py", "scripts/push-to-github.py") else "100644"
        tree_items.append({"path": path, "mode": mode, "type": "blob", "sha": blob["sha"]})

    tree = urllib.request.urlopen(
        urllib.request.Request(
            f"https://api.github.com/repos/{OWNER}/{REPO}/git/trees",
            data=json.dumps({"base_tree": base_tree, "tree": tree_items}).encode(),
            headers={
                "Authorization": f"token {token}",
                "Accept": "application/vnd.github+json",
                "Content-Type": "application/json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        ),
        timeout=30,
    ).read()
    tree = json.loads(tree)

    commit = urllib.request.urlopen(
        urllib.request.Request(
            f"https://api.github.com/repos/{OWNER}/{REPO}/git/commits",
            data=json.dumps({"message": message, "tree": tree["sha"], "parents": [base_commit]}).encode(),
            headers={
                "Authorization": f"token {token}",
                "Accept": "application/vnd.github+json",
                "Content-Type": "application/json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        ),
        timeout=30,
    ).read()
    commit = json.loads(commit)

    urllib.request.urlopen(
        urllib.request.Request(
            f"https://api.github.com/repos/{OWNER}/{REPO}/git/refs/heads/main",
            data=json.dumps({"sha": commit["sha"]}).encode(),
            headers={
                "Authorization": f"token {token}",
                "Accept": "application/vnd.github+json",
                "Content-Type": "application/json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            method="PATCH",
        ),
        timeout=30,
    ).read()

    return commit["html_url"]


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 scripts/push-to-github.py <commit-message>")
        sys.exit(1)
    message = sys.argv[1]
    token = load_token()
    base = latest_commit(token)
    files = {}
    root = Path(__file__).parent.parent
    for f in ["bin/lyta-shield", "SECURITY.md", "self-audit-log.md", "scripts/load-github-token.py", "scripts/push-to-github.py", "var/integrity-baseline.json", "docs/lyta-shield-guard-active.png"]:
        p = root / f
        if p.exists():
            files[f] = p.read_bytes()
    url = commit_tree(token, base, message, files)
    print("Pushed:", url)
