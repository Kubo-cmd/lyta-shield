#!/usr/bin/env bash
# Configure a repository-scoped SSH deploy key without embedding an account name.

set -euo pipefail

KEY="$HOME/.ssh/id_lyta_shield"
PUB="$KEY.pub"
SSH_CONFIG="$HOME/.ssh/config"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

if [[ ! -f "$KEY" ]]; then
    echo "Generating deploy key at $KEY"
    ssh-keygen -t ed25519 -C "lyta-shield@local" -f "$KEY" -N "" -q
fi

echo "Add this public key as a write-enabled Deploy key in the repository Settings."
printf '\n'
cat "$PUB"
printf '\n'

mkdir -p "$(dirname "$SSH_CONFIG")"
chmod 700 "$(dirname "$SSH_CONFIG")"
if ! grep -q "Host github.com-lyta-shield" "$SSH_CONFIG" 2>/dev/null; then
    cat >> "$SSH_CONFIG" <<EOF

# LYTA Shield deploy key
Host github.com-lyta-shield
    HostName github.com
    User git
    IdentityFile $KEY
    IdentitiesOnly yes
EOF
    chmod 600 "$SSH_CONFIG"
    echo "Updated SSH configuration."
fi

cd "$REPO_ROOT"
remote_url="$(git remote get-url origin)"
case "$remote_url" in
    https://github.com/*) repo_path="${remote_url#https://github.com/}" ;;
    git@github.com:*) repo_path="${remote_url#git@github.com:}" ;;
    git@github.com-lyta-shield:*) repo_path="${remote_url#git@github.com-lyta-shield:}" ;;
    *) echo "Unsupported origin URL; expected a GitHub repository." >&2; exit 1 ;;
esac
git remote set-url origin "git@github.com-lyta-shield:$repo_path"
echo "Deploy-key remote configured. Run: git push origin main"
