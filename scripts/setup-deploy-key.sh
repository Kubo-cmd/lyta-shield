#!/usr/bin/env bash
# Setup SSH deploy key for pushing lyta-shield to GitHub
# Run this after adding the public key below to https://github.com/Kubo-cmd/lyta-shield/settings/keys/new

set -euo pipefail

KEY="$HOME/.ssh/id_lyta_shield"
PUB="$KEY.pub"

if [[ ! -f "$KEY" ]]; then
    echo "Generating deploy key at $KEY"
    ssh-keygen -t ed25519 -C "lyta-shield@local" -f "$KEY" -N "" -q
fi

echo "Add this public key to GitHub as a Deploy key:"
echo
cat "$PUB"
echo

SSH_CONFIG="$HOME/.ssh/config"
mkdir -p "$(dirname "$SSH_CONFIG")"
if ! grep -q "Host github.com-lyta-shield" "$SSH_CONFIG" 2>/dev/null; then
    cat >> "$SSH_CONFIG" <<EOF

# LYTA Shield deploy key
Host github.com-lyta-shield
    HostName github.com
    User git
    IdentityFile $KEY
    IdentitiesOnly yes
EOF
    echo "Updated $SSH_CONFIG"
fi

cd "$(dirname "$0")/.."
git remote set-url origin git@github.com-lyta-shield:Kubo-cmd/lyta-shield.git
echo "Remote URL updated. Run: git push origin main"
