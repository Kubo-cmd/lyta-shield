#!/usr/bin/env bash
set -euo pipefail

# LYTA Shield installer
# Usage: curl -fsSL https://raw.githubusercontent.com/Kubo-cmd/lyta-shield/main/install.sh | bash

REPO_URL="https://raw.githubusercontent.com/Kubo-cmd/lyta-shield/main"
CONFIG_DIR="${HOME}/.config/lyta-shield"

echo "[LYTA Shield] Installing to $CONFIG_DIR..."
mkdir -p "$CONFIG_DIR"

for file in src/rules.json src/rules_engine.py src/lyta_shield.py src/lyta_shield_hook.sh; do
    if [[ -f "${file}" ]]; then
        cp "${file}" "$CONFIG_DIR/"
    else
        curl -fsSL "$REPO_URL/$file" -o "$CONFIG_DIR/$(basename "$file")"
    fi
done

chmod +x "$CONFIG_DIR/lyta_shield.py"

hook_line=". \"$CONFIG_DIR/lyta_shield_hook.sh\""

append_if_missing() {
    local file="$1"
    if [[ -f "$file" ]] && ! grep -F "$hook_line" "$file" >/dev/null 2>&1; then
        echo "" >> "$file"
        echo "# LYTA Shield" >> "$file"
        echo "$hook_line" >> "$file"
        echo "[LYTA Shield] Hook added to $file"
    fi
}

append_if_missing "${HOME}/.zshrc"
append_if_missing "${HOME}/.bashrc"

echo "[LYTA Shield] Terminal guard installed."
echo "[LYTA Shield] Start a new shell to activate."
echo "[LYTA Shield] Browser + AI chat guard: install the Tampermonkey userscript from"
echo "[LYTA Shield]   https://github.com/Kubo-cmd/lyta-shield/tree/main/extensions/browser"
echo "[LYTA Shield] Bypass: LYTA_SHIELD_DISABLE=1 <command>"
