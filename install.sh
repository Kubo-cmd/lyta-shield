#!/usr/bin/env bash
set -euo pipefail

# LYTA Shield installer. Run from an extracted release or repository checkout.

CONFIG_DIR="${HOME}/.config/lyta-shield"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REMOTE_BASE="${LYTA_SHIELD_REPO_URL:-}"

echo "[LYTA Shield] Installing to $CONFIG_DIR..."
mkdir -p "$CONFIG_DIR"

install_file() {
    local relative="$1"
    local destination="$CONFIG_DIR/$(basename "$relative")"
    if [[ -f "$SCRIPT_DIR/$relative" ]]; then
        cp "$SCRIPT_DIR/$relative" "$destination"
    elif [[ -n "$REMOTE_BASE" ]]; then
        curl -fsSL "${REMOTE_BASE%/}/$relative" -o "$destination"
    else
        echo "[LYTA Shield] Missing $relative. Run from an extracted release or set LYTA_SHIELD_REPO_URL." >&2
        exit 1
    fi
}

for file in src/rules.json src/rules_engine.py src/lyta_shield.py src/lyta_shield_hook.sh; do
    install_file "$file"
done

chmod +x "$CONFIG_DIR/lyta_shield.py"

hook_line=". \"$CONFIG_DIR/lyta_shield_hook.sh\""

append_if_missing() {
    local file="$1"
    if [[ -f "$file" ]] && ! grep -F "$hook_line" "$file" >/dev/null 2>&1; then
        printf '\n# LYTA Shield\n%s\n' "$hook_line" >> "$file"
        echo "[LYTA Shield] Hook added to $file"
    fi
}

append_if_missing "${HOME}/.zshrc"
append_if_missing "${HOME}/.bashrc"

echo "[LYTA Shield] Terminal guard installed."
echo "[LYTA Shield] Start a new shell to activate."
echo "[LYTA Shield] Browser guard: extensions/browser/lyta_shield_console_guard.user.js"
echo "[LYTA Shield] Bypass: LYTA_SHIELD_DISABLE=1 <command>"
