#!/usr/bin/env bash
set -euo pipefail

# LYTA Shield installer. Run from an extracted release or repository checkout.

CONFIG_DIR="${HOME}/.config/lyta-shield"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo "[LYTA Shield] Installing to $CONFIG_DIR..."
mkdir -p "$CONFIG_DIR"
STAGE_DIR="$(mktemp -d "$CONFIG_DIR/.install.XXXXXX")"
trap 'rm -rf "$STAGE_DIR"' EXIT

install_file() {
    local relative="$1"
    local source="$SCRIPT_DIR/$relative"
    local destination="$STAGE_DIR/$(basename "$relative")"
    if [[ ! -f "$source" || -L "$source" ]]; then
        echo "[LYTA Shield] Missing or unsafe $relative. Run from a verified release archive or repository checkout." >&2
        exit 1
    fi
    cp "$source" "$destination"
}

for file in src/rules.json src/rules_engine.py src/lyta_shield.py src/lyta_shield_hook.sh; do
    install_file "$file"
done

chmod +x "$STAGE_DIR/lyta_shield.py"
for staged in "$STAGE_DIR"/*; do
    mv -f "$staged" "$CONFIG_DIR/$(basename "$staged")"
done

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
