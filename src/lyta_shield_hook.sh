#!/usr/bin/env bash
# LYTA Shield shell hook
# Source this from ~/.zshrc or ~/.bashrc to intercept risky terminal commands.
#
# Install:
#   echo '. "$HOME/.config/lyta-shield/lyta_shield_hook.sh"' >> ~/.zshrc
#   echo '. "$HOME/.config/lyta-shield/lyta_shield_hook.sh"' >> ~/.bashrc


LYTA_SHIELD_BIN="${LYTA_SHIELD_BIN:-$HOME/.config/lyta-shield/lyta_shield.py}"
LYTA_SHIELD_RULES="${LYTA_SHIELD_RULES:-$HOME/.config/lyta-shield/rules.json}"

if [[ -n "$ZSH_VERSION" ]]; then
    lyta_shield() {
        [[ -o interactive ]] || return 0
        local cmd="$1"
        [[ -z "$cmd" ]] && return 0
        if [[ ! -f "$LYTA_SHIELD_BIN" || -L "$LYTA_SHIELD_BIN" ]]; then
            echo "[LYTA Shield] Guard unavailable or unsafe; command cancelled." >&2
            kill -INT $$
            return 1
        fi
        local result
        result=$(LYTA_SHIELD_RULES="$LYTA_SHIELD_RULES" python3 "$LYTA_SHIELD_BIN" --check "$cmd" 2>&1)
        local code=$?
        if [[ $code -eq 2 ]]; then
            echo ""
            echo "\033[1;31m[LYTA Shield] BLOCKED: dangerous command detected.\033[0m"
            echo "$result" | sed 's/^/  /'
            echo "\033[1;33mReview the command and rules before retrying.\033[0m"
            echo ""
            kill -INT $$
            return 1
        elif [[ $code -eq 1 ]]; then
            echo ""
            echo "\033[1;33m[LYTA Shield] WARNING: suspicious command.\033[0m"
            echo "$result" | sed 's/^/  /'
            echo ""
            printf "\033[1;33mType 'YES' to run anyway (or press Enter to cancel): \033[0m"
            local confirm
            read confirm
            if [[ "$confirm" != "YES" ]]; then
                echo "\033[1;31mCancelled.\033[0m"
                kill -INT $$
                return 1
            fi
            echo ""
        elif [[ $code -ne 0 ]]; then
            echo "[LYTA Shield] Guard failed with exit $code; command cancelled." >&2
            [[ -n "$result" ]] && echo "$result" | sed 's/^/  /' >&2
            kill -INT $$
            return 1
        fi
        return 0
    }
    preexec() { lyta_shield "$1"; }
fi

if [[ -n "$BASH_VERSION" ]]; then
    lyta_shield_bash() {
        local cmd="$BASH_COMMAND"
        [[ -z "$cmd" ]] && return 0
        if [[ ! -f "$LYTA_SHIELD_BIN" || -L "$LYTA_SHIELD_BIN" ]]; then
            echo "[LYTA Shield] Guard unavailable or unsafe; command cancelled." >&2
            kill -INT $$
            return 1
        fi
        local result
        result=$(LYTA_SHIELD_RULES="$LYTA_SHIELD_RULES" python3 "$LYTA_SHIELD_BIN" --check "$cmd" 2>&1)
        local code=$?
        if [[ $code -eq 2 ]]; then
            echo ""
            echo -e "\033[1;31m[LYTA Shield] BLOCKED: dangerous command detected.\033[0m"
            echo "$result" | sed 's/^/  /'
            echo -e "\033[1;33mReview the command and rules before retrying.\033[0m"
            echo ""
            kill -INT $$
        elif [[ $code -eq 1 ]]; then
            echo ""
            echo -e "\033[1;33m[LYTA Shield] WARNING: suspicious command.\033[0m"
            echo "$result" | sed 's/^/  /'
            echo ""
            read -p "Type 'YES' to run anyway (or press Enter to cancel): " confirm
            if [[ "$confirm" != "YES" ]]; then
                echo -e "\033[1;31mCancelled.\033[0m"
                kill -INT $$
            fi
            echo ""
        elif [[ $code -ne 0 ]]; then
            echo "[LYTA Shield] Guard failed with exit $code; command cancelled." >&2
            [[ -n "$result" ]] && echo "$result" | sed 's/^/  /' >&2
            kill -INT $$
            return 1
        fi
    }
    trap 'lyta_shield_bash' DEBUG
fi
