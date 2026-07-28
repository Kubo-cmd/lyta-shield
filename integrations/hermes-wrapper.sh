#!/usr/bin/env bash
# LYTA Shield Hermes wrapper — intercepts output and runs it through the guard.
# Usage: alias hermes="hermes-wrapper.sh"
# Or:    hermes-wrapper.sh <your normal hermes command and args>

set -euo pipefail

LYTA_DIR="${LYTA_DIR:-/Users/test/Octra/lyta-shield}"
GUARD="${LYTA_DIR}/integrations/hermes_guard.py"

if [[ ! -f "$GUARD" ]]; then
    echo "LYTA Shield guard not found: $GUARD" >&2
    exit 1
fi

# Capture output to temp file, then run guard over it.
OUT=$(mktemp)
trap 'rm -f "$OUT"' EXIT

if "$@" > "$OUT" 2>&1; then
    RC=$?
else
    RC=$?
fi

# Always run the guard before showing anything.
if ! python3 "$GUARD" --file "$OUT" >/dev/null 2>&1; then
    echo ""
    echo "⚠️  LYTA Shield: this assistant output triggered a guard rule."
    echo "   Run the guard manually to inspect: python3 $GUARD --file $OUT"
    echo ""
    python3 "$GUARD" --file "$OUT" || true
fi

cat "$OUT"
exit $RC
