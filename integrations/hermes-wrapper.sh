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

# Run the wrapped command; don't exit on failure so we can still inspect output.
set +e
"$@" > "$OUT" 2>&1
RC=$?
set -e

# Always run the guard before showing anything.
set +e
GUARD_JSON=$(python3 "$GUARD" --file "$OUT" 2>/dev/null)
GUARD_RC=$?
set -e

if [[ $GUARD_RC -ne 0 ]]; then
    echo ""
    echo "⚠️  LYTA Shield: this assistant output triggered a guard rule."
    echo "   Verdict:"
    echo "$GUARD_JSON" | python3 -c "import json,sys; d=json.load(sys.stdin); print('   ', d.get('verdict','?'), '-', ', '.join(d.get('reasons',[])))" || true
    echo ""
fi

cat "$OUT"
exit $RC
