#!/usr/bin/env bash
# LYTA Shield Hermes wrapper — intercepts output and runs it through the guard.
# Usage: alias hermes="hermes-wrapper.sh"
# Or:    hermes-wrapper.sh <your normal hermes command and args>

set -euo pipefail

LYTA_DIR="${LYTA_DIR:-/Users/test/Octra/lyta-shield}"
GUARD="${LYTA_DIR}/integrations/hermes_guard.py"
EVENT_LOG="${LYTA_EVENT_LOG:-${LYTA_DIR}/var/hermes-guard-events.jsonl}"
CIRCUIT_MARKER="${LYTA_DIR}/var/circuit-breaker-open"

mkdir -p "$(dirname "$EVENT_LOG")"

if [[ ! -f "$GUARD" ]]; then
    echo "LYTA Shield guard not found: $GUARD" >&2
    exit 1
fi

# Circuit breaker: if this is a chat command and 3+ DANGEROUS events occurred in the last 10 minutes, block.
IS_CHAT=0
for arg in "$@"; do
    if [[ "$arg" == "chat" ]]; then
        IS_CHAT=1
        break
    fi
done

if [[ "$IS_CHAT" -eq 1 && -f "$CIRCUIT_MARKER" ]]; then
    echo "🛑 LYTA Shield: CIRCUIT BREAKER is open. Hermes chat is blocked." >&2
    echo "   Run 'lyta-shield reset' to clear the breaker after reviewing the guard log." >&2
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

# Extract verdict and reasons for the event log.
VERDICT="SAFE"
REASONS="[]"
if [[ -n "$GUARD_JSON" ]]; then
    VERDICT=$(printf '%s' "$GUARD_JSON" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('verdict','SAFE'))" 2>/dev/null || echo "SAFE")
    REASONS=$(printf '%s' "$GUARD_JSON" | python3 -c "import json,sys; d=json.load(sys.stdin); print(json.dumps(d.get('reasons',[])))" 2>/dev/null || echo "[]")
fi

# Append telemetry event.
python3 - "$EVENT_LOG" "$RC" "$GUARD_RC" "$VERDICT" "$REASONS" "$*" <<'PY'
import json, sys, datetime, os
log, rc, guard_rc, verdict, reasons, cmd = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4], sys.argv[5], sys.argv[6]
try:
    reasons = json.loads(reasons)
except:
    reasons = []
host = os.environ.get("HOSTNAME", os.environ.get("COMPUTERNAME", "unknown"))
event = {
    "ts": datetime.datetime.utcnow().isoformat() + "Z",
    "host": host,
    "command": cmd,
    "wrapped_exit": rc,
    "guard_exit": guard_rc,
    "verdict": verdict,
    "reasons": reasons,
}
with open(log, "a") as f:
    f.write(json.dumps(event, separators=(",", ":")) + "\n")
PY

# Open circuit breaker if this was a chat with DANGEROUS verdict and threshold is met.
if [[ "$IS_CHAT" -eq 1 && "$VERDICT" == "DANGEROUS" ]]; then
    set +e
    DANGEROUS_COUNT=$(python3 - "$EVENT_LOG" <<'PYCB'
import json, sys, datetime, os
log = sys.argv[1]
cutoff = datetime.datetime.utcnow() - datetime.timedelta(minutes=10)
count = 0
if os.path.exists(log):
    with open(log) as f:
        for line in f:
            try:
                e = json.loads(line)
                if e.get("verdict") != "DANGEROUS":
                    continue
                ts = e.get("ts", "")
                if ts.endswith("Z"):
                    ts = ts[:-1]
                t = datetime.datetime.fromisoformat(ts)
                if t >= cutoff:
                    count += 1
            except Exception:
                pass
print(count)
PYCB
    )
    set -e
    if [[ "$DANGEROUS_COUNT" -ge 3 ]]; then
        touch "$CIRCUIT_MARKER"
        echo "" >&2
        echo "🛑 LYTA Shield: CIRCUIT BREAKER OPENED." >&2
        echo "   3 DANGEROUS chat verdicts in the last 10 minutes." >&2
        echo "   Hermes chat is now blocked until you run 'lyta-shield reset'." >&2
        echo "" >&2
    fi
fi

if [[ $GUARD_RC -ne 0 ]]; then
    echo ""
    echo "⚠️  LYTA Shield: this assistant output triggered a guard rule."
    echo "   Verdict:"
    echo "$GUARD_JSON" | python3 -c "import json,sys; d=json.load(sys.stdin); print('   ', d.get('verdict','?'), '-', ', '.join(d.get('reasons',[])))" || true
    echo ""
fi

cat "$OUT"
exit $RC
