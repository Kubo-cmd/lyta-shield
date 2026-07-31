#!/usr/bin/env bash
# LYTA Shield Hermes wrapper — intercepts output and runs it through the guard.
# Usage: alias hermes="hermes-wrapper.sh"
# Or:    hermes-wrapper.sh <your normal hermes command and args>

set -euo pipefail

LYTA_DIR="${LYTA_DIR:-$(cd "$(dirname "$0")/.." && pwd)}"
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

# Always run the guard before showing anything, including failed command output.
set +e
GUARD_JSON=$(python3 "$GUARD" --file "$OUT" 2>/dev/null)
GUARD_RC=$?
set -e

# Parse and validate the complete guard protocol once. Any inconsistent field
# or exit status is converted to a fail-closed DANGEROUS result.
PARSED=$(printf '%s' "$GUARD_JSON" | python3 -c 'import json,sys
try:
 d=json.load(sys.stdin)
 required={"allowed","verdict","code","reasons","matched","warning"}
 assert isinstance(d,dict) and set(d)==required
 assert type(d["allowed"]) is bool
 assert type(d["code"]) is int and d["code"] in (0,1,2)
 assert isinstance(d["verdict"],str) and d["verdict"] in ("SAFE","SUSPICIOUS","DANGEROUS")
 assert isinstance(d["reasons"],list) and all(isinstance(x,str) for x in d["reasons"])
 assert d["matched"] is None or isinstance(d["matched"],str)
 assert isinstance(d["warning"],str)
 rc=int(sys.argv[1])
 expected={"SAFE":(True,0,0),"SUSPICIOUS":(False,1,2),"DANGEROUS":(False,2,2)}
 assert (d["allowed"],d["code"],rc)==expected[d["verdict"]]
 print(d["verdict"])
 print(json.dumps(d["reasons"]))
except Exception:
 print("DANGEROUS")
 print("[\"guard_protocol_error\"]")
 raise SystemExit(2)' "$GUARD_RC" 2>/dev/null) || GUARD_RC=2
VERDICT=$(printf '%s\n' "$PARSED" | python3 -c 'import sys; print(sys.stdin.readline().strip() or "DANGEROUS")')
REASONS=$(printf '%s\n' "$PARSED" | python3 -c 'import sys; sys.stdin.readline(); print(sys.stdin.readline().strip() or "[\"guard_protocol_error\"]")')

# Append telemetry event.
python3 - "$EVENT_LOG" "$RC" "$GUARD_RC" "$VERDICT" "$REASONS" "${1:-unknown}" "$#" <<'PY'
import datetime, json, os, sys
log, rc, guard_rc, verdict, reasons, executable, argc = (
    sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4],
    sys.argv[5], os.path.basename(sys.argv[6]), int(sys.argv[7]),
)
try:
    reasons = json.loads(reasons)
except (TypeError, json.JSONDecodeError):
    reasons = ["guard_protocol_error"]
event = {
    "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "command": executable,
    "argument_count": max(argc - 1, 0),
    "wrapped_exit": rc,
    "guard_exit": guard_rc,
    "verdict": verdict,
    "reasons": reasons,
}
import stat
os.makedirs(os.path.dirname(log), exist_ok=True)
flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
if hasattr(os, "O_NOFOLLOW"):
    flags |= os.O_NOFOLLOW
try:
    descriptor = os.open(log, flags, 0o600)
except OSError as error:
    raise SystemExit(f"unsafe telemetry log: {error}") from error
info = os.fstat(descriptor)
if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
    os.close(descriptor)
    raise SystemExit("unsafe telemetry log: expected singly-linked owner-controlled regular file")
if info.st_size >= 1024 * 1024:
    os.close(descriptor)
    rotated = log + ".1"
    if os.path.lexists(rotated):
        rotated_info = os.lstat(rotated)
        if stat.S_ISLNK(rotated_info.st_mode) or not stat.S_ISREG(rotated_info.st_mode):
            raise SystemExit("unsafe rotated telemetry path")
        os.remove(rotated)
    if os.path.islink(log):
        raise SystemExit("unsafe telemetry log symlink")
    os.replace(log, rotated)
    descriptor = os.open(log, flags, 0o600)
with os.fdopen(descriptor, "a", encoding="utf-8") as handle:
    os.fchmod(handle.fileno(), 0o600)
    handle.write(json.dumps(event, separators=(",", ":")) + "\n")
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

if [[ $GUARD_RC -ne 0 || "$VERDICT" == "DANGEROUS" ]]; then
    echo "" >&2
    echo "⚠️  LYTA Shield blocked guarded output." >&2
    printf '%s' "$REASONS" | python3 -c 'import json,sys
try: reasons=json.load(sys.stdin)
except Exception: reasons=["guard_protocol_error"]
print("   Reasons: " + (", ".join(str(item) for item in reasons) or "unspecified"))' >&2
    echo "   Original output was suppressed." >&2
    echo "" >&2
    exit 2
fi

cat "$OUT"
exit "$RC"
