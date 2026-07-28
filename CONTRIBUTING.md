# Contributing to LYTA Shield

## Adding or tuning rules

1. Add a test case to `tests/test_rules.py` or `tests/test_adversarial_bypass.py`.
2. Run the full test suite: `python3 -m pytest tests/`
3. If a rule needs adjustment, edit `src/rules.json` and run the tests again.
4. Refresh the integrity baseline: `./bin/lyta-shield restore-baseline`
5. Commit, push, and ensure CI is green.

## Running locally

```bash
python3 -m pytest tests/          # all tests
./bin/lyta-shield-doctor           # health check
./bin/lyta-shield backup           # signed backup
./bin/lyta-shield verify-backup    # verify latest backup
```

## Security

Report sensitive security issues privately. Do not open public issues for active bypasses that could be weaponized.
