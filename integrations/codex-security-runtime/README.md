# Optional Codex Security runtime

This directory pins the official `@openai/codex-security` package and every transitive npm artifact used by the LYTA Shield preflight bridge.

Install locally:

```bash
npm ci --ignore-scripts --no-audit --no-fund
```

Security properties:

- exact package version and npm integrity values are committed in `package-lock.json`;
- npm lifecycle scripts are disabled during installation;
- `node_modules/` is local and untracked;
- the bridge verifies the reviewed CLI SHA-256 before every invocation;
- only the upstream network-free `scan --dry-run` path is exposed;
- no authentication or paid scan is started by installation.

After any intentional package upgrade, review the upstream diff, regenerate the lockfile, audit dependencies, verify `info --json`, update the package/plugin/commit/integrity/CLI digest pins in `../codex_security_bridge.py`, and rerun the full regression suite.
