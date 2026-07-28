# Security Policy

## Scope

This policy applies to the **LYTA Shield** repository, including:

- The `src/rules.json` rule engine
- The `lyta-shield.py` CLI
- The `lyta-shield.sh` / `lyta-shield.ps1` shell wrappers
- The browser userscript
- The documentation site under `docs/`

## Supported versions

Only the latest commit on `main` is supported. Users are expected to update to the latest commit after fixes land.

## Reporting a vulnerability or bypass

If you find a rule bypass, false positive, or any vulnerability in LYTA Shield itself:

1. **Email**: `security@kubo-cmd.github.io` (placeholder — update this issue or README with a real contact)
2. **Or**: open a **private GitHub Security Advisory** at https://github.com/Kubo-cmd/lyta-shield/security/advisories
3. Include:
   - A minimal payload or reproduction
   - The expected classification (SAFE, SUSPICIOUS, DANGEROUS)
   - The actual classification
   - Whether it is a bypass or a false positive

## Response timeline

- Acknowledgment: within 7 days
- Fix evaluation: within 14 days
- Public disclosure: coordinated with the reporter, default 30 days after a fix is released

## Red-team and research invitations

We actively invite independent reviewers, red-teamers, and security researchers to test LYTA Shield.

- The `tests/test_adversarial_bypass.py` file is a public challenge set. If you find a bypass, please add it as a test case and submit a PR or report it privately.
- The 1,000,000-call simulation is a synthetic fuzz regression test, not a security guarantee. Real validation comes from external review, bug bounty, and production use.

## What we do not consider in scope

- Vulnerabilities in third-party software LYTA Shield may warn about (for example, a malicious install script we flag)
- Social-engineering attacks that occur outside of the text streams LYTA Shield can inspect

## Safe harbor

We will not take legal action against anyone who reports security issues or submits bypass test cases in good faith, in line with this policy.

## Acknowledgments

We will list responsible disclosures in this section.

- *No acknowledgments yet — be the first.*
