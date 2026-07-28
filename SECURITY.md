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

We will list responsible disclosures and false-positive reports in this section.

- *No acknowledgments yet — be the first.*

### Bypass bounty

If you can make LYTA Shield output a DANGEROUS/SUSPICIOUS classification that should be SAFE, or allow a SAFE classification for a clearly malicious payload, report it:

1. Open a GitHub issue with the label `bypass` or `false-positive`.
2. Include the exact text you tested.
3. Include the command you ran: `python3 integrations/hermes_guard.py --file your-text.txt`.
4. Include the expected classification.

The first verified bypass of the Hermes output guard will receive a public acknowledgment in the README and a dedicated test case named after the reporter.

We do not pay cash bounties. Acknowledgment + a named regression test is the reward.

## False positives and false negatives

If LYTA Shield blocks something that should be safe, or misses something malicious, report it as a GitHub issue using the template below:


1. Open a [GitHub Security Advisory](https://github.com/Kubo-cmd/lyta-shield/security/advisories) or a public issue.
2. Include the exact input text and the rule IDs returned by `hermes_guard.py`.
3. Run `python3 integrations/hermes_guard.py --file your-message.txt` and paste the JSON output.
4. Explain why you think the classification is wrong.

Good reports help us tune the rules without breaking legitimate use.
