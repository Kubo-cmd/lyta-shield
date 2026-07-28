# LYTA Shield Browser Extension

This is a userscript that guards two common browser attack surfaces:

1. **AI chat inputs** — warns when you paste or submit dangerous commands into Claude, ChatGPT, Gemini, etc.
2. **Browser console** — blocks `eval()` of dangerous code and shows a warning.

## Install

1. Install [Tampermonkey](https://www.tampermonkey.net/) (Chrome, Firefox, Safari, Edge).
2. Click the `lyta_shield_console_guard.user.js` file in this repo.
3. Click "Raw" — Tampermonkey will auto-detect and prompt you to install.

## What it catches

- Pasting `eval(...)` payloads
- `fetch()` to remote URLs from pasted code
- `document.write` / `innerHTML` injection
- `localStorage` / `sessionStorage` / `process.env` key theft
- Paste-jacking instructions ("copy this into terminal")
- Base64-to-shell payloads

## Limitations

- Cannot directly intercept the browser DevTools console itself (browser security prevents this). It guards the page's `eval()` and chat inputs.
- AI chat sites change their DOM often. If the selector breaks, open an issue.

## Bypass

- Disable Tampermonkey for that site.
- Use LYTA Shield terminal guard for anything that reaches your shell.
