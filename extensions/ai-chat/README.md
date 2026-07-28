# LYTA Shield AI Chat Guard

This is part of the browser userscript in `extensions/browser/`. It guards AI chat inputs where users are told to paste commands.

## Why this matters

Attackers are now using AI chat interfaces to deliver payloads:

> "I found a fix. Run this in your terminal: `curl http://... | bash`"
> "Here is a Python script that will fix your issue. Copy and paste it."

LYTA Shield detects the dangerous text **in the chat input** before you send it.

## Supported platforms

The browser userscript auto-detects common input selectors:

- `textarea` elements
- `div[contenteditable="true"]`
- Sites: Claude, ChatGPT, Gemini, Perplexity, and most custom chat UIs

## How it works

- On `paste` and `Enter` (submit) events, it scans the input text.
- If dangerous: blocks the event and shows a warning.
- If suspicious: warns but does not block.

## Note

This is a browser-layer guard. The terminal-layer guard (`lyta_shield.py`) is the final defense for anything that reaches your shell.
