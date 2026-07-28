// ==UserScript==
// @name         LYTA Shield - Browser Console Guard
// @namespace    https://github.com/Kubo-cmd/lyta-shield
// @version      1.0.0
// @description  Intercepts dangerous paste in browser console and AI chat inputs
// @author       Kubo-cmd / LYTA.EXE
// @match        *://*/*
// @grant        none
// @run-at       document-start
// ==/UserScript==

(function() {
    'use strict';

    // === LOCAL RULES ENGINE (mirror of Python patterns) ===
    const BLOCKED_PATTERNS = [
        [/(echo\s+['"]?[A-Za-z0-9+/=\s]{40,}['"]?\s*\|\s*base64\s+-d\s*\|\s*(ba)?sh)\b/i, "base64_decode_to_shell"],
        [/(base64\s+-d\s*.*?\|\s*(ba)?sh)\b/i, "base64_decode_to_shell"],
        [/(python[23]?(?:\s+-c)?\s*['"].*?(?:base64|exec|eval|__import__)\s*.*?['"])/i, "python_obfuscated_exec"],
        [/\b(curl|wget|fetch)\b.*?\|\s*(ba)?sh\b/i, "remote_fetch_to_shell"],
        [/\b(curl|wget|fetch)\b.*?\s+>\s+\/tmp\/\w+\s*&&\s*chmod\s*\+x\s+\/tmp\/\w+\s*(?:&&|;|\|\|)\s*\S*\/tmp\/\w+/i, "remote_fetch_chmod_execute"],
        [/\b(eval\s*\(|\beval\s*\(|\beval\s+['"])/i, "browser_eval"],
        [/\b(fetch\s*\(\s*['"]https?:\/\/|XMLHttpRequest\s*\(|navigator\.sendBeacon\s*\(\s*['"]https?:\/\/)/i, "browser_remote_fetch"],
        [/\b(document\.write\s*\(|document\.body\.innerHTML\s*=)/i, "browser_dom_injection"],
        [/\b(localStorage\s*\[\s*['"]apiKey|sessionStorage\s*\[\s*['"]apiKey|process\.env\s*\.\s*\w*[kK]ey\w*)/i, "credential_exfil"],
        [/\b(prompt\s*\(\s*['"]Please\s+enter\s+your\s+(?:password|token|key|secret)|confirm\s*\(\s*['"].*?(?:password|token|key|secret))/i, "browser_credential_phishing"],
        [/\b(paste\s+this\s+(?:command|code)\s+(?:into|in)\s+(?:your\s+)?(?:terminal|shell|console))\b/i, "paste_jacking_instruction"],
        [/\b(copy\s+this\s+(?:command|code|script|text)\s+(?:and\s+)?(?:paste|run|execute)\s+it)\b/i, "paste_jacking_instruction"],
        [/\b(copy\s+(?:and\s+)?paste\s+(?:this\s+)?(?:command|code|script|text))\b/i, "paste_jacking_instruction"],
        [/\b(run\s+this\s+(?:command|code)\s+in\s+(?:your\s+)?(?:terminal|shell|console))\b/i, "paste_jacking_instruction"],
    ];

    const SUSPICIOUS_PATTERNS = [
        [/\b(Function\s*\(\s*\)|new\s+Function\s*\(\s*\)|setTimeout\s*\(\s*['"].*?\)|setInterval\s*\(\s*['"].*?\))/i, "browser_dynamic_code"],
        [/\b(Worker\s*\(|SharedWorker\s*\(|importScripts\s*\(\s*['"]https?:\/\/)/i, "browser_worker_remote"],
        [/\b(paste\s+(?:this\s+)?(?:code|command|text))\b/i, "paste_instruction_weak"],
        [/\b(copy\s+(?:the\s+following\s+)?(?:code|command|script))\b/i, "copy_instruction_weak"],
    ];

    function check(text) {
        if (!text || typeof text !== 'string') return { action: 'SAFE', code: 0, reasons: [], matched: null };
        const normalized = text.replace(/[\u200b\u200c\u200d\u200e\u200f\u202a-\u202e\u2060\u2066-\u2069\ufeff]/g, '').replace(/\s+/g, ' ').trim();
        if (!normalized) return { action: 'SAFE', code: 0, reasons: [], matched: null };

        for (const [pat, reason] of BLOCKED_PATTERNS) {
            const m = normalized.match(pat);
            if (m) {
                return { action: 'DANGEROUS', code: 2, reasons: [reason], matched: m[0] };
            }
        }

        const reasons = [];
        for (const [pat, reason] of SUSPICIOUS_PATTERNS) {
            if (normalized.match(pat)) reasons.push(reason);
        }
        if (reasons.length) {
            return { action: 'SUSPICIOUS', code: 1, reasons, matched: null };
        }
        return { action: 'SAFE', code: 0, reasons: [], matched: null };
    }

    function showWarning(target, verdict) {
        const color = verdict.code === 2 ? '#ff4444' : '#ffaa00';
        const title = verdict.code === 2 ? 'LYTA Shield: BLOCKED' : 'LYTA Shield: WARNING';
        const msg = verdict.code === 2
            ? 'This code is dangerous. LYTA Shield blocked the paste.'
            : 'This code is suspicious. Review before running.';
        const reasons = verdict.reasons.map(r => `• ${r}`).join('\n');

        const div = document.createElement('div');
        div.style.cssText = `
            position:fixed; top:20px; left:50%; transform:translateX(-50%);
            z-index:2147483647; background:#000; color:#fff;
            border:2px solid ${color}; border-radius:12px;
            padding:16px 20px; max-width:500px; font-family:system-ui,sans-serif;
            font-size:14px; line-height:1.5; box-shadow:0 10px 40px rgba(0,0,0,0.8);
        `;
        div.innerHTML = `
            <div style="font-weight:bold; color:${color}; font-size:16px; margin-bottom:8px;">${title}</div>
            <div style="margin-bottom:8px;">${msg}</div>
            <pre style="background:#111; padding:8px; border-radius:6px; overflow:auto; max-height:120px; margin:8px 0;">${target.value.slice(0,200)}</pre>
            <div style="color:#aaa; margin-bottom:12px;">${reasons}</div>
            <div style="text-align:right;">
                <button id="lyta-shield-dismiss" style="background:#333; color:#fff; border:1px solid #555; padding:6px 12px; border-radius:6px; cursor:pointer;">Dismiss</button>
            </div>
        `;
        document.body.appendChild(div);
        document.getElementById('lyta-shield-dismiss').onclick = () => div.remove();
    }

    // === AI CHAT INPUT GUARD ===
    const AI_CHAT_SELECTORS = [
        'textarea[placeholder*="Message"], textarea[placeholder*="message"]',
        'textarea[placeholder*="Ask"], textarea[placeholder*="ask"]',
        'textarea[placeholder*="Chat"], textarea[placeholder*="chat"]',
        'div[contenteditable="true"][role="textbox"]',
        '[data-testid="chat-input"]',
        'textarea',
        'div[contenteditable="true"]',
    ];

    function guardInput(event) {
        const target = event.target;
        if (!target) return;
        const text = target.value || target.innerText || '';
        const verdict = check(text);
        if (verdict.code !== 0) {
            event.preventDefault();
            event.stopPropagation();
            showWarning(target, verdict);
            return false;
        }
    }

    function attachInputGuards() {
        document.querySelectorAll(AI_CHAT_SELECTORS.join(', ')).forEach(el => {
            if (el.dataset.lytaShieldGuarded) return;
            el.dataset.lytaShieldGuarded = 'true';
            el.addEventListener('paste', guardInput, true);
            el.addEventListener('keydown', (e) => {
                if (e.key === 'Enter' && !e.shiftKey) {
                    const text = e.target.value || e.target.innerText || '';
                    const verdict = check(text);
                    if (verdict.code !== 0) {
                        e.preventDefault();
                        e.stopPropagation();
                        showWarning(e.target, verdict);
                    }
                }
            }, true);
        });
    }

    // === BROWSER CONSOLE GUARD ===
    const originalConsoleLog = console.log;
    const warningShown = new Set();

    function guardConsolePaste() {
        // We cannot intercept DevTools directly, but we can warn via a visible banner
        // when a dangerous script tag is injected or when the page itself tries to eval.
        const originalEval = window.eval;
        window.eval = function(code) {
            const verdict = check(code);
            if (verdict.code === 2) {
                if (!warningShown.has(code)) {
                    warningShown.add(code);
                    showWarning({ value: code }, verdict);
                    originalConsoleLog.call(console, '[LYTA Shield] BLOCKED eval:', code);
                }
                throw new Error('LYTA Shield blocked dangerous eval()');
            }
            return originalEval(code);
        };
    }

    // === INIT ===
    setInterval(attachInputGuards, 1000);
    attachInputGuards();
    guardConsolePaste();

    console.log('[LYTA Shield] Browser guard active');
})();
