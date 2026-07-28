// ==UserScript==
// @name         LYTA Shield - Browser Console Guard
// @namespace    https://github.com/Kubo-cmd/lyta-shield
// @version      1.1.0
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
        [/(echo\s+['"]?[A-Za-z0-9+/=\s]{40,}['"]?\s*\|\s*base64\s+(-d|--decode)\s*\|\s*(\/?bin\/)?(ba)?sh)\b/i, "base64_decode_to_shell"],
        [/(base64\s+(-d|--decode)\s*.*?\|\s*(\/?bin\/)?(ba)?sh)\b/i, "base64_decode_to_shell2"],
        [/(python[23]?(?:\s+-c)?\s*['"].*?(?:base64|exec|eval|__import__)\s*.*?['"])/i, "python_obfuscated_exec"],
        [/(perl\s+-e\s*['"].*?(?:system|exec|eval)\s*.*?['"])/i, "perl_obfuscated_exec"],
        [/(ruby\s+-e\s*['"].*?(?:exec|eval|system)\s*.*?['"])/i, "ruby_obfuscated_exec"],
        [/\bnode\s+-e\s*['"].*?(?:exec|eval)\s*.*?['"]/i, "node_obfuscated_exec"],
        [/\b(curl|wget|fetch)\b.*?\|\s*(ba)?sh\b/i, "remote_fetch_to_shell"],
        [/\b(curl|wget|fetch)\b.*?(?:\s+\|\s+(sudo\s+)?(ba)?sh|(?:bash|sh)\s+-c)/i, "remote_fetch_to_shell2"],
        [/\b(curl|wget|fetch)\b.*?\s+>\s+\/tmp\/\w+\s*&&\s*chmod\s*\+x\s+\/tmp\/\w+\s*(?:&&|;|\|\|)\s*\S*\/tmp\/\w+/i, "remote_fetch_chmod_execute"],
        [/\b(eval\s*\(|\beval\s*\(|\beval\s+['"])/i, "browser_eval"],
        [/\b(fetch\s*\(\s*['"]https?:\/\/|XMLHttpRequest\s*\(|navigator\.sendBeacon\s*\(\s*['"]https?:\/\/)/i, "browser_remote_fetch"],
        [/\b(Worker\s*\(\s*['"]https?:\/\/|SharedWorker\s*\(\s*['"]https?:\/\/|importScripts\s*\(\s*['"]https?:\/\/)/i, "browser_worker_remote"],
        [/\b(document\.write\s*\(|document\.body\.innerHTML\s*=)/i, "browser_dom_injection"],
        [/\b(localStorage\s*\[\s*['"]apiKey|sessionStorage\s*\[\s*['"]apiKey|process\.env\s*\.\s*\w*[kK]ey\w*)/i, "credential_exfil"],
        [/\b(prompt\s*\(\s*['"]Please\s+enter\s+your\s+(?:password|token|key|secret)|confirm\s*\(\s*['"].*?(?:password|token|key|secret))/i, "browser_credential_phishing"],
        [/\b(paste\s+this\s+(?:command|code)\s+(?:into|in)\s+(?:your\s+)?(?:terminal|shell|console))\b/i, "paste_jacking_instruction"],
        [/\b(copy\s+this\s+(?:command|code|script|text)\s+(?:and\s+)?(?:paste|run|execute)\s+it)\b/i, "paste_jacking_instruction"],
        [/\b(copy\s+(?:and\s+)?paste\s+(?:this\s+)?(?:command|code|script|text))\b/i, "paste_jacking_instruction"],
        [/\b(copy\s+(?:the\s+following\s+)?(?:command|code|script|text|this)\s+(?:into|in|to|inside)\s+(?:the\s+)?(?:your\s+)?(?:terminal|shell|console|command\s+line|prompt|window))\b/i, "paste_jacking_instruction"],
        [/\b(paste\s+(?:the\s+following\s+)?(?:command|code|script|text)\s+(?:into|in|to)\s+(?:the\s+)?(?:your\s+)?(?:terminal|shell|console|command\s+line|prompt|window))\b/i, "paste_jacking_instruction"],
        [/\b(run\s+this\s+(?:command|code)\s+in\s+(?:your\s+)?(?:terminal|shell|console))\b/i, "paste_jacking_instruction"],
        [/\b(website|page|link|site|popup)\s+(?:told|asked|instructed|said|says|wants|tells)\s+(?:me|you|us|him|her)\s+(?:to\s+)?(?:copy|paste|run|execute|type|put|enter)\b/i, "paste_jacking_instruction"],
        [/\b(?:copy|paste|run|execute|type|put|enter)\s+(?:this\s+)?(?:code|command|script|text|thing)?\s*(?:in|into|inside|to)\s+(?:the\s+)?(?:your\s+)?(?:terminal|shell|console|command[-\s]?line|prompt|window|box|field)\b/i, "paste_jacking_instruction"],
        [/\b(put|type|enter|paste)\s+(?:this\s+)?(?:code|command|script|text|thing)?\s*(?:in|into|inside|to)\s+(?:the\s+)?(?:your\s+)?(?:command[-\s]?line|terminal|shell|console|prompt|window)\b/i, "paste_jacking_instruction"],
        [/\b(rm\s+-rf\s+\/\s*$|rm\s+-rf\s+~\s*$|rm\s+-rf\s+\$HOME\s*$|rm\s+-rf\s+\/\w+|rm\s+-rf\s+\/\w+\/\w+|mkfs\.|>:\s*\{\}\;|fork\s+bomb)\b/i, "destructive_command"],
        [/\b(rm\s+-rf\s+\/|rm\s+-rf\s+~|rm\s+-rf\s+\$HOME)\s*$/i, "destructive_command2"],
        [/\b(dd\s+if=\/dev\/zero\s+of=\/dev\/[sh]d[a-z])\b/i, "destructive_command3"],
        [/\bnc\s+-e\s+|netcat\s+-e\s+/i, "reverse_shell"],
        [/\b\/dev\/tcp\/\d+\.\d+\.\d+\.\d+\/\d+\s+\|\s*(ba)?sh\b/i, "reverse_shell2"],
        [/(bash\s+-i\s+>&\s+\/dev\/tcp\/)/i, "reverse_shell3"],
    ];

    const SUSPICIOUS_PATTERNS = [
        [/\b(curl|wget|fetch)\b.*?\|\s*(python[23]?|perl|ruby|node)\b/i, "remote_fetch_to_interpreter"],
        [/\b(curl|wget|fetch)\b.*?\s+\|\s*(sudo\s+)?(bash|sh)\s+-s\b/i, "remote_fetch_to_shell_s"],
        [/\b(curl|wget|fetch)\b.*?\s+-o\s+\/tmp\/\w+\s*;\s*chmod\s*\+x/i, "remote_fetch_tmp_executable"],
        [/\b(pip|npm|gem|cargo)\s+install\s+[^\s]+\s*\|\s*(ba)?sh\b/i, "package_manager_pipe"],
        [/\b(echo\s+['"]?[A-Za-z0-9+/=\s]{12,}['"]?\s*\|\s*base64\s+(-d|--decode))\b/i, "base64_decode_without_shell"],
        [/\b(?:openssl|gpg)\s+enc\b.*?\|\s*(ba)?sh\b/i, "encrypted_payload_to_shell"],
        [/\b(eval\s*\(|\beval\s+['"]\$|\bexec\s+\$\(curl)/i, "eval_dynamic_exec"],
        [/\b(Function\s*\(\s*\)|new\s+Function\s*\(\s*['"].*?\)|setTimeout\s*\(\s*['"].*?\)|setInterval\s*\(\s*['"].*?\))/i, "browser_dynamic_code"],
        [/\b(disable\s+(?:security|gatekeeper|sip|sudoers|firewall|defender))\b/i, "security_disable"],
        [/\b(spctl\s+--master-disable|csrutil\s+disable)\b/i, "macos_security_disable"],
    ];

    function normalize(text) {
        return text
            .replace(/[\u200b\u200c\u200d\u200e\u200f\u202a-\u202e\u2060\u2066-\u2069\ufeff]/g, '')
            .replace(/\s+/g, ' ')
            .trim();
    }

    function check(text) {
        if (!text || typeof text !== 'string') return { action: 'SAFE', code: 0, reasons: [], matched: null };
        const normalized = normalize(text);
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
        const value = target.value || target.innerText || '';

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
            <pre style="background:#111; padding:8px; border-radius:6px; overflow:auto; max-height:120px; margin:8px 0;">${value.slice(0,200)}</pre>
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
