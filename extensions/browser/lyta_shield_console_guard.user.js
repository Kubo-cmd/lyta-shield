// ==UserScript==
// @name         LYTA Shield - Browser Console Guard
// @namespace    urn:lyta-shield
// @version      1.2.0
// @description  Intercepts dangerous paste in browser console and AI chat inputs
// @author       LYTA.EXE
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
        [/\b(curl|wget|fetch)\b.*?\|\s*(?:\/bin\/)?(?:ba|z)?sh\b/i, "remote_fetch_to_shell"],
        [/\b(curl|wget|fetch)\b.*?(?:\s+\|\s+(sudo\s+)?(?:\/bin\/)?(?:ba|z)?sh|(?:bash|sh|zsh)\s+-c)/i, "remote_fetch_to_shell2"],
        [/\b(curl|wget|fetch)\b.*?\s+>\s+\/tmp\/\w+\s*&&\s*chmod\s*\+x\s+\/tmp\/\w+\s*(?:&&|;|\|\|)\s*\S*\/tmp\/\w+/i, "remote_fetch_chmod_execute"],
        [/\beval\s*\(\s*['"][^'"]*(?:exec|system|cookie|localStorage|fetch|XMLHttpRequest|document\.write|child_process|require\s*\()[^'"]*['"]/i, "browser_eval"],
        [/\beval\s*\(\s*(['"])\s*alert\s*\(\s*1\s*\)\s*;?\s*\1\s*\)/i, "browser_eval_alert_one"],
        [/\beval\s*\(\s*(['"])\s*document\.location\s*=\s*(['"])https?:\/\/[^/'"\s)]+(?:\/[^'"\s)]*)?\2\s*;?\s*\1\s*\)/i, "browser_eval_document_location_external"],
        [/\beval\s*\(\s*['"](?:\d+\s*[-+*/])\d+['"]\s*\)/i, "browser_eval_simple"],
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
        [/\brm\s+-(?=[a-z]*f)(?=[a-z]*r)[a-z]+\s+(?:\/|~|\$HOME)\s*$/i, "destructive_command_option_permutation"],
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
        [/\b(eval\s+['"]\$|exec\s+\$\(curl)/i, "eval_dynamic_exec"],
        [/\b(Function\s*\(\s*\)|new\s+Function\s*\(\s*['"].*?\)|setTimeout\s*\(\s*['"].*?\)|setInterval\s*\(\s*['"].*?\))/i, "browser_dynamic_code"],
        [/\b(disable\s+(?:security|gatekeeper|sip|sudoers|firewall|defender))\b/i, "security_disable"],
        [/\b(spctl\s+--master-disable|csrutil\s+disable)\b/i, "macos_security_disable"],
    ];

    const SAFE_INSTALLERS = [
        /^https:\/\/hermes-agent\.nousresearch\.com\/install\.sh$/i,
        /^https:\/\/raw\.githubusercontent\.com\/Homebrew\/install\/(?:HEAD|master)\/install\.sh$/i,
        /^https:\/\/ollama\.com\/install\.sh$/i,
        /^https:\/\/sh\.rustup\.rs$/i,
        /^https:\/\/brew\.sh\/install$/i,
        /^https:\/\/raw\.githubusercontent\.com\/NousResearch\/hermes-agent\/(?:main|master)\/install\.sh$/i,
        /^https:\/\/x\.ai\/cli\/install\.sh$/i,
    ];

    function safeInstaller(pipeline) {
        const urls = pipeline.match(/https:\/\/[^\s'"|;]+/gi) || [];
        return urls.length === 1 && urls.some(url => SAFE_INSTALLERS.some(pattern => pattern.test(url.replace(/[\])],?$/, ''))));
    }

    function safeContext(text, start, end) {
        const left = Math.max(text.lastIndexOf('.', start), text.lastIndexOf('!', start), text.lastIndexOf('?', start), text.lastIndexOf('\n', start)) + 1;
        const rightCandidates = ['.', '!', '?', '\n'].map(marker => text.indexOf(marker, end)).filter(index => index >= 0);
        const right = rightCandidates.length ? Math.min(...rightCandidates) : text.length;
        const local = text.slice(left, right);
        return /\b(do\s+not|don't|never)\s+(?:actually\s+)?(?:run|execute|paste|copy)|\bcopy\s+this\s+(?:and\s+)?paste\s+it\s+into\s+(?:the\s+)?(?:your\s+)?(?:shell|terminal|console)\s+for\s+(?:the\s+)?(?:tutorial|documentation|example|test)/i.test(local);
    }

    function normalize(text) {
        return text.normalize('NFKC')
            .replace(/[\u200b\u200c\u200d\u200e\u200f\u202a-\u202e\u2060\u2066-\u2069\ufeff]/g, '')
            .replace(/\s+/g, ' ')
            .trim();
    }

    function check(text) {
        if (!text || typeof text !== 'string') return { action: 'SAFE', code: 0, reasons: [], matched: null };
        const normalized = normalize(text);
        if (!normalized) return { action: 'SAFE', code: 0, reasons: [], matched: null };

        let downgraded = null;
        for (const [pat, reason] of BLOCKED_PATTERNS) {
            const m = normalized.match(pat);
            if (m) {
                if (reason === 'paste_jacking_instruction' && safeContext(normalized, m.index, m.index + m[0].length)) {
                    downgraded = { action: 'SUSPICIOUS', code: 1, reasons: [reason, 'explicit_safe_context_needs_review'], matched: m[0] };
                    continue;
                }
                if (reason.startsWith('remote_fetch_to_shell') && safeInstaller(normalized)) {
                    downgraded = { action: 'SUSPICIOUS', code: 1, reasons: [reason, 'known_safe_installer_needs_confirmation'], matched: m[0] };
                    continue;
                }
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
        if (downgraded) return downgraded;
        return { action: 'SAFE', code: 0, reasons: [], matched: null };
    }

    globalThis.__LYTA_SHIELD_TEST__ = { check, normalize };
    if (typeof document === 'undefined') return;

    function addTextBlock(parent, text, style) {
        const node = document.createElement('div');
        node.style.cssText = style;
        node.textContent = text;
        parent.appendChild(node);
        return node;
    }

    function showWarning(target, verdict, previewText) {
        const color = verdict.code === 2 ? '#ff4444' : '#ffaa00';
        const title = verdict.code === 2 ? 'LYTA Shield: BLOCKED' : 'LYTA Shield: WARNING';
        const msg = verdict.code === 2
            ? 'This code is dangerous. LYTA Shield blocked the action.'
            : 'This code is suspicious. Review before continuing.';
        const reasons = verdict.reasons.map(reason => `• ${reason}`).join('\n');
        const value = previewText ?? target.value ?? target.innerText ?? '';

        const div = document.createElement('div');
        div.style.cssText = `
            position:fixed; top:20px; left:50%; transform:translateX(-50%);
            z-index:2147483647; background:#000; color:#fff;
            border:2px solid ${color}; border-radius:12px;
            padding:16px 20px; max-width:500px; font-family:system-ui,sans-serif;
            font-size:14px; line-height:1.5; box-shadow:0 10px 40px rgba(0,0,0,0.8);
        `;
        addTextBlock(div, title, `font-weight:bold;color:${color};font-size:16px;margin-bottom:8px;`);
        addTextBlock(div, msg, 'margin-bottom:8px;');
        const preview = document.createElement('pre');
        preview.style.cssText = 'background:#111;padding:8px;border-radius:6px;overflow:auto;max-height:120px;margin:8px 0;';
        preview.textContent = String(value).slice(0, 200);
        div.appendChild(preview);
        addTextBlock(div, reasons, 'color:#aaa;margin-bottom:12px;white-space:pre-wrap;');
        const actions = document.createElement('div');
        actions.style.textAlign = 'right';
        const dismiss = document.createElement('button');
        dismiss.type = 'button';
        dismiss.textContent = 'Dismiss';
        dismiss.style.cssText = 'background:#333;color:#fff;border:1px solid #555;padding:6px 12px;border-radius:6px;cursor:pointer;';
        dismiss.addEventListener('click', () => div.remove());
        actions.appendChild(dismiss);
        div.appendChild(actions);
        (document.body || document.documentElement).appendChild(div);
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

    function inputText(target) {
        return target?.value ?? target?.innerText ?? '';
    }

    function blockEvent(event, target, text) {
        const verdict = check(text);
        if (verdict.code === 0) return true;
        event.preventDefault();
        event.stopImmediatePropagation();
        showWarning(target, verdict, text);
        return false;
    }

    function guardPaste(event) {
        const target = event.target;
        if (!target) return;
        const clipboardText = event.clipboardData?.getData('text/plain') ?? '';
        blockEvent(event, target, clipboardText);
    }

    function guardedInputWithin(container) {
        if (!container) return null;
        if (container.matches?.(AI_CHAT_SELECTORS.join(', '))) return container;
        return container.querySelector?.(AI_CHAT_SELECTORS.join(', ')) ?? null;
    }

    function guardSubmission(event) {
        const input = guardedInputWithin(event.target);
        if (input) blockEvent(event, input, inputText(input));
    }

    function guardSubmitClick(event) {
        const button = event.target?.closest?.('button, input[type="submit"], [role="button"]');
        if (!button) return;
        const input = guardedInputWithin(button.closest('form'));
        if (input) blockEvent(event, input, inputText(input));
    }

    function attachInputGuards() {
        document.querySelectorAll(AI_CHAT_SELECTORS.join(', ')).forEach(el => {
            if (el.dataset.lytaShieldGuarded) return;
            el.dataset.lytaShieldGuarded = 'true';
            el.addEventListener('paste', guardPaste, true);
            el.addEventListener('keydown', (event) => {
                if (event.key === 'Enter' && !event.shiftKey) {
                    blockEvent(event, event.target, inputText(event.target));
                }
            }, true);
        });
    }

    document.addEventListener('submit', guardSubmission, true);
    document.addEventListener('click', guardSubmitClick, true);

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
