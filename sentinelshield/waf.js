// =============================================
//  SENTINELSHIELD v2.0 — WAF.JS
//  Advanced WAF engine + rate limiter
// =============================================

const WAF = (() => {

    // ── BASE RULES ──────────────────────────────
    let RULES = [
        {
            id: 'r001', name: 'SQL Injection – Union/Select', key: 'sqli',
            color: '#ff6b35', severity: 'critical', action: 'block',
            desc: 'Detects UNION SELECT and classic SQL injection patterns',
            hits: 0, enabled: true,
            patterns: [
                /(\bUNION\b.*\bSELECT\b)/i, /(\bSELECT\b.*\bFROM\b)/i,
                /(\bDROP\b.*\bTABLE\b)/i, /(\bINSERT\b.*\bINTO\b)/i,
                /('.*--)/, /(OR\s+['"]?\d+['"]?\s*=\s*['"]?\d+)/i,
                /(AND\s+['"]?\d+['"]?\s*=\s*['"]?\d+)/i,
                /(\bEXEC\b.*\()/i, /(;.*DROP)/i,
                /(%27|%22|%3B)/, /(\bSLEEP\b\s*\()/i,
                /(\bBENCHMARK\b\s*\()/i, /(\bWAITFOR\b\s+\bDELAY\b)/i,
            ]
        },
        {
            id: 'r002', name: 'Cross-Site Scripting (XSS)', key: 'xss',
            color: '#9b59ff', severity: 'high', action: 'block',
            desc: 'Detects script injection, event handlers and encoded XSS',
            hits: 0, enabled: true,
            patterns: [
                /<script[\s\/>]/i, /<\/script>/i, /javascript:/i,
                /on\w+\s*=/i, /<img[^>]+onerror/i, /eval\s*\(/i,
                /document\.cookie/i, /alert\s*\(/i, /String\.fromCharCode/i,
                /%3Cscript/i, /expression\s*\(/i, /vbscript:/i,
                /data:text\/html/i,
            ]
        },
        {
            id: 'r003', name: 'Local File Inclusion (LFI)', key: 'lfi',
            color: '#ffcc00', severity: 'critical', action: 'block',
            desc: 'Detects attempts to read local filesystem files',
            hits: 0, enabled: true,
            patterns: [
                /\/etc\/passwd/i, /\/etc\/shadow/i, /\.\.\/\.\.\/\.\.\//,
                /php:\/\/filter/i, /php:\/\/input/i, /expect:\/\//i,
                /\/proc\/self/i, /boot\.ini/i, /win\.ini/i,
                /system32/i, /%2e%2e%2f/i, /\.\.%2F/i,
            ]
        },
        {
            id: 'r004', name: 'OS Command Injection', key: 'cmd',
            color: '#ff2d55', severity: 'critical', action: 'block',
            desc: 'Detects shell command injection via pipes, semicolons and subshells',
            hits: 0, enabled: true,
            patterns: [
                /;\s*(ls|dir|cat|whoami|id|uname|pwd|wget|curl|bash|sh|cmd|powershell)/i,
                /\|\s*(ls|dir|cat|whoami|id|uname|wget|curl|bash|sh|nc|netcat)/i,
                /`[^`]+`/, /\$\(.*\)/,
                /\bping\b.*-[cn]/i, /\bnmap\b/i, /\bnetcat\b|\bnc\b\s/i,
                /&&.*\b(rm|del|format|shutdown)\b/i,
            ]
        },
        {
            id: 'r005', name: 'Directory Traversal', key: 'traversal',
            color: '#00e5c0', severity: 'high', action: 'block',
            desc: 'Detects path traversal attempts using ../ sequences',
            hits: 0, enabled: true,
            patterns: [
                /\.\.\//, /\.\.%2F/i, /%2e%2e%2f/i, /\.\.%5C/i, /\.\.\\/,
                /%252e%252e%252f/i,
            ]
        },
        {
            id: 'r006', name: 'XXE Injection', key: 'xxe',
            color: '#00d4ff', severity: 'high', action: 'block',
            desc: 'Detects XML External Entity injection patterns',
            hits: 0, enabled: true,
            patterns: [
                /<!ENTITY/i, /SYSTEM\s+"file:/i, /SYSTEM\s+'file:/i,
                /<!DOCTYPE[^>]*\[/i, /&\w+;/,
                /<!ENTITY\s+\w+\s+SYSTEM/i,
            ]
        },
        {
            id: 'r007', name: 'SSRF Attack', key: 'ssrf',
            color: '#ff8ac4', severity: 'high', action: 'block',
            desc: 'Detects Server-Side Request Forgery attempts',
            hits: 0, enabled: true,
            patterns: [
                /http:\/\/169\.254\.169\.254/i,  // AWS metadata
                /http:\/\/localhost/i,
                /http:\/\/127\.\d+\.\d+\.\d+/i,
                /http:\/\/0\.0\.0\.0/i,
                /file:\/\//i,
                /gopher:\/\//i,
                /dict:\/\//i,
                /ftp:\/\/.*@/i,
            ]
        },
        {
            id: 'r008', name: 'Scanner / Recon UA', key: 'scanner',
            color: '#88ee44', severity: 'medium', action: 'alert',
            desc: 'Detects known security scanner user-agent strings',
            hits: 0, enabled: true,
            patterns: [
                /sqlmap/i, /nikto/i, /nessus/i, /acunetix/i,
                /burpsuite/i, /dirbuster/i, /masscan/i, /metasploit/i,
                /nmap/i, /openvas/i, /w3af/i, /wpscan/i,
            ]
        },
    ];

    // Custom rules added by user
    let customRules = [];

    function getAllRules() { return [...RULES, ...customRules]; }

    function addCustomRule(rule) { customRules.push(rule); }
    function deleteRule(id) {
        RULES = RULES.filter(r => r.id !== id);
        customRules = customRules.filter(r => r.id !== id);
    }
    function toggleRule(id) {
        const all = getAllRules();
        const r = all.find(r => r.id === id);
        if (r) r.enabled = !r.enabled;
    }
    function resetRules() { RULES.forEach(r => { r.hits = 0; r.enabled = true; }); customRules = []; }

    // ── RATE LIMITER ────────────────────────────
    const RATE_LIMIT = 10;
    const RATE_WINDOW = 10000;
    const ipTracker = {};

    function checkRateLimit(ip) {
        const now = Date.now();
        if (!ipTracker[ip]) ipTracker[ip] = [];
        ipTracker[ip] = ipTracker[ip].filter(t => now - t < RATE_WINDOW);
        ipTracker[ip].push(now);
        return ipTracker[ip].length > RATE_LIMIT;
    }
    function getIPCount(ip) { return (ipTracker[ip] || []).length; }
    function getAllIPs() { return ipTracker; }

    // ── INSPECT ─────────────────────────────────
    function inspect(req) {
        const { ip, method, url, body = '', userAgent = '', headers = '', cookie = '' } = req;
        const target = [url, body, userAgent, headers, cookie].join(' ');

        const isRateLimited = checkRateLimit(ip);
        const triggered = [];

        for (const rule of getAllRules()) {
            if (!rule.enabled) continue;
            for (const pat of rule.patterns) {
                if (pat.test(target)) {
                    if (!triggered.find(r => r.id === rule.id)) {
                        rule.hits++;
                        triggered.push(rule);
                    }
                    break;
                }
            }
        }

        const isMalicious = triggered.length > 0;
        let status, icon, message;

        if (isMalicious && triggered.some(r => r.action === 'block')) {
            status = 'blocked';
            icon = '🚫';
            message = `Malicious payload detected: ${triggered.map(r => r.name).join(' + ')}`;
        } else if (isMalicious) {
            status = 'blocked';
            icon = '⚠';
            message = `Alert-only rule triggered: ${triggered.map(r => r.name).join(', ')}`;
        } else if (isRateLimited) {
            status = 'ratelimit';
            icon = '⏱';
            message = `Rate limit exceeded – ${getIPCount(ip)} requests from ${ip} in 10 seconds`;
        } else {
            status = 'allowed';
            icon = '✅';
            message = 'Request passed all security checks';
        }

        return { status, icon, message, categories: triggered, requestCount: getIPCount(ip), isRateLimited };
    }

    // ── DECODE HELPERS ───────────────────────────
    function decodePayload(s) {
        try { s = decodeURIComponent(s); } catch (e) { }
        try { s = decodeURIComponent(s); } catch (e) { } // double-decode
        s = s.replace(/&#(\d+);/g, (_, n) => String.fromCharCode(n));
        s = s.replace(/&#x([\da-f]+);/gi, (_, n) => String.fromCharCode(parseInt(n, 16)));
        return s;
    }

    return { inspect, getAllRules, addCustomRule, deleteRule, toggleRule, resetRules, decodePayload, getAllIPs };
})();