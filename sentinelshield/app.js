// =============================================
//  SENTINELSHIELD v2.0 — APP.JS
//  Main controller
// =============================================

// ── BACKGROUND CANVAS ──────────────────────
(function initBG() {
    const cv = document.getElementById('bgCanvas');
    const ctx = cv.getContext('2d');
    let W, H, particles = [];

    function resize() {
        W = cv.width = window.innerWidth;
        H = cv.height = window.innerHeight;
    }
    window.addEventListener('resize', resize);
    resize();

    for (let i = 0; i < 60; i++) particles.push({
        x: Math.random() * 1920, y: Math.random() * 1080,
        vx: (Math.random() - 0.5) * 0.3, vy: (Math.random() - 0.5) * 0.3,
        r: Math.random() * 1.5 + 0.5, a: Math.random()
    });

    function drawBG() {
        ctx.clearRect(0, 0, W, H);
        // Grid
        ctx.strokeStyle = 'rgba(26,40,64,0.25)'; ctx.lineWidth = 1;
        for (let x = 0; x < W; x += 60) { ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, H); ctx.stroke(); }
        for (let y = 0; y < H; y += 60) { ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(W, y); ctx.stroke(); }
        // Particles
        particles.forEach(p => {
            p.x += p.vx; p.y += p.vy;
            if (p.x < 0) p.x = W; if (p.x > W) p.x = 0;
            if (p.y < 0) p.y = H; if (p.y > H) p.y = 0;
            ctx.beginPath(); ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
            ctx.fillStyle = `rgba(0,212,255,${p.a * 0.4})`; ctx.fill();
        });
        // Connect nearby
        particles.forEach((a, i) => {
            particles.slice(i + 1).forEach(b => {
                const d = Math.hypot(a.x - b.x, a.y - b.y);
                if (d < 120) { ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.strokeStyle = `rgba(0,212,255,${0.06 * (1 - d / 120)})`; ctx.lineWidth = 0.5; ctx.stroke(); }
            });
        });
        requestAnimationFrame(drawBG);
    }
    drawBG();
})();

// ── CLOCK ──────────────────────────────────
function updateClock() {
    const el = document.getElementById('navClock');
    if (el) el.textContent = new Date().toLocaleTimeString();
}
setInterval(updateClock, 1000);

// ── BOOT SEQUENCE ──────────────────────────
const BOOT_LINES = [
    '[INIT]  Loading signature database…',
    '[INIT]  WAF engine starting…',
    '[INIT]  Rate limiter initialized (10 req/10s)…',
    '[INIT]  Pattern rules loaded: 8 rule sets, 74 signatures…',
    '[INIT]  Logger module ready…',
    '[INIT]  Dashboard canvases initialized…',
    '[INIT]  Network interface binding on port 443…',
    '[OK]    All subsystems operational',
    '[OK]    SentinelShield v2.0 active — SYSTEM PROTECTED',
];

(function boot() {
    const fill = document.getElementById('bootFill');
    const log = document.getElementById('bootLog');
    let i = 0;

    const iv = setInterval(() => {
        if (i < BOOT_LINES.length) {
            log.innerHTML += BOOT_LINES[i] + '<br>';
            fill.style.width = ((i + 1) / BOOT_LINES.length * 100) + '%';
            i++;
        } else {
            clearInterval(iv);
            setTimeout(() => {
                const bs = document.getElementById('bootScreen');
                bs.style.opacity = '0';
                setTimeout(() => {
                    bs.style.display = 'none';
                    document.getElementById('appShell').classList.remove('hidden');
                    Dashboard.init();
                    renderRulesTable();
                    updateClock();
                }, 800);
            }, 400);
        }
    }, 130);
})();

// ── TAB SWITCHING ──────────────────────────
function switchTab(tab) {
    document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
    document.querySelectorAll('.nav-tab').forEach(el => el.classList.remove('active'));
    document.getElementById('tab-' + tab)?.classList.add('active');
    document.querySelector(`.nav-tab[data-tab="${tab}"]`)?.classList.add('active');
    if (tab === 'report') generateReport();
}

// ── ATTACK PRESETS ─────────────────────────
const PRESETS = {
    sqli: { method: 'POST', url: "/login.php?id=1'%20OR%201=1%20--", body: "username=admin'--&password=x", note: 'Classic SQL Injection – auth bypass' },
    xss: { method: 'GET', url: "/search?q=<script>alert(document.cookie)</script>", body: 'comment=<img src=x onerror=alert(1)>', note: 'Reflected XSS – cookie theft' },
    lfi: { method: 'GET', url: '/page?file=../../../../etc/passwd', body: '', note: 'LFI – reading /etc/passwd' },
    cmd: { method: 'POST', url: '/ping?host=localhost;whoami', body: 'cmd=ls+-la+|+cat+/etc/shadow', note: 'OS Command Injection via pipe' },
    traversal: { method: 'GET', url: '/download?file=../../config/database.yml', body: '', note: 'Directory traversal to config file' },
    brute: { method: 'POST', url: '/admin/login', body: 'username=admin&password=password123', note: 'Brute-force login (×10 requests)', repeat: 10 },
    xxe: { method: 'POST', url: '/api/parse-xml', body: '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>', note: 'XXE – reading /etc/passwd via XML entity' },
    ssrf: { method: 'GET', url: '/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/', body: '', note: 'SSRF – AWS metadata endpoint' },
};

const RANDOM_IPS = ['192.168.1.10', '10.0.0.42', '172.16.5.3', '45.33.32.156', '198.51.100.7', '203.0.113.55', '1.2.3.4', '77.88.55.66'];
const RANDOM_PATHS = ['/index.php', '/api/v1/users', '/admin', '/login', '/search', '/upload', '/profile', '/api/token', '/static/app.js'];
const RANDOM_UAS = ['Mozilla/5.0 (Windows NT 10.0)', 'sqlmap/1.7.8', 'curl/7.64.1', 'Python-requests/2.28', 'Googlebot/2.1', 'Nikto/2.1.6'];

function loadPreset(key) {
    const p = PRESETS[key];
    if (!p) return;
    document.getElementById('simMethod').value = p.method;
    document.getElementById('simURL').value = p.url;
    document.getElementById('simBody').value = p.body;
    if (p.repeat) {
        let c = 0;
        const iv = setInterval(() => {
            fireRequest(true);
            if (++c >= p.repeat) clearInterval(iv);
        }, 150);
    }
}

function randomRequest() {
    document.getElementById('simIP').value = RANDOM_IPS[Math.floor(Math.random() * RANDOM_IPS.length)];
    document.getElementById('simMethod').value = Math.random() > 0.5 ? 'GET' : 'POST';
    document.getElementById('simURL').value = RANDOM_PATHS[Math.floor(Math.random() * RANDOM_PATHS.length)];
    document.getElementById('simUA').value = RANDOM_UAS[Math.floor(Math.random() * RANDOM_UAS.length)];
    document.getElementById('simBody').value = '';
}

function clearSim() {
    document.getElementById('simIP').value = '192.168.1.100';
    document.getElementById('simMethod').value = 'GET';
    document.getElementById('simURL').value = '/index.php';
    document.getElementById('simBody').value = '';
    document.getElementById('simHeaders').value = '';
    document.getElementById('simUA').value = 'Mozilla/5.0 (Windows NT 10.0)';
    document.getElementById('simCookie').value = '';
    document.getElementById('simPort').value = '80';
    resetResultDisplay();
}

// ── FIRE REQUEST ───────────────────────────
let sessionHistory = [];

function fireRequest(silent = false) {
    const req = {
        ip: document.getElementById('simIP').value.trim() || '127.0.0.1',
        method: document.getElementById('simMethod').value,
        url: document.getElementById('simURL').value.trim() || '/',
        body: document.getElementById('simBody').value.trim(),
        headers: document.getElementById('simHeaders').value.trim(),
        userAgent: document.getElementById('simUA').value.trim(),
        cookie: document.getElementById('simCookie').value.trim(),
        port: document.getElementById('simPort').value.trim() || '80',
    };

    const result = WAF.inspect(req);

    Logger.addLog({
        ip: req.ip, method: req.method, url: req.url,
        body: req.body, status: result.status,
        category: result.categories.map(r => r.name || r.key).join(', ')
    });

    Dashboard.update(req, result);

    sessionHistory.unshift({ req, result, time: new Date().toTimeString().slice(0, 8) });
    if (sessionHistory.length > 50) sessionHistory.pop();
    renderSessionHistory();

    if (!silent) {
        showResult(result, req);
        showPacketDissection(req, result);
    }
}

// ── RESULT DISPLAY ─────────────────────────
function showResult(result, req) {
    const box = document.getElementById('resultDisplay');
    if (!box) return;
    box.className = `result-display ${result.status}`;

    const statusInfo = {
        allowed: { icon: '✅', label: 'REQUEST ALLOWED' },
        blocked: { icon: '🚫', label: 'REQUEST BLOCKED' },
        ratelimit: { icon: '⏱', label: 'RATE LIMITED' },
    };
    const si = statusInfo[result.status];

    const tags = result.categories.map(c =>
        `<span class="rtag ${c.key}">${c.name || c.key}</span>`
    ).join('');
    const rlTag = result.isRateLimited ? `<span class="rtag ratelimit">RATE LIMIT</span>` : '';

    box.innerHTML = `
    <div class="result-main">
      <div class="res-icon">${si.icon}</div>
      <div class="res-title ${result.status}">${si.label}</div>
      <div class="res-msg">${result.message}</div>
      <div class="res-tags">${tags}${rlTag}</div>
      <div style="margin-top:10px;font-family:var(--font-mono);font-size:0.65rem;color:var(--muted)">
        IP: ${req.ip} · ${req.method} ${req.url} · ${new Date().toLocaleTimeString()}
      </div>
    </div>`;
}

function resetResultDisplay() {
    const box = document.getElementById('resultDisplay');
    if (!box) return;
    box.className = 'result-display';
    box.innerHTML = `<div class="rd-idle"><div class="rd-shield">🛡</div><div class="rd-wait">Awaiting Request…</div><div class="rd-sub">Configure and fire a request to see real-time WAF analysis</div></div>`;
}

// ── PACKET DISSECTION ──────────────────────
function showPacketDissection(req, result) {
    const el = document.getElementById('packetDissect');
    if (!el) return;
    const decoded = WAF.decodePayload;
    const highlight = (s) => {
        return s.replace(/(<script[\s\S]*?<\/script>|on\w+=|javascript:|UNION.*SELECT|OR 1=1|\.\.\/|\/etc\/passwd|whoami|eval\(|alert\(|<!ENTITY)/gi,
            m => `<span class="pd-hit">${m}</span>`);
    };

    const layers = [
        { label: 'URL / PATH', cls: 'url', content: highlight(req.url || '(empty)') },
        { label: 'HEADERS', cls: 'hdr', content: highlight(req.headers || '(none)') },
        { label: 'BODY / PAYLOAD', cls: 'body', content: highlight(req.body || '(empty)') },
        { label: 'COOKIE', cls: 'cookie', content: highlight(req.cookie || '(none)') },
    ];

    el.innerHTML = layers.map(l => `
    <div class="pd-layer ${l.cls}">
      <div class="pd-layer-hdr">${l.label}<span>▾</span></div>
      <div class="pd-layer-body">${l.content}</div>
    </div>`).join('');
}

// ── SESSION HISTORY ────────────────────────
function renderSessionHistory() {
    const el = document.getElementById('sessionHistory');
    if (!el) return;
    el.innerHTML = sessionHistory.slice(0, 30).map(h => `
    <div class="sh-item ${h.result.status}" onclick="replayHistory(this)" title="${h.req.url}">
      <span class="sh-time">${h.time}</span>
      <span class="sh-status">${h.result.status.toUpperCase()}</span>
      <span class="sh-url">[${h.req.method}] ${h.req.url}</span>
    </div>`).join('');
}
function clearHistory() { sessionHistory = []; renderSessionHistory(); }

// ── PACKET ANALYZER TAB ────────────────────
function analyzePacket() {
    const raw = document.getElementById('rawPacket').value.trim();
    if (!raw) return;

    const lines = raw.split('\n');
    const reqLine = lines[0] || '';
    const parts = reqLine.split(' ');
    const method = parts[0] || 'GET';
    const url = parts[1] || '/';

    const headerSection = [], bodyLines = [];
    let inBody = false;
    lines.slice(1).forEach(l => {
        if (!inBody && l.trim() === '') { inBody = true; return; }
        if (inBody) bodyLines.push(l);
        else headerSection.push(l);
    });

    const headers = headerSection.join('\n');
    const body = bodyLines.join('\n');
    const ua = (headerSection.find(h => /user-agent/i.test(h)) || '').replace(/.*?:\s*/i, '');
    const cookie = (headerSection.find(h => /^cookie:/i.test(h)) || '').replace(/.*?:\s*/i, '');
    const hostLine = (headerSection.find(h => /^host:/i.test(h)) || '').replace(/.*?:\s*/i, '');

    const req = { ip: '<packet>', method, url, body, headers, userAgent: ua, cookie };
    const result = WAF.inspect(req);

    // Render decoded layers
    const dl = document.getElementById('decodedLayers');
    const highlight = s => s.replace(/(UNION.*SELECT|OR 1=1|<script|on\w+=|javascript:|\.\.\/|\/etc\/passwd|whoami|eval\(|alert\(|<!ENTITY|SYSTEM\s+"file:|169\.254)/gi, m => `<span class="pd-hit">${m}</span>`);

    dl.innerHTML = [
        { l: 'REQUEST LINE', c: 'url', v: reqLine },
        { l: 'HOST', c: 'hdr', v: hostLine },
        { l: 'HEADERS', c: 'hdr', v: highlight(headers) },
        { l: 'BODY', c: 'body', v: highlight(body) },
        { l: 'COOKIE', c: 'cookie', v: highlight(cookie) },
        { l: 'USER-AGENT', c: 'hdr', v: ua },
        { l: 'URL DECODED', c: 'url', v: highlight(WAF.decodePayload(url)) },
    ].map(x => `
    <div class="pd-layer ${x.c}">
      <div class="pd-layer-hdr">${x.l}<span>▾</span></div>
      <div class="pd-layer-body">${x.v || '(empty)'}</div>
    </div>`).join('');

    // Render result panel
    const ar = document.getElementById('analyzerResult');
    const statusColor = result.status === 'allowed' ? 'ok' : result.status === 'blocked' ? 'blocked' : 'warn';
    const statusLabel = result.status === 'allowed' ? '✅ REQUEST ALLOWED' : '🚫 REQUEST BLOCKED';

    const findings = result.categories.length
        ? result.categories.map(c => `<b style="color:${c.color}">[${(c.name || c.key).toUpperCase()}]</b> ${c.desc || 'Pattern matched'}`).join('<br>')
        : 'No malicious patterns detected.';

    ar.innerHTML = `
    <div class="ar-section">
      <div class="ar-sec-hdr ${statusColor}">${statusLabel}</div>
      <div class="ar-sec-body">${result.message}</div>
    </div>
    <div class="ar-section">
      <div class="ar-sec-hdr warn">FINDINGS</div>
      <div class="ar-sec-body">${findings}</div>
    </div>
    <div class="ar-section">
      <div class="ar-sec-hdr ok">REQUEST SUMMARY</div>
      <div class="ar-sec-body">
        Method: <b>${method}</b><br>
        Path:   <b>${url}</b><br>
        Host:   <b>${hostLine || '—'}</b><br>
        Body length: <b>${body.length} bytes</b><br>
        Rules triggered: <b>${result.categories.length}</b>
      </div>
    </div>`;
}

// ── RULES TAB ──────────────────────────────
let ruleCounter = 100;

function renderRulesTable() {
    const el = document.getElementById('rulesTable');
    if (!el) return;
    el.innerHTML = `
    <div class="rule-row" style="background:transparent;border:none;font-size:0.6rem;color:var(--muted);letter-spacing:1px;text-transform:uppercase">
      <span>RULE NAME</span><span>KEY</span><span>SEVERITY</span><span>ACTION</span><span>HITS</span><span>CONTROLS</span>
    </div>` +
        WAF.getAllRules().map(r => `
      <div class="rule-row ${r.enabled ? '' : 'disabled'}" id="rule-${r.id}">
        <span class="rule-name">${r.name}</span>
        <span class="rule-key">${r.key}</span>
        <span class="rule-sev ${r.severity}">${r.severity.toUpperCase()}</span>
        <span class="rule-action">${r.action.toUpperCase()}</span>
        <span class="rule-hits">${r.hits}</span>
        <span class="rule-btns">
          <button class="rule-btn toggle" onclick="toggleRule('${r.id}')">${r.enabled ? 'DISABLE' : 'ENABLE'}</button>
          <button class="rule-btn del" onclick="deleteRule('${r.id}')">DEL</button>
        </span>
      </div>`).join('');
}

function toggleRule(id) { WAF.toggleRule(id); renderRulesTable(); }
function deleteRule(id) { WAF.deleteRule(id); renderRulesTable(); }
function resetRules() { WAF.resetRules(); renderRulesTable(); }

function openRuleEditor() {
    document.getElementById('reName').value = '';
    document.getElementById('reKey').value = '';
    document.getElementById('rePattern').value = '';
    document.getElementById('reDesc').value = '';
    document.getElementById('ruleSaveMsg').textContent = '';
}

function saveRule() {
    const name = document.getElementById('reName').value.trim();
    const key = document.getElementById('reKey').value.trim().toLowerCase().replace(/\s+/g, '-');
    const patStr = document.getElementById('rePattern').value.trim();
    const sev = document.getElementById('reSeverity').value;
    const act = document.getElementById('reAction').value;
    const desc = document.getElementById('reDesc').value.trim();

    if (!name || !key || !patStr) { showSaveMsg('⚠ Fill in all required fields', 'var(--yellow)'); return; }

    let regex;
    try {
        const m = patStr.match(/^\/(.+)\/([gimsuy]*)$/);
        regex = m ? new RegExp(m[1], m[2]) : new RegExp(patStr, 'i');
    } catch (e) { showSaveMsg('⚠ Invalid regex pattern', 'var(--red)'); return; }

    ruleCounter++;
    WAF.addCustomRule({
        id: 'cr' + ruleCounter, name, key, color: '#00d4ff', severity: sev, action: act,
        desc, hits: 0, enabled: true, patterns: [regex]
    });
    renderRulesTable();
    showSaveMsg('✅ Rule saved successfully', 'var(--green)');
}

function showSaveMsg(msg, color) {
    const el = document.getElementById('ruleSaveMsg');
    if (el) { el.textContent = msg; el.style.color = color; setTimeout(() => el.textContent = '', 3000); }
}

// ── LOGS ───────────────────────────────────
function filterLogs() { Logger.filterLogs(); }
function clearLogs() { Logger.clearLogs(); }
function exportLogs() { Logger.exportLogs(); }

// ── REPORT ─────────────────────────────────
function generateReport() {
    const el = document.getElementById('reportContent');
    if (!el) return;
    const s = Dashboard.getStats();
    const logs = Logger.getLogs();
    const now = new Date().toLocaleString();
    const rules = WAF.getAllRules();
    const blockRate = s.total ? Math.round(s.blocked / s.total * 100) : 0;

    const catRows = Object.values(s.categories).map(c =>
        `<tr><td>${c.label}</td><td>${c.count}</td><td>${s.total ? Math.round(c.count / s.total * 100) : 0}%</td></tr>`
    ).join('');

    const ipRows = Object.entries(s.ips).sort((a, b) => b[1].blocked - a[1].blocked).slice(0, 10).map(([ip, d], i) =>
        `<tr><td>#${i + 1}</td><td>${ip}</td><td>${d.count}</td><td>${d.blocked}</td></tr>`
    ).join('');

    el.innerHTML = `
    <div class="rp-section">
      <div class="rp-hdr">SENTINELSHIELD — SESSION SECURITY REPORT</div>
      <div style="font-size:0.68rem;color:var(--muted);margin-bottom:16px">Generated: ${now}</div>
      <div class="rp-stat-grid">
        <div class="rp-stat"><div class="rp-stat-val">${s.total}</div><div class="rp-stat-lbl">Total Requests</div></div>
        <div class="rp-stat"><div class="rp-stat-val" style="color:var(--red)">${s.blocked}</div><div class="rp-stat-lbl">Blocked / Rate Limited</div></div>
        <div class="rp-stat"><div class="rp-stat-val" style="color:var(--yellow)">${blockRate}%</div><div class="rp-stat-lbl">Block Rate</div></div>
      </div>
    </div>
    <div class="rp-section">
      <div class="rp-hdr">ATTACK CATEGORY BREAKDOWN</div>
      ${catRows ? `<table class="rp-table"><tr><th>Category</th><th>Count</th><th>% of Total</th></tr>${catRows}</table>` : '<div style="color:var(--muted);font-size:0.72rem">No attacks recorded.</div>'}
    </div>
    <div class="rp-section">
      <div class="rp-hdr">TOP OFFENDING IP ADDRESSES</div>
      ${ipRows ? `<table class="rp-table"><tr><th>Rank</th><th>IP Address</th><th>Total Req</th><th>Blocked</th></tr>${ipRows}</table>` : '<div style="color:var(--muted);font-size:0.72rem">No IP data.</div>'}
    </div>
    <div class="rp-section">
      <div class="rp-hdr">ACTIVE DETECTION RULES</div>
      <table class="rp-table">
        <tr><th>Rule Name</th><th>Severity</th><th>Action</th><th>Hits</th><th>Status</th></tr>
        ${rules.map(r => `<tr><td>${r.name}</td><td>${r.severity.toUpperCase()}</td><td>${r.action.toUpperCase()}</td><td>${r.hits}</td><td>${r.enabled ? 'ACTIVE' : 'DISABLED'}</td></tr>`).join('')}
      </table>
    </div>
    <div class="rp-section">
      <div class="rp-hdr">SECURITY RECOMMENDATIONS</div>
      <div style="font-size:0.72rem;line-height:2;color:var(--text)">
        ${blockRate > 50 ? '⚠ High block rate detected — consider IP whitelisting or reviewing rule sensitivity.<br>' : ''}
        ${s.categories['sqli']?.count > 0 ? '• SQL Injection attempts detected — review database query parameterization.<br>' : ''}
        ${s.categories['xss']?.count > 0 ? '• XSS attempts detected — enforce Content Security Policy (CSP) headers.<br>' : ''}
        ${s.categories['lfi']?.count > 0 ? '• LFI attempts detected — validate and sanitize all file path inputs.<br>' : ''}
        ${s.categories['cmd']?.count > 0 ? '• Command injection detected — never pass user input to system commands.<br>' : ''}
        ${s.rateLimited > 0 ? '• Rate limiting triggered — consider implementing CAPTCHA or IP blocking.<br>' : ''}
        ${s.total === 0 ? 'No requests analyzed yet. Use the Simulator to test the WAF.' : ''}
      </div>
    </div>`;
}

function exportReport() {
    const s = Dashboard.getStats();
    const txt = `SENTINELSHIELD SESSION REPORT\n${'='.repeat(50)}\nGenerated: ${new Date().toLocaleString()}\n\nTotal Requests : ${s.total}\nBlocked        : ${s.blocked}\nAllowed        : ${s.allowed}\nRate Limited   : ${s.rateLimited}\nUnique IPs     : ${Object.keys(s.ips).length}\nBlock Rate     : ${s.total ? Math.round(s.blocked / s.total * 100) : 0}%\n\nATTACK BREAKDOWN\n${'-'.repeat(30)}\n${Object.values(s.categories).map(c => `${c.label.padEnd(30)} ${c.count}`).join('\n') || 'None'}\n\nTOP OFFENDERS\n${'-'.repeat(30)}\n${Object.entries(s.ips).sort((a, b) => b[1].blocked - a[1].blocked).slice(0, 10).map(([ip, d]) => `${ip.padEnd(20)} Requests:${d.count} Blocked:${d.blocked}`).join('\n') || 'None'}\n\nLOG ENTRIES (last 20)\n${'-'.repeat(30)}\n${Logger.getLogs().slice(0, 20).map(l => `[${l.time}] ${l.status.toUpperCase().padEnd(10)} ${l.ip.padEnd(16)} ${l.method.padEnd(7)} ${l.url}`).join('\n')}`;
    const blob = new Blob([txt], { type: 'text/plain' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob); a.download = `sentinelshield_report_${Date.now()}.txt`; a.click();
}