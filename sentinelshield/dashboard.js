// =============================================
//  SENTINELSHIELD v2.0 — DASHBOARD.JS
//  Radar + Timeline + Gauge + Charts
// =============================================

const Dashboard = (() => {

    const stats = {
        total: 0, blocked: 0, allowed: 0, rateLimited: 0,
        categories: {}, ips: {},
        timeline: new Array(40).fill(0).map(() => ({ blocked: 0, allowed: 0 }))
    };

    let radarAngle = 0;
    let radarDots = [];
    let timelineCtx, radarCtx, gaugeCtx;

    /* ── INIT CANVASES ── */
    function init() {
        const tc = document.getElementById('timelineCanvas');
        const rc = document.getElementById('radarCanvas');
        const gc = document.getElementById('gaugeCanvas');
        if (tc) timelineCtx = tc.getContext('2d');
        if (rc) { radarCtx = rc.getContext('2d'); animateRadar(); }
        if (gc) gaugeCtx = gc.getContext('2d');
        drawTimeline();
        drawGauge(0);
        renderBreakdown();
        renderIPLeader();
    }

    /* ── UPDATE ON NEW REQUEST ── */
    function update(req, result) {
        stats.total++;
        if (result.status === 'allowed') stats.allowed++;
        else if (result.status === 'ratelimit') { stats.blocked++; stats.rateLimited++; }
        else stats.blocked++;

        result.categories.forEach(cat => {
            if (!stats.categories[cat.key])
                stats.categories[cat.key] = { label: cat.name || cat.category || cat.key, color: cat.color, count: 0 };
            stats.categories[cat.key].count++;
        });

        if (!stats.ips[req.ip]) stats.ips[req.ip] = { count: 0, blocked: 0 };
        stats.ips[req.ip].count++;
        if (result.status !== 'allowed') stats.ips[req.ip].blocked++;

        // Timeline rolling window
        stats.timeline.shift();
        stats.timeline.push({
            blocked: result.status !== 'allowed' ? 1 : 0,
            allowed: result.status === 'allowed' ? 1 : 0
        });

        // Radar dot
        if (result.status !== 'allowed') {
            radarDots.push({ angle: Math.random() * Math.PI * 2, dist: 0.3 + Math.random() * 0.6, life: 1, key: result.categories[0]?.key || 'cmd' });
        }

        updateCards();
        drawTimeline();
        drawGauge(stats.total ? Math.round((stats.blocked / stats.total) * 100) : 0);
        renderBreakdown();
        renderIPLeader();
        updateThreatLevel();
        updateThreatFeed(req, result);
    }

    function updateCards() {
        const rateLimIPs = Object.values(stats.ips).filter(v => v.count > 10).length;
        setText('hs-total', stats.total);
        setText('hs-blocked', stats.blocked);
        setText('hs-allowed', stats.allowed);
        setText('hs-rate', stats.rateLimited);
        setText('hs-ips', Object.keys(stats.ips).length);
        setText('hs-rules', WAF.getAllRules().filter(r => r.enabled).length);
    }
    function setText(id, v) { const el = document.getElementById(id); if (el) el.textContent = v; }

    /* ── TIMELINE CANVAS ── */
    function drawTimeline() {
        const cv = document.getElementById('timelineCanvas');
        if (!cv || !timelineCtx) return;
        const ctx = timelineCtx;
        const W = cv.width, H = cv.height;
        ctx.clearRect(0, 0, W, H);

        const BAR = Math.floor(W / stats.timeline.length) - 2;
        const maxVal = Math.max(...stats.timeline.map(t => t.blocked + t.allowed), 1);

        // Grid lines
        ctx.strokeStyle = 'rgba(26,40,64,0.8)'; ctx.lineWidth = 1;
        for (let i = 0; i < 4; i++) {
            const y = H * (i / 4);
            ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(W, y); ctx.stroke();
        }

        stats.timeline.forEach((t, i) => {
            const x = i * (BAR + 2) + 1;
            const bH = Math.round((t.blocked / maxVal) * (H - 4));
            const aH = Math.round((t.allowed / maxVal) * (H - 4));

            if (aH > 0) {
                ctx.fillStyle = 'rgba(0,255,159,0.5)';
                ctx.fillRect(x, H - aH, BAR, aH);
            }
            if (bH > 0) {
                ctx.fillStyle = 'rgba(255,45,85,0.75)';
                ctx.fillRect(x, H - bH, BAR, bH);
                // glow cap
                ctx.fillStyle = 'rgba(255,45,85,0.9)';
                ctx.fillRect(x, H - bH, BAR, 2);
            }
        });

        // Legend
        ctx.font = '10px JetBrains Mono';
        ctx.fillStyle = 'rgba(0,255,159,0.8)'; ctx.fillRect(6, 6, 8, 8);
        ctx.fillStyle = '#6a8aaa'; ctx.fillText('Allowed', 18, 15);
        ctx.fillStyle = 'rgba(255,45,85,0.8)'; ctx.fillRect(72, 6, 8, 8);
        ctx.fillStyle = '#6a8aaa'; ctx.fillText('Blocked', 84, 15);
    }

    /* ── RADAR CANVAS ── */
    const CAT_COLORS = { sqli: '#ff6b35', xss: '#9b59ff', lfi: '#ffcc00', cmd: '#ff2d55', traversal: '#00e5c0', xxe: '#00d4ff', ssrf: '#ff8ac4', scanner: '#88ee44' };

    function animateRadar() {
        const cv = document.getElementById('radarCanvas');
        if (!cv || !radarCtx) return;
        const ctx = radarCtx;
        const W = cv.width, H = cv.height, CX = W / 2, CY = H / 2, R = CX - 10;

        ctx.clearRect(0, 0, W, H);

        // Rings
        for (let i = 1; i <= 4; i++) {
            ctx.beginPath(); ctx.arc(CX, CY, R * (i / 4), 0, Math.PI * 2);
            ctx.strokeStyle = `rgba(26,40,64,${0.4 + i * 0.1})`; ctx.lineWidth = 1; ctx.stroke();
        }

        // Cross hairs
        ctx.strokeStyle = 'rgba(26,40,64,0.5)'; ctx.lineWidth = 1;
        ctx.beginPath(); ctx.moveTo(CX - R, CY); ctx.lineTo(CX + R, CY); ctx.stroke();
        ctx.beginPath(); ctx.moveTo(CX, CY - R); ctx.lineTo(CX, CY + R); ctx.stroke();

        // Sweep
        const sweep = ctx.createConicalGradient ? null : null;
        const sx = CX + Math.cos(radarAngle) * R, sy = CY + Math.sin(radarAngle) * R;
        const grad = ctx.createLinearGradient(CX, CY, sx, sy);
        grad.addColorStop(0, 'rgba(0,212,255,0.3)');
        grad.addColorStop(1, 'rgba(0,212,255,0)');
        ctx.beginPath();
        ctx.moveTo(CX, CY);
        ctx.arc(CX, CY, R, radarAngle - 0.5, radarAngle);
        ctx.lineTo(CX, CY);
        ctx.fillStyle = 'rgba(0,212,255,0.1)'; ctx.fill();
        // sweep line
        ctx.beginPath();
        ctx.moveTo(CX, CY);
        ctx.lineTo(CX + Math.cos(radarAngle) * R, CY + Math.sin(radarAngle) * R);
        ctx.strokeStyle = 'rgba(0,212,255,0.7)'; ctx.lineWidth = 1.5; ctx.stroke();

        radarAngle += 0.03;

        // Threat dots
        radarDots = radarDots.filter(d => d.life > 0.02);
        radarDots.forEach(d => {
            const x = CX + Math.cos(d.angle) * d.dist * R;
            const y = CY + Math.sin(d.angle) * d.dist * R;
            const col = CAT_COLORS[d.key] || '#ff2d55';
            ctx.beginPath(); ctx.arc(x, y, 3, 0, Math.PI * 2);
            ctx.fillStyle = col; ctx.fill();
            ctx.beginPath(); ctx.arc(x, y, 5 + d.life * 4, 0, Math.PI * 2);
            ctx.strokeStyle = col.replace(')', `,${d.life * 0.4})`).replace('rgb', 'rgba');
            ctx.lineWidth = 1; ctx.stroke();
            d.life -= 0.005;
        });

        // Center dot
        ctx.beginPath(); ctx.arc(CX, CY, 4, 0, Math.PI * 2);
        ctx.fillStyle = '#00d4ff'; ctx.fill();
        ctx.beginPath(); ctx.arc(CX, CY, 8, 0, Math.PI * 2);
        ctx.strokeStyle = 'rgba(0,212,255,0.4)'; ctx.lineWidth = 1; ctx.stroke();

        requestAnimationFrame(animateRadar);
    }

    /* ── GAUGE CANVAS ── */
    function drawGauge(pct) {
        const cv = document.getElementById('gaugeCanvas');
        if (!cv || !gaugeCtx) return;
        const ctx = gaugeCtx;
        const W = cv.width, H = cv.height, CX = W / 2, CY = H - 10, R = Math.min(W, H * 2) / 2 - 10;
        ctx.clearRect(0, 0, W, H);

        // Background arc
        ctx.beginPath(); ctx.arc(CX, CY, R, Math.PI, 0);
        ctx.strokeStyle = 'rgba(26,40,64,0.8)'; ctx.lineWidth = 12; ctx.lineCap = 'round'; ctx.stroke();

        // Value arc
        const angle = Math.PI + (pct / 100) * Math.PI;
        const col = pct < 30 ? '#00ff9f' : pct < 60 ? '#ffcc00' : pct < 80 ? '#ff6b35' : '#ff2d55';
        ctx.beginPath(); ctx.arc(CX, CY, R, Math.PI, angle);
        ctx.strokeStyle = col; ctx.lineWidth = 12; ctx.lineCap = 'round'; ctx.stroke();

        // Glow
        ctx.shadowColor = col; ctx.shadowBlur = 12;
        ctx.beginPath(); ctx.arc(CX, CY, R, Math.PI, angle);
        ctx.strokeStyle = col; ctx.lineWidth = 2; ctx.stroke();
        ctx.shadowBlur = 0;

        const gv = document.getElementById('gaugeVal');
        if (gv) { gv.textContent = pct + '%'; gv.style.color = col; }
    }

    /* ── BREAKDOWN ── */
    function renderBreakdown() {
        const el = document.getElementById('breakdownChart');
        if (!el) return;
        const cats = Object.values(stats.categories);
        if (!cats.length) { el.innerHTML = '<div style="color:var(--muted);font-size:0.7rem;text-align:center;padding:10px">No attacks yet</div>'; return; }
        const max = Math.max(...cats.map(c => c.count));
        el.innerHTML = cats.map(c => `
      <div class="br-row">
        <div class="br-label">${c.label.replace(/\(.*\)/, '').replace(/[–—].*/, '').trim()}</div>
        <div class="br-track"><div class="br-fill" style="width:${max > 0 ? (c.count / max * 100) : 0}%;background:${c.color}"></div></div>
        <div class="br-count">${c.count}</div>
      </div>`).join('');
    }

    /* ── IP LEADERBOARD ── */
    function renderIPLeader() {
        const el = document.getElementById('ipLeaderboard');
        if (!el) return;
        const sorted = Object.entries(stats.ips).sort((a, b) => b[1].blocked - a[1].blocked).slice(0, 6);
        if (!sorted.length) { el.innerHTML = '<div style="color:var(--muted);font-size:0.7rem;text-align:center;padding:10px">No data yet</div>'; return; }
        el.innerHTML = sorted.map(([ip, d], i) => {
            const badge = d.blocked > 5 ? 'crit' : d.blocked > 2 ? 'high' : 'med';
            const label = d.blocked > 5 ? 'CRITICAL' : d.blocked > 2 ? 'HIGH' : 'MEDIUM';
            return `<div class="ip-row">
        <span class="ip-rank">#${i + 1}</span>
        <span class="ip-addr">${ip}</span>
        <span class="ip-blocks">${d.blocked} blocked</span>
        <span class="ip-badge ${badge}">${label}</span>
      </div>`;
        }).join('');
    }

    /* ── THREAT LEVEL ── */
    function updateThreatLevel() {
        const rate = stats.total ? stats.blocked / stats.total : 0;
        let level = 1, label = 'LOW', cls = '';
        if (rate > 0.1) { level = 2; }
        if (rate > 0.3) { level = 3; label = 'MEDIUM'; cls = 'high'; }
        if (rate > 0.5) { level = 4; label = 'HIGH'; cls = 'high'; }
        if (rate > 0.7) { level = 5; label = 'CRITICAL'; cls = 'critical'; }

        const classes = ['on1', 'on2', 'on3', 'on4', 'on5'];
        for (let i = 1; i <= 5; i++) {
            const b = document.getElementById('tmb' + i);
            if (b) { b.className = 'tm-bar' + (i <= level ? ' ' + classes[i - 1] : ''); }
        }
        const tt = document.getElementById('tmText'); if (tt) tt.textContent = label;
        const rl = document.getElementById('radarLabel'); if (rl) { rl.textContent = label; rl.style.color = level >= 4 ? 'var(--red)' : level >= 3 ? 'var(--yellow)' : 'var(--green)'; }
        const tb = document.getElementById('threatBadge');
        if (tb) { tb.textContent = 'THREAT: ' + label; tb.className = 'threat-badge' + (cls ? ' ' + cls : ''); }
    }

    /* ── THREAT FEED ── */
    function updateThreatFeed(req, result) {
        if (result.status === 'allowed') return;
        const feed = document.getElementById('threatFeed');
        if (!feed) return;
        const type = result.categories[0]?.key?.toUpperCase() || 'RATE-LIMIT';
        const el = document.createElement('div');
        el.className = 'tf-item';
        el.innerHTML = `
        <span class="tf-time">${new Date().toTimeString().slice(0, 8)}</span>
        <span class="tf-ip">${req.ip}</span>
        <span class="tf-type">${type}</span>
        <span class="tf-url">${req.url}</span>
    `;
        feed.prepend(el);
        while (feed.children.length > 20) feed.removeChild(feed.lastChild);
    }

    function getStats() { return stats; }

    return { init, update, getStats };
})();