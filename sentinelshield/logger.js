// =============================================
//  SENTINELSHIELD v2.0 — LOGGER.JS
// =============================================

const Logger = (() => {
    let logs = [];
    let rowNum = 0;

    function ts() { return new Date().toTimeString().slice(0, 8); }

    function addLog(entry) {
        rowNum++;
        const log = { ...entry, time: ts(), num: rowNum };
        logs.unshift(log);
        if (logs.length > 500) logs.pop();
        renderRow(log);
        updateFooter();
        return log;
    }

    function renderRow(log) {
        const table = document.getElementById('logTable');
        if (!table) return;
        const row = document.createElement('div');
        row.className = `log-row ${log.status}`;
        row.dataset.status = log.status;
        row.dataset.cat = (log.category || '').toLowerCase();
        row.dataset.raw = `${log.ip} ${log.url} ${log.category}`.toLowerCase();
        row.innerHTML = `
      <span class="lr-num">${log.num}</span>
      <span class="lr-time">${log.time}</span>
      <span class="lr-ip">${log.ip}</span>
      <span class="lr-meth">${log.method}</span>
      <span class="lr-stat">${log.status.toUpperCase()}</span>
      <span class="lr-cat">${log.category || '—'}</span>
      <span class="lr-url">${escHtml(log.url)}</span>
      <span class="lr-body">${escHtml((log.body || '').slice(0, 40))}</span>
    `;
        table.prepend(row);
        while (table.children.length > 200) table.removeChild(table.lastChild);
    }

    function escHtml(s) {
        return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }

    function filterLogs() {
        const status = document.getElementById('logFilter').value;
        const cat = document.getElementById('logCatFilter').value;
        const q = document.getElementById('logSearch').value.toLowerCase();
        const rows = document.querySelectorAll('.log-row');
        let vis = 0;
        rows.forEach(r => {
            const matchStatus = status === 'all' || r.dataset.status === status;
            const matchCat = cat === 'all' || r.dataset.cat.includes(cat);
            const matchQ = !q || r.dataset.raw.includes(q);
            r.style.display = (matchStatus && matchCat && matchQ) ? '' : 'none';
            if (matchStatus && matchCat && matchQ) vis++;
        });
        updateFooter(vis);
    }

    function updateFooter(count) {
        const f = document.getElementById('logFooter');
        if (f) f.textContent = `${count !== undefined ? count : logs.length} events displayed · ${logs.length} total`;
    }

    function clearLogs() {
        logs = []; rowNum = 0;
        const t = document.getElementById('logTable');
        if (t) t.innerHTML = '';
        updateFooter(0);
    }

    function exportLogs() {
        const header = 'NUM,TIME,IP,METHOD,STATUS,CATEGORY,URL,BODY\n';
        const rows = logs.map(l =>
            `${l.num},"${l.time}","${l.ip}","${l.method}","${l.status}","${l.category || ''}","${l.url}","${(l.body || '').replace(/"/g, "'")}"`
        ).join('\n');
        const blob = new Blob([header + rows], { type: 'text/csv' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = `sentinelshield_log_${Date.now()}.csv`;
        a.click();
    }

    function getLogs() { return logs; }
    function getCount() { return logs.length; }

    return { addLog, filterLogs, clearLogs, exportLogs, getLogs, getCount };
})();