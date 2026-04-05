/* ============================================================================
   dashboard.js — Threat Intelligence Aggregator — Frontend Logic
   ============================================================================
   Responsibilities:
     • Poll /api/stats every N seconds and update stat cards
     • Load and render IOC table from /api/iocs with pagination
     • Live search (debounced) via /api/search
     • Severity + Type filter dropdowns
     • "Run Pipeline" button trigger
     • Live clock
   ============================================================================ */

"use strict";

/* ── Constants ────────────────────────────────────────────────────────────── */
const REFRESH_INTERVAL_MS = (window._refreshInterval || 30) * 1000;
const PER_PAGE            = 50;

/* ── State ────────────────────────────────────────────────────────────────── */
let currentPage     = 1;
let searchDebounce  = null;

/* ── DOM refs ─────────────────────────────────────────────────────────────── */
const $ = id => document.getElementById(id);

const statTotal     = $("statTotal");
const statHigh      = $("statHigh");
const statMedium    = $("statMedium");
const statLow       = $("statLow");
const statRepeated  = $("statRepeated");
const lastUpdated   = $("lastUpdated");
const sourceList    = $("sourceList");
const breakdownBars = $("breakdownBars");
const iocTbody      = $("iocTbody");
const pagination    = $("pagination");
const searchInput   = $("searchInput");
const filterSev     = $("filterSeverity");
const filterType    = $("filterType");
const btnRun        = $("btnRunPipeline");
const toast         = $("toast");
const footerClock   = $("footerClock");

/* ── Utilities ────────────────────────────────────────────────────────────── */

function showToast(msg, type = "ok") {
  toast.textContent = msg;
  toast.className   = `toast show ${type}`;
  setTimeout(() => { toast.className = "toast"; }, 3500);
}

function fmtDate(iso) {
  if (!iso) return "—";
  try {
    const d = new Date(iso);
    return d.toISOString().replace("T", " ").slice(0, 19) + " UTC";
  } catch { return iso; }
}

function animateNumber(el, target) {
  const start = parseInt(el.textContent) || 0;
  if (start === target) return;
  const step  = Math.ceil(Math.abs(target - start) / 20);
  const dir   = target > start ? 1 : -1;
  let   cur   = start;
  const timer = setInterval(() => {
    cur += dir * step;
    if ((dir > 0 && cur >= target) || (dir < 0 && cur <= target)) {
      cur = target;
      clearInterval(timer);
    }
    el.textContent = cur.toLocaleString();
  }, 30);
}

function severityBadge(sev) {
  return `<span class="badge badge-${sev}">${sev}</span>`;
}

function typeChip(t) {
  return `<span class="chip chip-${t}">${t.toUpperCase()}</span>`;
}

/* ── Stats refresh ────────────────────────────────────────────────────────── */

async function refreshStats() {
  try {
    const res  = await fetch("/api/stats");
    if (!res.ok) return;
    const data = await res.json();

    animateNumber(statTotal,    data.total    || 0);
    animateNumber(statHigh,     data.high     || 0);
    animateNumber(statMedium,   data.medium   || 0);
    animateNumber(statLow,      data.low      || 0);
    animateNumber(statRepeated, data.repeated || 0);

    if (data.generated) {
      lastUpdated.textContent = "Updated: " + fmtDate(data.generated);
    }

    // Sources
    if (data.sources && data.sources.length) {
      sourceList.innerHTML = data.sources.map(s =>
        `<li class="source-item"><span class="src-dot"></span>${s}</li>`
      ).join("");
    }

    // Breakdown bars
    if (data.breakdown && Object.keys(data.breakdown).length) {
      const total = data.total || 1;
      breakdownBars.innerHTML = Object.entries(data.breakdown).map(([type, cnt]) => {
        const pct = Math.max(2, ((cnt / total) * 100).toFixed(1));
        return `
          <div class="bar-row">
            <span class="bar-label">${type.toUpperCase()}</span>
            <div class="bar-track">
              <div class="bar-fill bar-${type}" style="width:${pct}%"></div>
            </div>
            <span class="bar-count">${cnt}</span>
          </div>`;
      }).join("");
    }

  } catch (e) {
    console.warn("Stats refresh error:", e);
  }
}

/* ── IOC table ────────────────────────────────────────────────────────────── */

async function loadIOCs(page = 1) {
  currentPage = page;

  const q    = searchInput.value.trim();
  const sev  = filterSev.value;
  const type = filterType.value;

  const params = new URLSearchParams({
    page,
    per_page: PER_PAGE,
    ...(q    ? { q }           : {}),
    ...(sev  ? { severity: sev } : {}),
    ...(type ? { type }        : {}),
  });

  iocTbody.innerHTML = `<tr><td colspan="6" class="loading-row">Loading…</td></tr>`;
  pagination.innerHTML = "";

  try {
    const res  = await fetch(`/api/iocs?${params}`);
    const data = await res.json();
    renderTable(data.iocs || []);
    renderPagination(data.page, data.pages, data.total);
  } catch (e) {
    iocTbody.innerHTML = `<tr><td colspan="6" class="loading-row">Error loading data.</td></tr>`;
    console.error("IOC load error:", e);
  }
}

function renderTable(iocs) {
  if (!iocs.length) {
    iocTbody.innerHTML = `<tr><td colspan="6" class="loading-row">No indicators match the current filter.</td></tr>`;
    return;
  }

  iocTbody.innerHTML = iocs.map(ioc => `
    <tr>
      <td>${severityBadge(ioc.severity)}</td>
      <td>${typeChip(ioc.type)}</td>
      <td><div class="ioc-value" title="${ioc.value}">${ioc.value}</div></td>
      <td><div class="sources-cell" title="${(ioc.sources||[]).join(', ')}">${(ioc.sources||[]).join(', ')}</div></td>
      <td class="count-cell">${ioc.count}</td>
      <td class="date-cell">${fmtDate(ioc.first_seen)}</td>
    </tr>
  `).join("");
}

function renderPagination(page, pages, total) {
  if (pages <= 1) {
    pagination.innerHTML = `<span class="page-info">${total} indicators</span>`;
    return;
  }

  let html = `<span class="page-info">${total} indicators | Page ${page} of ${pages}</span>`;

  // Prev
  if (page > 1) {
    html += `<button class="page-btn" onclick="loadIOCs(${page-1})">‹ Prev</button>`;
  }

  // Page numbers (window of 5)
  const start = Math.max(1, page - 2);
  const end   = Math.min(pages, page + 2);
  for (let p = start; p <= end; p++) {
    html += `<button class="page-btn${p===page?' active':''}" onclick="loadIOCs(${p})">${p}</button>`;
  }

  // Next
  if (page < pages) {
    html += `<button class="page-btn" onclick="loadIOCs(${page+1})">Next ›</button>`;
  }

  pagination.innerHTML = html;
}

/* ── Search (debounced) ───────────────────────────────────────────────────── */
searchInput.addEventListener("input", () => {
  clearTimeout(searchDebounce);
  searchDebounce = setTimeout(() => loadIOCs(1), 320);
});

/* ── Filters ──────────────────────────────────────────────────────────────── */
filterSev.addEventListener("change",  () => loadIOCs(1));
filterType.addEventListener("change", () => loadIOCs(1));

/* ── Run Pipeline button ──────────────────────────────────────────────────── */
btnRun.addEventListener("click", async () => {
  btnRun.classList.add("running");
  btnRun.textContent = "⟳ RUNNING…";
  btnRun.disabled    = true;

  try {
    const res  = await fetch("/api/run-pipeline", { method: "POST" });
    const data = await res.json();
    if (data.status === "ok") {
      showToast("✓ Pipeline complete!", "ok");
      await refreshStats();
      loadIOCs(1);
    } else {
      showToast("✗ Pipeline error: " + (data.message || "unknown"), "err");
    }
  } catch (e) {
    showToast("✗ Network error", "err");
  } finally {
    btnRun.classList.remove("running");
    btnRun.textContent = "⟳ RUN PIPELINE";
    btnRun.disabled    = false;
  }
});

/* ── Live clock ───────────────────────────────────────────────────────────── */
function updateClock() {
  footerClock.textContent = new Date().toUTCString().replace("GMT", "UTC");
}
updateClock();
setInterval(updateClock, 1000);

/* ── Auto-refresh loop ────────────────────────────────────────────────────── */
async function fullRefresh() {
  await refreshStats();
  await loadIOCs(currentPage);
}

setInterval(fullRefresh, REFRESH_INTERVAL_MS);

/* ── Initial load ─────────────────────────────────────────────────────────── */
(async function init() {
  await refreshStats();
  await loadIOCs(1);
})();
