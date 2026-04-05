"""
Report Generator
Generates JSON and styled HTML reports from scan results.
FOR EDUCATIONAL AND AUTHORIZED USE ONLY.
"""

import json
import os
from datetime import datetime
from typing import Dict

SEVERITY_COLORS = {
    "CRITICAL": "#ff2d55",
    "HIGH":     "#ff9500",
    "MEDIUM":   "#ffd60a",
    "LOW":      "#30d158",
}

REPORTS_DIR = os.path.join(
    os.path.dirname(__file__), "../../reports"
)


class ReportGenerator:
    def __init__(self, scan_id: str, scan_data: Dict):
        self.scan_id = scan_id
        self.scan_data = scan_data
        os.makedirs(REPORTS_DIR, exist_ok=True)

    def generate_json(self) -> str:
        path = os.path.join(REPORTS_DIR, f"scan_{self.scan_id}.json")
        with open(path, "w") as f:
            json.dump(
                {
                    "scan_id": self.scan_id,
                    "generated_at": datetime.utcnow().isoformat(),
                    "summary": self.scan_data.get("summary", {}),
                    "findings": self.scan_data.get("findings", []),
                },
                f,
                indent=2,
            )
        return path

    def generate_html(self) -> str:
        path = os.path.join(REPORTS_DIR, f"scan_{self.scan_id}.html")
        findings = self.scan_data.get("findings", [])
        summary = self.scan_data.get("summary", {})
        generated = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        risk_score = summary.get("risk_score", 0)
        risk_color = (
            "#30d158" if risk_score < 30
            else "#ff9500" if risk_score < 70
            else "#ff2d55"
        )

        findings_html = ""
        for f in findings:
            sev = f.get("severity", "LOW")
            color = SEVERITY_COLORS.get(sev, "#888")
            tc = "#000" if sev == "MEDIUM" else "#fff"
            findings_html += f"""
        <div class="finding">
          <div class="finding-header" style="border-left:4px solid {color};">
            <span class="badge" style="background:{color};color:{tc}">{sev}</span>
            <strong>{f.get('title', '')}</strong>
            <span class="module-tag">{f.get('module', '')}</span>
          </div>
          <div class="finding-body">
            <p><strong>Description:</strong> {f.get('description', '')}</p>
            <p><strong>Path:</strong> <code>{f.get('path', 'N/A')}</code></p>
            <p><strong>Exploitable:</strong>
              {'⚠️ Yes' if f.get('exploitation_possible') else '✅ No'}</p>
            <p><strong>Mitigation:</strong>
              <code>{f.get('mitigation', 'Review manually')}</code></p>
          </div>
        </div>"""

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>PrivEsc Report — {self.scan_id}</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:'Courier New',monospace;background:#0a0a0f;
       color:#e0e0e0;padding:2rem}}
  h1{{color:#00ff88;font-size:1.8rem;margin-bottom:.3rem}}
  .subtitle{{color:#666;margin-bottom:2rem;font-size:.85rem}}
  .grid{{display:grid;
         grid-template-columns:repeat(auto-fit,minmax(150px,1fr));
         gap:1rem;margin-bottom:2rem}}
  .card{{background:#13131a;border:1px solid #222;border-radius:8px;
         padding:1rem;text-align:center}}
  .card .n{{font-size:2rem;font-weight:bold}}
  .card .l{{font-size:.75rem;color:#888;margin-top:.3rem}}
  .finding{{background:#13131a;border:1px solid #222;
            border-radius:8px;margin-bottom:1rem;overflow:hidden}}
  .finding-header{{padding:.8rem 1rem;display:flex;align-items:center;
                   gap:.7rem;background:#0e0e18}}
  .finding-body{{padding:1rem;font-size:.88rem;line-height:1.7}}
  .finding-body p{{margin-bottom:.4rem}}
  code{{background:#1e1e2e;padding:.1rem .4rem;border-radius:3px;
        color:#7dd3fc;font-size:.82rem}}
  .badge{{padding:.2rem .6rem;border-radius:4px;
          font-weight:bold;font-size:.75rem}}
  .module-tag{{font-size:.75rem;color:#888;margin-left:auto}}
  .warning{{background:#2d1a00;border:1px solid #ff9500;border-radius:8px;
            padding:1rem;margin-bottom:2rem;color:#ff9500;font-size:.85rem}}
  .risk-bg{{background:#1a1a2e;border-radius:4px;height:16px;overflow:hidden}}
  .risk-fill{{height:100%;border-radius:4px;
              background:{risk_color};width:{risk_score}%}}
</style>
</head>
<body>
<h1>🔍 Linux PrivEsc Toolkit Report</h1>
<p class="subtitle">
  Scan ID: {self.scan_id} | Generated: {generated}
</p>
<div class="warning">
  ⚠️ For educational and authorized security auditing purposes only.
</div>
<div class="grid">
  <div class="card">
    <div class="n" style="color:#e0e0e0">{summary.get('total', 0)}</div>
    <div class="l">Total</div>
  </div>
  <div class="card">
    <div class="n" style="color:#ff2d55">{summary.get('critical', 0)}</div>
    <div class="l">Critical</div>
  </div>
  <div class="card">
    <div class="n" style="color:#ff9500">{summary.get('high', 0)}</div>
    <div class="l">High</div>
  </div>
  <div class="card">
    <div class="n" style="color:#ffd60a">{summary.get('medium', 0)}</div>
    <div class="l">Medium</div>
  </div>
  <div class="card">
    <div class="n" style="color:#30d158">{summary.get('low', 0)}</div>
    <div class="l">Low</div>
  </div>
  <div class="card">
    <div class="n" style="color:{risk_color}">{risk_score}</div>
    <div class="l">Risk Score</div>
  </div>
</div>
<div style="margin-bottom:2rem">
  <p style="color:#888;font-size:.8rem;margin-bottom:.4rem">
    Overall Risk
  </p>
  <div class="risk-bg"><div class="risk-fill"></div></div>
</div>
<h2 style="color:#00ff88;margin-bottom:1rem">
  Findings ({len(findings)})
</h2>
{findings_html or '<p style="color:#666">No findings.</p>'}
</body>
</html>"""

        with open(path, "w") as f:
            f.write(html)
        return path
