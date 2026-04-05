import { useState } from "react";

const SC = {
    CRITICAL: "#ff2d55",
    HIGH: "#ff9500",
    MEDIUM: "#ffd60a",
    LOW: "#30d158",
};
const ST = {
    CRITICAL: "#fff",
    HIGH: "#fff",
    MEDIUM: "#000",
    LOW: "#fff",
};

function FindingRow({ finding }) {
    const [open, setOpen] = useState(false);
    const sev = finding.severity || "LOW";
    const bg = SC[sev] || "#888";
    const tc = ST[sev] || "#fff";

    return (
        <div className="finding-row">
            <div className="finding-main" onClick={() => setOpen(!open)}>
                <div className="finding-left">
                    <span
                        className="sev-badge"
                        style={{ background: bg, color: tc }}
                    >
                        {sev}
                    </span>
                    <span className="finding-title">{finding.title}</span>
                </div>
                <div className="finding-right">
                    <span className="module-chip">{finding.module}</span>
                    {finding.exploitation_possible && (
                        <span className="exploit-chip">⚠️ Exploitable</span>
                    )}
                    <span className="expand-icon">{open ? "▾" : "▸"}</span>
                </div>
            </div>

            {open && (
                <div className="finding-detail">
                    <div>
                        <span className="detail-label">Description</span>
                        <p className="detail-text">{finding.description}</p>
                    </div>
                    {finding.path && (
                        <div>
                            <span className="detail-label">Path</span>
                            <code className="detail-code">{finding.path}</code>
                        </div>
                    )}
                    {finding.cve && (
                        <div>
                            <span className="detail-label">CVE</span>

                            href={`https://nvd.nist.gov/vuln/detail/${finding.cve}`}
                            target="_blank"
                            rel="noreferrer"
                            className="cve-link"
              >
                            {finding.cve} ↗
                        </a>
            </div>
            )}
            <div>
                <span className="detail-label">Mitigation</span>
                <code className="detail-code mitigation">
                    {finding.mitigation}
                </code>
            </div>
        </div>
    )
}
    </div >
  );
}

export default function ScanResults({ findings }) {
    if (!findings?.length) {
        return (
            <p className="empty-state">No findings match this filter.</p>
        );
    }

    const groups = findings.reduce((acc, f) => {
        const m = f.module || "Other";
        if (!acc[m]) acc[m] = [];
        acc[m].push(f);
        return acc;
    }, {});

    return (
        <div className="results-container">
            {Object.entries(groups).map(([mod, items]) => (
                <div key={mod} className="module-group">
                    <div className="module-group-header">
                        <span className="module-name">{mod}</span>
                        <span className="module-count">
                            {items.length} finding{items.length !== 1 ? "s" : ""}
                        </span>
                    </div>
                    <div className="module-findings">
                        {items.map((f, i) => (
                            <FindingRow key={i} finding={f} />
                        ))}
                    </div>
                </div>
            ))}
        </div>
    );
}