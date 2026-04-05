import { useState } from "react";
import Navbar from "./Navbar";
import RiskMeter from "./RiskMeter";
import ScanResults from "./ScanResults";

const SC = {
    CRITICAL: "#ff2d55",
    HIGH: "#ff9500",
    MEDIUM: "#ffd60a",
    LOW: "#30d158",
};

export default function Dashboard({
    onStartScan,
    isScanning,
    scanStatus,
    scanResults,
    error,
}) {
    const [activeFilter, setActiveFilter] = useState("ALL");

    const summary = scanResults?.summary || scanStatus?.summary || {};
    const findings = scanResults?.findings || [];
    const filtered =
        activeFilter === "ALL"
            ? findings
            : findings.filter(f => f.severity === activeFilter);

    return (
        <div className="dashboard">
            <Navbar />
            <main className="main-content">

                {/* Header */}
                <div className="header-row">
                    <div>
                        <h1 className="page-title">System Audit</h1>
                        <p className="page-subtitle">
                            Linux Privilege Escalation Detection
                        </p>
                    </div>
                    <button
                        className={`scan-btn ${isScanning ? "scanning" : ""}`}
                        onClick={onStartScan}
                        disabled={isScanning}
                    >
                        {isScanning ? (
                            <>
                                <span className="spinner" />
                                Scanning...
                            </>
                        ) : (
                            <>⚡ Start Scan</>
                        )}
                    </button>
                </div>

                {/* Progress */}
                {isScanning && scanStatus && (
                    <div className="scan-progress">
                        <div className="progress-bar-wrap">
                            <div className="progress-bar-fill" />
                        </div>
                        <p className="progress-label">
                            Module:{" "}
                            <strong>
                                {scanStatus.current_module || "Initializing..."}
                            </strong>
                        </p>
                    </div>
                )}

                {/* Error */}
                {error && (
                    <div className="error-banner">⚠️ {error}</div>
                )}

                {/* Warning */}
                <div className="edu-banner">
                    🛡️{" "}
                    <strong>
                        For authorized security auditing and educational use only.
                    </strong>{" "}
                    Do not run on systems you do not own.
                </div>

                {/* Stats */}
                <div className="stats-grid">
                    {[
                        { label: "Total Findings", value: summary.total ?? "—", color: "#e0e0e0" },
                        { label: "Critical", value: summary.critical ?? "—", color: SC.CRITICAL },
                        { label: "High", value: summary.high ?? "—", color: SC.HIGH },
                        { label: "Medium", value: summary.medium ?? "—", color: SC.MEDIUM },
                        { label: "Low", value: summary.low ?? "—", color: SC.LOW },
                    ].map(card => (
                        <div key={card.label} className="stat-card">
                            <div
                                className="stat-number"
                                style={{ color: card.color }}
                            >
                                {card.value}
                            </div>
                            <div className="stat-label">{card.label}</div>
                        </div>
                    ))}
                    <div className="stat-card risk-card">
                        <RiskMeter score={summary.risk_score || 0} />
                    </div>
                </div>

                {/* Findings */}
                {findings.length > 0 && (
                    <div className="findings-section">
                        <div className="findings-header">
                            <h2 className="section-title">Findings</h2>
                            <div className="filter-pills">
                                {["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"].map(s => (
                                    <button
                                        key={s}
                                        className={`filter-pill ${activeFilter === s ? "active" : ""
                                            }`}
                                        style={
                                            activeFilter === s && s !== "ALL"
                                                ? { borderColor: SC[s], color: SC[s] }
                                                : {}
                                        }
                                        onClick={() => setActiveFilter(s)}
                                    >
                                        {s}
                                    </button>
                                ))}
                            </div>
                        </div>
                        <ScanResults findings={filtered} />
                    </div>
                )}

                {scanResults && findings.length === 0 && (
                    <div className="no-findings">
                        ✅ No vulnerabilities detected!
                    </div>
                )}

            </main>
        </div>
    );
}