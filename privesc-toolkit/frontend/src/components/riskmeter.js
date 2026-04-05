function getRiskLabel(score) {
    if (score === 0) return { label: "No Scan", color: "#30d158" };
    if (score < 25) return { label: "Low Risk", color: "#30d158" };
    if (score < 50) return { label: "Medium Risk", color: "#ffd60a" };
    if (score < 75) return { label: "High Risk", color: "#ff9500" };
    return { label: "Critical", color: "#ff2d55" };
}

export default function RiskMeter({ score }) {
    const { label, color } = getRiskLabel(score);
    const circ = 2 * Math.PI * 45;
    const offset = circ - (score / 100) * circ;

    return (
        <div className="risk-meter">
            <svg width="100" height="100" viewBox="0 0 100 100">
                <circle
                    cx="50" cy="50" r="45"
                    fill="none" stroke="#1e1e2e" strokeWidth="8"
                />
                <circle
                    cx="50" cy="50" r="45"
                    fill="none"
                    stroke={color}
                    strokeWidth="8"
                    strokeLinecap="round"
                    strokeDasharray={circ}
                    strokeDashoffset={offset}
                    transform="rotate(-90 50 50)"
                    style={{
                        transition: "stroke-dashoffset 1s ease, stroke 0.5s ease"
                    }}
                />
                <text
                    x="50" y="46"
                    textAnchor="middle"
                    fill={color}
                    fontSize="18"
                    fontWeight="bold"
                    fontFamily="monospace"
                >
                    {score}
                </text>
                <text
                    x="50" y="60"
                    textAnchor="middle"
                    fill="#666"
                    fontSize="8"
                    fontFamily="monospace"
                >
                    /100
                </text>
            </svg>
            <p className="risk-label" style={{ color }}>{label}</p>
        </div>
    );
}