import { useCallback, useEffect, useState } from "react";
import "./App.css";
import Dashboard from "./components/Dashboard";

const API_BASE = "http://localhost:5000/api";

export default function App() {
    const [scanId, setScanId] = useState(null);
    const [scanStatus, setScanStatus] = useState(null);
    const [scanResults, setScanResults] = useState(null);
    const [isScanning, setIsScanning] = useState(false);
    const [error, setError] = useState(null);

    const startScan = useCallback(async () => {
        setIsScanning(true);
        setError(null);
        setScanResults(null);
        setScanStatus(null);
        try {
            const res = await fetch(`${API_BASE}/scan/start`, { method: "POST" });
            const data = await res.json();
            setScanId(data.scan_id);
        } catch {
            setError(
                "Could not connect to backend. " +
                "Is Flask running on port 5000?"
            );
            setIsScanning(false);
        }
    }, []);

    useEffect(() => {
        if (!scanId || !isScanning) return;
        const interval = setInterval(async () => {
            try {
                const sr = await fetch(`${API_BASE}/scan/status/${scanId}`);
                const sd = await sr.json();
                setScanStatus(sd);
                if (sd.status === "complete") {
                    setIsScanning(false);
                    const rr = await fetch(`${API_BASE}/scan/results/${scanId}`);
                    setScanResults(await rr.json());
                }
            } catch {
                setError("Lost connection during scan.");
                setIsScanning(false);
            }
        }, 1500);
        return () => clearInterval(interval);
    }, [scanId, isScanning]);

    return (
        <div className="app">
            <Dashboard
                onStartScan={startScan}
                isScanning={isScanning}
                scanStatus={scanStatus}
                scanResults={scanResults}
                error={error}
            />
        </div>
    );
}