export default function Navbar() {
    return (
        <nav className="navbar">
            <div className="nav-brand">
                <span className="nav-icon">🔍</span>
                <span className="nav-title">PrivEsc Toolkit</span>
                <span className="nav-badge">DETECTION ONLY</span>
            </div>
            <div className="nav-links">
                <a href="#" className="nav-link active">Dashboard</a>

                href="http://localhost:5000/api/scan/list"
                target="_blank"
                rel="noreferrer"
                className="nav-link" >
                API
            </a>
        </div>
    </nav >
  );
}