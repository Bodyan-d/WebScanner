import React, { useState } from "react";
import ScanForm from "./components/ScanForm";
import Results from "./components/Results";

export default function App() {
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  return (
    <div className="container">
      <header className="header">
        <h1>WebScanner — Dashboard</h1>
        <p className="subtitle">Fast scans (ports, headers, XSS, SQLi) + optional sqlmap</p>
      </header>

      <main>
        <ScanForm
          onStart={() => {
            setReport(null);
            setError(null);
            setLoading(true);
          }}
          onDone={(res) => {
            setReport(res);
            setLoading(false);
          }}
          onError={(err) => {
            setError(err);
            setLoading(false);
          }}
        />

        {loading && <div className="notify">Scan running — this may take a minute...</div>}
        {error && <div className="error">Error: {String(error)}</div>}

        {report && (
          <section style={{ marginTop: 20 }}>
            <Results parts={report.parts} report={report.report} />
          </section>
        )}
      </main>

      <footer className="footer">
        <small>Tip: for docker setups use host.docker.internal as target host for container-to-host access.</small>
      </footer>
    </div>
  );
}
