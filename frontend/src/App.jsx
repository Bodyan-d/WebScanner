import React, { useState } from "react";
import ScanForm from "./components/ScanForm";
import Results from "./components/Results";

export default function App() {
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState({ base: false, sqlmap: false });
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
            setLoading({ base: true, sqlmap: false });
          }}
          onDone={(res, sqlmapDone = false) => {
            if (sqlmapDone) {
              setReport(prev => ({
                ...prev,
                parts: { ...prev?.parts, sqlmap: res.parts?.sqlmap },
                report: res.report || prev?.report
              }));
              setLoading(prev => ({ ...prev, sqlmap: false }));
            } else {
              setReport(res);
              setLoading(prev => ({ ...prev, base: false }));
            }
          }}
          onError={(err) => {
            setError(err);
            setLoading({ base: false, sqlmap: false });
          }}
        />

        {loading.base && (
          <div className="notify">Scan running — this may take some time...</div>
        )}
        {error && <div className="error">Error: {String(error)}</div>}

        {report && (
          <section style={{ marginTop: 20 }}>
            <Results parts={report.parts} report={report.report} loading={loading} />
          </section>
        )}
      </main>

      <footer className="footer">
        <small>Tip: for docker setups use host.docker.internal as target host for container-to-host access.</small>
      </footer>
    </div>
  );
}
