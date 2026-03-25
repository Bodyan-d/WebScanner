import React, { useState } from "react";
import Results from "./components/Results";
import ScanForm from "./components/ScanForm";

function mergeReport(prev, next) {
  if (!prev) {
    return next;
  }
  if (!next) {
    return prev;
  }
  if (prev.scan_id && next.scan_id && prev.scan_id !== next.scan_id) {
    return prev;
  }

  return {
    ...prev,
    ...next,
    scan_id: next.scan_id ?? prev.scan_id,
    target: next.target ?? prev.target,
    report: next.report ?? prev.report,
    job: next.job ?? prev.job,
    parts: {
      ...(prev.parts || {}),
      ...(next.parts || {}),
      sqlmap: next.parts?.sqlmap ?? prev.parts?.sqlmap,
    },
  };
}

export default function App() {
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState({ base: false, sqlmap: false });
  const [error, setError] = useState(null);

  return (
    <div className="container">
      <header className="header">
        <h1>WebScanner Dashboard</h1>
        <p className="subtitle">Fast scans for ports, service fingerprints, CVE risk, headers, XSS, SQLi, and optional sqlmap follow-up checks.</p>
      </header>

      <main>
        <ScanForm
          currentReport={report}
          onBaseStart={() => {
            setError(null);
            setLoading(prev => ({ ...prev, base: true }));
          }}
          onBaseDone={(res) => {
            setReport(res);
            setLoading(prev => ({ ...prev, base: false }));
          }}
          onSqlmapStart={(res) => {
            setError(null);
            setLoading(prev => ({ ...prev, sqlmap: true }));
            setReport(prev => mergeReport(prev, res));
          }}
          onSqlmapUpdate={(res) => {
            setReport(prev => mergeReport(prev, res));
          }}
          onSqlmapDone={(res) => {
            setReport(prev => mergeReport(prev, res));
            setLoading(prev => ({ ...prev, sqlmap: false }));
          }}
          onSqlmapError={(message, fallbackReport) => {
            if (fallbackReport) {
              setReport(prev => mergeReport(prev, fallbackReport));
            }
            setError(message);
            setLoading(prev => ({ ...prev, sqlmap: false }));
          }}
          onError={(err) => {
            setError(err instanceof Error ? err.message : String(err));
            setLoading({ base: false, sqlmap: false });
          }}
        />

        {loading.base && <div className="notify">Base scan is running in the background. Current results stay visible until the new scan completes.</div>}
        {!loading.base && loading.sqlmap && <div className="notify">Sqlmap deep scan is running in the background. Other tabs remain available.</div>}
        {error && <div className="error">Error: {error}</div>}

        {report && (
          <section style={{ marginTop: 20 }}>
            <Results parts={report.parts} report={report.report} target={report.target} />
          </section>
        )}
      </main>

      <footer className="footer">
        <small>Tip: in Docker, keep the frontend talking to `/api` and let nginx proxy requests to the backend.</small>
      </footer>
    </div>
  );
}
