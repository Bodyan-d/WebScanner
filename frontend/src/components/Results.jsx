import React, { useState } from "react";

const severityColor = (level = "") => {
  const value = String(level || "").toLowerCase();
  if (value.includes("critical") || value.includes("error")) return "#ef4444";
  if (value.includes("high") || value.includes("warning")) return "#f59e0b";
  if (value.includes("moderate") || value.includes("info")) return "#0ea5e9";
  return "#6b7280";
};

const niceJSON = value => {
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value ?? "");
  }
};

function PortsView({ parts }) {
  const ports = parts?.ports ?? null;
  const tcp = ports?.tcp ?? (ports?.nmap && ports.nmap.ports) ?? null;
  if (!tcp || typeof tcp !== "object") {
    return <pre className="mono">{niceJSON(ports)}</pre>;
  }
  const entries = Object.entries(tcp).sort((a, b) => Number(a[0]) - Number(b[0]));
  return (
    <table className="table">
      <thead>
        <tr>
          <th>Port</th>
          <th>Status</th>
        </tr>
      </thead>
      <tbody>
        {entries.map(([port, isOpen]) => (
          <tr key={port}>
            <td style={{ width: 80 }}>{port}</td>
            <td>
              <span className={`badge ${isOpen ? "open" : "closed"}`}>{isOpen ? "open" : "closed"}</span>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function URLsView({ parts }) {
  const crawl = parts?.crawl ?? {};
  const urls = Array.isArray(crawl?.urls) ? crawl.urls : Array.isArray(crawl) ? crawl : [];
  if (!urls.length) {
    return <div className="muted">No URLs found.</div>;
  }
  return (
    <div className="urls">
      {urls.map((url, index) => (
        <div key={index} className="url-item">
          <a href={url} target="_blank" rel="noreferrer">{url}</a>
        </div>
      ))}
    </div>
  );
}

function HeadersView({ parts }) {
  const headers = parts?.headers ?? {};
  if (headers?.error) {
    return <pre className="mono">{headers.error}</pre>;
  }
  return (
    <div>
      <div><strong>Present</strong></div>
      <pre className="mono small-block">{niceJSON(headers.present ?? headers)}</pre>
      {headers.missing && (
        <div style={{ marginTop: 8 }}>
          <strong>Missing:</strong> {Array.isArray(headers.missing) ? headers.missing.join(", ") : niceJSON(headers.missing)}
        </div>
      )}
    </div>
  );
}

function FindingsList({ items = [], type = "Finding" }) {
  if (!items.length) {
    return <div className="secure-panel">No {type} findings were detected.</div>;
  }

  return (
    <div className="findings-grid">
      {items.map((item, index) => {
        const vulnerable = item.reflected === true || item.suspected === true;
        const hasError = Boolean(item.error);
        const color = hasError ? "#f59e0b" : vulnerable ? "#ef4444" : "#22c55e";
        const label = hasError ? "Request error" : vulnerable ? "Potential issue" : "Informational";
        const paramValue = Array.isArray(item.param) ? item.param.join(", ") : item.param;

        return (
          <div
            key={`${type}-${index}`}
            className="finding-card"
            style={{
              color: "#fff",
              background: "#111827",
              border: `1px solid ${color}`,
              borderLeft: `6px solid ${color}`,
              padding: "14px 16px",
              borderRadius: 8,
            }}
          >
            <div style={{ display: "flex", justifyContent: "space-between", gap: 12 }}>
              <div style={{ fontWeight: 700, color }}>{label}</div>
              <div className="muted small">{type}</div>
            </div>

            <div style={{ marginTop: 6 }}>
              {item.url && (
                <div>
                  <strong>URL:</strong>{" "}
                  <a className="url-wrap" href={item.url} target="_blank" rel="noreferrer" style={{ color: "#60a5fa" }}>
                    {item.url}
                  </a>
                </div>
              )}
              {paramValue && (
                <div>
                  <strong>Parameter:</strong> <code>{paramValue}</code>
                </div>
              )}
              {item.payload && (
                <div>
                  <strong>Payload:</strong> <code>{item.payload}</code>
                </div>
              )}
              {item.evidence?.length > 0 && (
                <div>
                  <strong>Evidence:</strong> {item.evidence.join(", ")}
                </div>
              )}
              {typeof item.similarity === "number" && (
                <div>
                  <strong>Similarity:</strong> {Math.round(item.similarity * 100)}%
                </div>
              )}
              <div style={{ marginTop: 8, fontSize: 13, color: "#94a3b8" }}>
                Status: {item.status ?? "unknown"}
              </div>
              {item.error && (
                <div className="finding-error">
                  <strong>Error:</strong> {item.error}
                </div>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
}

function SqlmapView({ sqlmap }) {
  if (!sqlmap) {
    return <div className="muted">sqlmap was not run for this scan.</div>;
  }

  if (sqlmap.status === "queued" || sqlmap.status === "running") {
    return (
      <div className="notify-panel">
        <strong>sqlmap status:</strong> {sqlmap.status}
        {sqlmap.message && <div style={{ marginTop: 8 }}>{sqlmap.message}</div>}
        {Array.isArray(sqlmap.scanned_urls) && sqlmap.scanned_urls.length > 0 && (
          <div style={{ marginTop: 8 }}>Targets queued: {sqlmap.scanned_urls.length}</div>
        )}
      </div>
    );
  }

  if (sqlmap.ok === false || sqlmap.status === "failed") {
    return <div className="error-block">sqlmap error: {sqlmap.error || "Unknown error"}</div>;
  }

  const findings = Array.isArray(sqlmap?.findings) ? sqlmap.findings : [];
  if (!findings.length) {
    return (
      <div className="secure-panel">
        {sqlmap.message || "No sqlmap findings were detected."}
      </div>
    );
  }

  const grouped = findings.reduce((acc, finding) => {
    const key = `${finding.url}::${finding.message}`;
    if (!acc[key]) acc[key] = { ...finding, occurrences: 0 };
    acc[key].occurrences += 1;
    return acc;
  }, {});

  return (
    <div>
      {Array.isArray(sqlmap.scanned_urls) && (
        <div className="muted" style={{ marginBottom: 12 }}>
          Scanned URLs: {sqlmap.scanned_urls.length}
        </div>
      )}
      {Object.values(grouped).map((finding, index) => {
        const color = severityColor(finding.level);
        return (
          <div key={index} className="sqlmap-item" style={{ borderLeft: `4px solid ${color}` }}>
            <div style={{ color, fontWeight: 600 }}>
              {finding.level?.toUpperCase()}: {finding.message} ({finding.occurrences} times)
            </div>
            <div style={{ fontSize: 12, color: "#6b7280", marginTop: 4 }}>{finding.url}</div>
            {finding.detail && <pre className="mono raw-output" style={{ marginTop: 8 }}>{finding.detail}</pre>}
          </div>
        );
      })}
    </div>
  );
}

export default function Results({ parts = {}, report, target }) {
  const [active, setActive] = useState("ports");
  const sqlmapStatus = parts?.sqlmap?.status;
  const sqlmapTitle = sqlmapStatus && sqlmapStatus !== "completed" ? `sqlmap (${sqlmapStatus})` : "sqlmap";

  const countUrls = Array.isArray(parts?.crawl?.urls) ? parts.crawl.urls.length : 0;
  const tabs = [
    { id: "ports", title: "Ports" },
    { id: "urls", title: `URLs (${countUrls})` },
    { id: "headers", title: "Headers" },
    { id: "xss", title: `XSS (${(parts?.xss || []).length})` },
    { id: "sqli", title: `SQLi (${(parts?.sqli || []).length})` },
    { id: "sqlmap", title: sqlmapTitle },
  ];

  return (
    <div className="card">
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 16 }}>
        <div>
          <h2 style={{ margin: 0 }}>Scan results</h2>
          {target && <div className="muted" style={{ marginTop: 6 }}>{target}</div>}
        </div>
        <div style={{ fontSize: 12, color: "#666" }}>
          Report: <code>{report}</code>
        </div>
      </div>

      <div className="tabs-row" style={{ marginTop: 12 }}>
        {tabs.map(tab => (
          <button key={tab.id} onClick={() => setActive(tab.id)} className={`tab-btn ${active === tab.id ? "active" : ""}`}>
            {tab.title}
          </button>
        ))}
      </div>

      <div style={{ marginTop: 16 }}>
        {active === "ports" && <PortsView parts={parts} />}
        {active === "urls" && <URLsView parts={parts} />}
        {active === "headers" && <HeadersView parts={parts} />}
        {active === "xss" && <FindingsList items={parts?.xss || []} type="XSS" />}
        {active === "sqli" && <FindingsList items={parts?.sqli || []} type="SQLi" />}
        {active === "sqlmap" && <SqlmapView sqlmap={parts?.sqlmap} />}
      </div>
    </div>
  );
}
