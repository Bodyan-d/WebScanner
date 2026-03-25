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

const riskClass = severity => {
  const value = String(severity || "").toLowerCase();
  if (value.includes("critical")) return "critical";
  if (value.includes("high")) return "high";
  if (value.includes("medium")) return "medium";
  if (value.includes("low")) return "low";
  return "none";
};

const formatScore = score => (typeof score === "number" ? score.toFixed(1) : "n/a");

function formatServiceLabel(service = {}) {
  const chunks = [];
  if (service?.name) chunks.push(service.name);
  if (service?.product && service.product !== service.name) chunks.push(service.product);
  if (service?.version) chunks.push(service.version);
  return chunks.join(" • ") || "Unknown service";
}

function RiskChip({ risk }) {
  const severity = risk?.severity || "None";
  const score = risk?.highest_cvss;
  return (
    <span className={`risk-chip ${riskClass(severity)}`}>
      {severity}
      {typeof score === "number" && ` ${formatScore(score)}`}
    </span>
  );
}

function PortsView({ parts }) {
  const ports = parts?.ports ?? null;
  const portItems = Array.isArray(ports?.items) ? ports.items : null;
  const portSummary = ports?.summary ?? {};

  if (!portItems) {
    return <pre className="mono">{niceJSON(ports)}</pre>;
  }

  if (!portItems.length) {
    return <div className="secure-panel">No open ports were detected in the configured top-port set.</div>;
  }

  return (
    <div>
      <div className="ports-summary">
        <div>
          <strong>Open ports:</strong> {portSummary?.open_port_count ?? portItems.length}
        </div>
        <div>
          <strong>Highest risk:</strong>{" "}
          <RiskChip risk={{ severity: portSummary?.highest_severity, highest_cvss: portSummary?.highest_cvss }} />
        </div>
        <div>
          <strong>Ports with CVE matches:</strong> {portSummary?.ports_with_vulnerabilities ?? 0}
        </div>
      </div>

      {ports?.fallback_reason && (
        <div className="muted" style={{ marginBottom: 12 }}>
          nmap service detection was unavailable, so the scanner used lightweight banner probing. Details may be less precise.
        </div>
      )}

      <div className="port-list">
        {portItems.map(item => {
          const service = item?.service || {};
          const vulnerabilities = Array.isArray(item?.vulnerabilities) ? item.vulnerabilities : [];
          return (
            <details key={`${item.port}-${item.protocol || "tcp"}`} className="port-accordion">
              <summary className="port-summary">
                <div className="port-summary-main">
                  <span className="port-code">{item.port}/{item.protocol || "tcp"}</span>
                  <span className={`badge ${item.open ? "open" : "closed"}`}>{item.state || (item.open ? "open" : "closed")}</span>
                  <span className="service-pill">{formatServiceLabel(service)}</span>
                </div>
                <div className="port-summary-meta">
                  <RiskChip risk={item?.risk} />
                  <span className="muted">{item?.risk?.cve_count || 0} CVE matches</span>
                </div>
              </summary>

              <div className="port-details">
                <div className="port-detail-grid">
                  <div>
                    <strong>Detected service</strong>
                    <div>{service?.name || "Unknown"}</div>
                  </div>
                  <div>
                    <strong>Product</strong>
                    <div>{service?.product || "Unknown"}</div>
                  </div>
                  <div>
                    <strong>Version</strong>
                    <div>{service?.version || "Unknown"}</div>
                  </div>
                  <div>
                    <strong>Detection</strong>
                    <div>{service?.detection || "Unknown"}</div>
                  </div>
                  <div>
                    <strong>Risk</strong>
                    <div>
                      <RiskChip risk={item?.risk} />
                    </div>
                  </div>
                  <div>
                    <strong>Sources</strong>
                    <div>NVD API + Vulnerability Lookup</div>
                  </div>
                </div>

                {service?.banner && (
                  <div style={{ marginTop: 12 }}>
                    <strong>Banner / server hint</strong>
                    <pre className="mono small-block" style={{ marginTop: 6 }}>{service.banner}</pre>
                  </div>
                )}

                {service?.extrainfo && (
                  <div style={{ marginTop: 12 }}>
                    <strong>Extra info</strong>
                    <div style={{ marginTop: 6 }}>{service.extrainfo}</div>
                  </div>
                )}

                {item?.lookup_error && (
                  <div className="muted" style={{ marginTop: 12 }}>
                    CVE lookup warning: {item.lookup_error}
                  </div>
                )}

                {!vulnerabilities.length && (
                  <div className="secure-panel" style={{ marginTop: 12 }}>
                    No CVE matches were found for the detected service fingerprint.
                  </div>
                )}

                {!!vulnerabilities.length && (
                  <div className="vuln-list">
                    {vulnerabilities.map(vuln => (
                      <div key={vuln.id} className="vuln-card">
                        <div className="vuln-card-header">
                          <div>
                            <strong>{vuln.id}</strong>
                            <div className="muted small" style={{ marginTop: 4 }}>
                              {(vuln.sources || [vuln.source]).join(", ")}
                            </div>
                          </div>
                          <RiskChip risk={{ severity: vuln.severity, highest_cvss: vuln.cvss }} />
                        </div>
                        {vuln.summary && <div style={{ marginTop: 10 }}>{vuln.summary}</div>}
                        <div className="vuln-meta">
                          <span>Published: {vuln.published || "Unknown"}</span>
                          <span>Updated: {vuln.last_modified || "Unknown"}</span>
                          <span>CVSS: {formatScore(vuln.cvss)}</span>
                        </div>
                        {vuln.vector && (
                          <div style={{ marginTop: 8 }}>
                            <code>{vuln.vector}</code>
                          </div>
                        )}
                        {vuln.link && (
                          <div style={{ marginTop: 8 }}>
                            <a href={vuln.link} target="_blank" rel="noreferrer">Open advisory</a>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </details>
          );
        })}
      </div>
    </div>
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
