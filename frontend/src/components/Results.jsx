import React, { useState } from "react";

/*
  Залежить від твоєї реалізації Tabs.
  Якщо у тебе є компонент Tabs, який приймає tabs=[{id,title,content}],
  можна адаптувати — нижче я роблю прості local tabs (без зовнішнього Tabs).
*/

const severityColor = (lvl = "") => {
  const s = String(lvl || "").toLowerCase();
  if (s.includes("critical") || s.includes("error")) return "#ef4444";
  if (s.includes("high") || s.includes("warning")) return "#f59e0b";
  if (s.includes("moderate") || s.includes("info")) return "#0ea5e9";
  return "#6b7280";
};

const niceJSON = (v) => {
  try { return JSON.stringify(v, null, 2); } catch { return String(v ?? ""); }
};

/* ---------- Subcomponents ---------- */

function PortsView({ parts }) {
  const ports = parts?.ports ?? null;
  const tcp = ports?.tcp ?? (ports?.nmap && ports.nmap.ports) ?? null;
  if (!tcp || typeof tcp !== "object") {
    return <pre className="mono">{niceJSON(ports)}</pre>;
  }
  const entries = Object.entries(tcp).sort((a,b) => Number(a[0]) - Number(b[0]));
  return (
    <table className="table">
      <thead><tr><th>Port</th><th>Status</th></tr></thead>
      <tbody>
        {entries.map(([p, v]) => (
          <tr key={p}>
            <td style={{width:80}}>{p}</td>
            <td>
              <span className={`badge ${v ? "open" : "closed"}`}>{v ? "open" : "closed"}</span>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function URLsView({ parts }) {
  const crawl = parts?.crawl ?? {};
  const urls = Array.isArray(crawl?.urls) ? crawl.urls : (Array.isArray(crawl) ? crawl : []);
  if (!urls || urls.length === 0) return <div className="muted">No URLs found</div>;
  return (
    <div className="urls">
      {urls.map((u, i) => (
        <div key={i} className="url-item">
          <a href={u} target="_blank" rel="noreferrer">{u}</a>
        </div>
      ))}
    </div>
  );
}

function HeadersView({ parts }) {
  const headers = parts?.headers ?? {};
  if (headers?.error) return <pre className="mono">{headers.error}</pre>;
  return (
    <div>
      <div><strong>Present</strong></div>
      <pre className="mono small-block">{niceJSON(headers.present ?? headers)}</pre>
      {headers.missing && <div style={{marginTop:8}}><strong>Missing:</strong> {Array.isArray(headers.missing) ? headers.missing.join(", ") : niceJSON(headers.missing)}</div>}
    </div>
  );
}

function FindingsList({ items = [], type = "Finding" }) {
  if (!items || items.length === 0) {
    return (
      <div
        style={{
          background: "#0f172a",
          color: "#22c55e",
          padding: "20px",
          borderRadius: 8,
          textAlign: "center",
          fontWeight: 600,
          fontSize: 18,
        }}
      >
        ✅ Secure — No {type} vulnerabilities found
      </div>
    );
  }

  return (
    <div className="findings-grid" style={{ display: "grid", gap: 10 }}>
      {items.map((it, idx) => {
        // визначаємо рівень ризику
        const vulnerable =
          it.reflected === true ||
          it.suspected === true ||
          String(it.status).startsWith("4") ||
          String(it.status).startsWith("5");

        const color = vulnerable ? "#ef4444" : "#22c55e"; // червоний / зелений
        const title = `${type} #${idx + 1}`;

        return (
          <div
            key={idx}
            className="finding-card"
            style={{
              background: "#111827",
              border: `1px solid ${color}`,
              borderLeft: `6px solid ${color}`,
              padding: "14px 16px",
              borderRadius: 8,
              boxShadow: vulnerable
                ? "0 0 10px rgba(239,68,68,0.4)"
                : "0 0 6px rgba(34,197,94,0.3)",
            }}
          >
            <div style={{ display: "flex", justifyContent: "space-between" }}>
              <div style={{ fontWeight: 700, color }}>
                {vulnerable ? "⚠️ Vulnerability detected" : "✅ Secure"}
              </div>
              <div className="muted small">{type}</div>
            </div>

            <div style={{ marginTop: 6 }}>
              {it.url && (
                <div>
                  <strong>URL:</strong>{" "}
                  <a
                    href={it.url}
                    target="_blank"
                    rel="noreferrer"
                    style={{ color: "#3b82f6" }}
                  >
                    {it.url}
                  </a>
                </div>
              )}
              {it.param && (
                <div>
                  <strong>Parameter:</strong> <code>{it.param}</code>
                </div>
              )}
              {it.payload && (
                <div>
                  <strong>Payload:</strong>{" "}
                  <code style={{ color: "#f59e0b" }}>{it.payload}</code>
                </div>
              )}
              {it.marker && (
                <div>
                  <strong>Marker:</strong> <code>{it.marker}</code>
                </div>
              )}
              {it.similarity && (
                <div>
                  <strong>Similarity:</strong> {Math.round(it.similarity * 100)}%
                </div>
              )}
              <div style={{ marginTop: 8, fontSize: 13, color: "#94a3b8" }}>
                Status: {it.status ?? "unknown"}
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
}

function SqlmapView({ sqlmap }) {
  // підтримує і масив, і об'єкт з output
  const results = Array.isArray(sqlmap)
    ? sqlmap
    : Array.isArray(sqlmap?.output)
      ? sqlmap.output
      : sqlmap
        ? [sqlmap]
        : [];

  if (!items || items.length === 0) {
   return (
      <div
        style={{
          background: "#0f172a",
          color: "#22c55e",
          padding: "20px",
          borderRadius: 8,
          textAlign: "center",
          fontWeight: 600,
          fontSize: 18,
        }}
      >
        ✅ Secure — No sqlmap vulnerabilities found
      </div>
    ); 
  }

  return (
    <div>
      {results.map((r, i) => {
        const color = severityColor(r.level);
        return (
          <div key={i} className="sqlmap-finding" style={{
            marginBottom: 10,
            padding: 10,
            borderLeft: `4px solid ${color}`,
            borderRadius: 6
          }}>
            <div style={{ color, fontWeight: 600 }}>
              {r.level?.toUpperCase()}: {r.message}
            </div>
            {r.detail && (
              <pre className="mono small-block" style={{ marginTop: 4 }}>
                {r.detail}
              </pre>
            )}
            {r.line && (
              <div style={{ fontSize: 12, color: "#aaa", marginTop: 4 }}>
                {r.line}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

/* ---------- Main component ---------- */

export default function Results({ parts = {}, report }) {
  const [active, setActive] = useState("ports");

  const countUrls = Array.isArray(parts?.crawl?.urls) ? parts.crawl.urls.length : 0;
  const tabs = [
    { id: "ports", title: "Ports" },
    { id: "urls", title: `URLs (${countUrls})` },
    { id: "headers", title: "Headers" },
    { id: "xss", title: `XSS (${(parts?.xss || []).length})` },
    { id: "sqli", title: `SQLi (${(parts?.sqli || []).length})` },
    { id: "sqlmap", title: "sqlmap" }
  ];

  return (
    <div className="card">
      <div style={{display:'flex',justifyContent:'space-between',alignItems:'center'}}>
        <h2 style={{margin:0}}>Scan results</h2>
        <div style={{fontSize:12,color:"#666"}}>Report: <code>{report}</code></div>
      </div>

      <div className="tabs-row" style={{marginTop:12}}>
        {tabs.map(t => (
          <button key={t.id} onClick={() => setActive(t.id)} className={`tab-btn ${active===t.id ? "active":""}`}>
            {t.title}
          </button>
        ))}
      </div>

      <div style={{marginTop:16}}>
        {active === "ports" && <PortsView parts={parts} />}
        {active === "urls" && <URLsView parts={parts} />}
        {active === "headers" && <HeadersView parts={parts} />}
        {active === "xss" && <FindingsList items={parts?.xss} type="XSS" />}
        {active === "sqli" && <FindingsList items={parts?.sqli} type="SQLi" />}
        {active === "sqlmap" && <SqlmapView sqlmap={parts?.sqlmap} />}
      </div>
    </div>
  );
}
