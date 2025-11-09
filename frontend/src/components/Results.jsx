import React from "react";
import Tabs from "./Tabs";

function PortsView({ parts }) {
  const ports = parts?.ports ?? null;
  const tcp = ports?.tcp ?? (ports?.nmap && ports.nmap.ports) ?? null;
  if (!tcp || typeof tcp !== "object") {
    return <pre className="mono">{JSON.stringify(ports, null, 2)}</pre>;
  }
  const entries = Object.entries(tcp);
  return (
    <table className="table">
      <thead><tr><th>Port</th><th>Status</th></tr></thead>
      <tbody>
        {entries.map(([p,v]) => (
          <tr key={p}><td>{p}</td><td className={v ? "open" : "closed"}>{v ? "open" : "closed"}</td></tr>
        ))}
      </tbody>
    </table>
  );
}

function URLsView({ parts }) {
  const crawl = parts?.crawl ?? {};
  const urls = Array.isArray(crawl?.urls) ? crawl.urls : (Array.isArray(crawl) ? crawl : []);
  if (!urls.length) return <div>No URLs found</div>;
  return (
    <div className="urls">
      {urls.map((u,i) => <div key={i} className="url-item"><a href={u} target="_blank" rel="noreferrer">{u}</a></div>)}
    </div>
  );
}

function HeadersView({ parts }) {
  const headers = parts?.headers ?? {};
  if (headers.error) return <pre className="mono">{headers.error}</pre>;
  return (
    <div>
      <div><strong>Present</strong></div>
      <pre className="mono">{JSON.stringify(headers.present ?? headers, null, 2)}</pre>
      {headers.missing && <div style={{marginTop:8}}><strong>Missing:</strong> {JSON.stringify(headers.missing)}</div>}
    </div>
  );
}

function FindingsList({ items, type }) {
  if (!items || items.length === 0) return <div>No findings</div>;
  return (
    <div>
      {items.map((it, idx) => (
        <div key={idx} className="finding">
          <div><strong>{type} #{idx+1}</strong></div>
          <pre className="mono">{JSON.stringify(it, null, 2)}</pre>
        </div>
      ))}
    </div>
  );
}

export default function Results({ parts = {}, report }) {
  const tabs = [
    { id: "ports", title: "Ports", content: <PortsView parts={parts} /> },
    { id: "urls", title: "URLs", content: <URLsView parts={parts} /> },
    { id: "headers", title: "Headers", content: <HeadersView parts={parts} /> },
    { id: "xss", title: `XSS (${(parts?.xss||[]).length})`, content: <FindingsList items={parts?.xss} type="XSS" /> },
    { id: "sqli", title: `SQLi (${(parts?.sqli||[]).length})`, content: <FindingsList items={parts?.sqli} type="SQLi" /> },
    { id: "sqlmap", title: "sqlmap", content: <pre className="mono">{parts?.sqlmap?.output ?? JSON.stringify(parts?.sqlmap ?? {}, null, 2)}</pre> }
  ];

  return (
    <div className="card">
      <div style={{display:'flex',justifyContent:'space-between',alignItems:'center'}}>
        <h2 style={{margin:0}}>Scan results</h2>
        <div style={{fontSize:12,color:"#666"}}>Report: <code>{report}</code></div>
      </div>

      <Tabs tabs={tabs} />
    </div>
  );
}
