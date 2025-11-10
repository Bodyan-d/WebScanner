import React, { useState } from "react";

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";

export default function ScanForm({ onStart, onDone, onError }) {
  const [url, setUrl] = useState("");
  const [maxPages, setMaxPages] = useState(50);
  const [concurrency, setConcurrency] = useState(5);
  const [runSqlmap, setRunSqlmap] = useState(false);
  // sqlmap args
  const [level, setLevel] = useState(3);
  const [risk, setRisk] = useState(2);
  const [threads, setThreads] = useState(5);
  const [tamper, setTamper] = useState("");

  async function submit(e) {
    e.preventDefault();
    if (!url) return alert("Enter a target URL");

    const sqlmap_args = [
      `--level=${level}`,
      `--risk=${risk}`,
      `--threads=${threads}`,
      `--crawl=1`,
      "--random-agent",
      "--batch"
    ];
    if (tamper) sqlmap_args.push(`--tamper=${tamper}`);

    const payload = {
      url,
      max_pages: Number(maxPages),
      concurrency: Number(concurrency),
      run_sqlmap: !!runSqlmap,
      sqlmap_args: runSqlmap ? sqlmap_args : undefined
    };

    try {
      onStart && onStart();
      const res = await fetch(`${API_BASE}/api/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      });
      if (!res.ok) {
        const txt = await res.text();
        throw new Error(`Server ${res.status}: ${txt}`);
      }
      const json = await res.json();
      onDone && onDone(json);
    } catch (err) {
      onError && onError(err);
    }
  }

  return (
    <form className="card form" onSubmit={submit}>
      <div className="form-row">
        <label className="label">Target URL</label>
        <input className="input" type="url" value={url} onChange={(e)=>setUrl(e.target.value)} placeholder="https://example.com" required />
      </div>

      <div className="form-grid">
        <div className="form-row">
          <label className="label">Max pages</label>
          <input className="input" type="number" value={maxPages} onChange={(e)=>setMaxPages(e.target.value)} min={1} max={200} />
        </div>
        <div className="form-row">
          <label className="label">Concurrency</label>
          <input className="input" type="number" value={concurrency} onChange={(e)=>setConcurrency(e.target.value)} min={1} max={20} />
        </div>
        <div className="form-row inline">
          <label><input type="checkbox" checked={runSqlmap} onChange={(e)=>setRunSqlmap(e.target.checked)} /> Run sqlmap</label>
        </div>
      </div>

      {runSqlmap && (
        <div className="card small">
          <div className="form-grid">
            <div className="form-row">
              <label className="label">Level (1-5)</label>
              <input className="input" type="number" value={level} onChange={e=>setLevel(Number(e.target.value))} min={1} max={5} />
            </div>
            <div className="form-row">
              <label className="label">Risk (1-3)</label>
              <input className="input" type="number" value={risk} onChange={e=>setRisk(Number(e.target.value))} min={1} max={3} />
            </div>
            <div className="form-row">
              <label className="label">Threads</label>
              <input className="input" type="number" value={threads} onChange={e=>setThreads(Number(e.target.value))} min={1} max={20} />
            </div>
            <div className="form-row">
              <label className="label">Tamper (opt)</label>
              <input className="input" type="text" value={tamper} onChange={e=>setTamper(e.target.value)} placeholder="space2comment" />
            </div>
          </div>
        </div>
      )}

      <div style={{display:'flex',gap:8,marginTop:12}}>
        <button className="btn primary" type="submit">Start scan</button>
        <button className="btn" type="button" onClick={()=>{ setUrl(""); setRunSqlmap(false); }}>Clear</button>
      </div>
    </form>
  );
}
