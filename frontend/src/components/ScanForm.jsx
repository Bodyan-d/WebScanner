import React, { useState } from "react";

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";

export default function ScanForm({ onStart, onDone, onError }) {
  const [url, setUrl] = useState("");
  const [maxPages, setMaxPages] = useState(50);
  const [concurrency, setConcurrency] = useState(5);
  const [runSqlmap, setRunSqlmap] = useState(false);
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
      "--random-agent",
      "--batch"
    ];
    if (tamper) sqlmap_args.push(`--tamper=${tamper}`);

    const basePayload = {
      url,
      max_pages: Number(maxPages),
      concurrency: Number(concurrency),
      run_sqlmap: false,
      sqlmap_args: undefined
    };

    try {
      onStart && onStart();

      // 1️⃣ Базове сканування
      const resBase = await fetch(`${API_BASE}/api/scan_no_sqlmap`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(basePayload)
      });

      if (!resBase.ok) {
        const txt = await resBase.text();
        throw new Error(`Server ${resBase.status}: ${txt}`);
      }

      const jsonBase = await resBase.json();

      onDone && onDone(jsonBase);

      if (!runSqlmap) return;

      // 2️⃣ Sqlmap сканування
      const scanId = jsonBase.scan_id;
      if (!scanId) {
        const err = new Error("scan_id not returned by server — cannot run sqlmap.");
        onError && onError(err);
        return;
      }

      const sqlmapPayload = {
        url,
        scan_id: scanId,
        run_sqlmap: true,
        sqlmap_args: sqlmap_args
      };

      const resSqlmap = await fetch(`${API_BASE}/api/scan_sqlmap`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(sqlmapPayload)
      });

      if (!resSqlmap.ok) {
        const txt = await resSqlmap.text();
        throw new Error(`SQLMap run failed ${resSqlmap.status}: ${txt}`);
      }

      const jsonSqlmap = await resSqlmap.json();


      onDone && onDone(prev => ({
        ...prev,
        parts: {
          ...prev.parts,
          sqlmap: jsonSqlmap.parts?.sqlmap || jsonSqlmap
        }
      }));

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
