import React, { useRef, useState } from "react";

const API_BASE = (import.meta.env.VITE_API_URL || "/api").replace(/\/$/, "");
const API_KEY = import.meta.env.VITE_API_KEY || "";
const BASE_SCAN_POLL_INTERVAL_MS = 3000;
const BASE_SCAN_POLL_MAX_ATTEMPTS = 900;
const SQLMAP_POLL_INTERVAL_MS = 3000;
const SQLMAP_POLL_MAX_ATTEMPTS = 600;

function buildHeaders() {
  const headers = { "Content-Type": "application/json" };
  if (API_KEY) {
    headers["X-API-Key"] = API_KEY;
  }
  return headers;
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function normalizeTarget(value) {
  return String(value || "").trim().replace(/\/+$/, "");
}

export default function ScanForm({
  currentReport,
  onBaseStart,
  onBaseDone,
  onSqlmapStart,
  onSqlmapUpdate,
  onSqlmapDone,
  onSqlmapError,
  onError,
}) {
  const [url, setUrl] = useState("");
  const [maxPages, setMaxPages] = useState(50);
  const [concurrency, setConcurrency] = useState(5);
  const [runSqlmap, setRunSqlmap] = useState(false);
  const [level, setLevel] = useState(3);
  const [risk, setRisk] = useState(2);
  const [threads, setThreads] = useState(5);
  const [tamper, setTamper] = useState("");
  const activeRunRef = useRef(0);

  function isActiveRun(runId) {
    return activeRunRef.current === runId;
  }

  async function pollBaseScanJob(jobId, runId) {
    for (let attempt = 0; attempt < BASE_SCAN_POLL_MAX_ATTEMPTS; attempt += 1) {
      if (!isActiveRun(runId)) {
        return null;
      }

      const response = await fetch(`${API_BASE}/scan_no_sqlmap/${jobId}`, {
        method: "GET",
        headers: buildHeaders(),
      });

      if (!response.ok) {
        throw new Error(`base scan status failed ${response.status}: ${await response.text()}`);
      }

      const payload = await response.json();
      if (!isActiveRun(runId)) {
        return null;
      }

      const status = payload?.job?.status;
      if (status === "completed") {
        return payload;
      }
      if (status === "failed") {
        throw new Error(payload?.job?.error || "base scan failed.");
      }

      await sleep(BASE_SCAN_POLL_INTERVAL_MS);
    }

    throw new Error("base scan polling timed out on the frontend.");
  }

  async function startBaseScan(targetUrl, safeMaxPages, safeConcurrency, runId) {
    const response = await fetch(`${API_BASE}/scan_no_sqlmap`, {
      method: "POST",
      headers: buildHeaders(),
      body: JSON.stringify({
        url: targetUrl,
        max_pages: safeMaxPages,
        concurrency: safeConcurrency,
        run_sqlmap: false,
      }),
    });

    if (!response.ok) {
      throw new Error(`Server ${response.status}: ${await response.text()}`);
    }

    const startPayload = await response.json();
    if (!isActiveRun(runId)) {
      return null;
    }

    const immediateStatus = startPayload?.job?.status;
    const jobId = startPayload?.job?.job_id;
    if (!jobId || immediateStatus === "completed") {
      return startPayload;
    }
    if (immediateStatus === "failed") {
      throw new Error(startPayload?.job?.error || "base scan failed.");
    }

    return await pollBaseScanJob(jobId, runId);
  }

  async function pollSqlmapJob(jobId, runId) {
    for (let attempt = 0; attempt < SQLMAP_POLL_MAX_ATTEMPTS; attempt += 1) {
      if (!isActiveRun(runId)) {
        return null;
      }

      const response = await fetch(`${API_BASE}/scan_sqlmap/${jobId}`, {
        method: "GET",
        headers: buildHeaders(),
      });

      if (!response.ok) {
        throw new Error(`sqlmap status failed ${response.status}: ${await response.text()}`);
      }

      const payload = await response.json();
      if (!isActiveRun(runId)) {
        return null;
      }
      onSqlmapUpdate?.(payload);

      const status = payload?.parts?.sqlmap?.status || payload?.job?.status;
      if (status === "completed") {
        return payload;
      }
      if (status === "failed") {
        throw new Error(payload?.parts?.sqlmap?.error || payload?.job?.error || "sqlmap job failed.");
      }

      await sleep(SQLMAP_POLL_INTERVAL_MS);
    }

    throw new Error("sqlmap polling timed out on the frontend.");
  }

  async function startSqlmap(scanId, targetUrl, safeConcurrency, sqlmapArgs, runId) {
    const sqlmapPayload = {
      url: targetUrl,
      scan_id: scanId,
      run_sqlmap: true,
      sqlmap_args: sqlmapArgs,
      concurrency: safeConcurrency,
      max_pages: Math.min(50, Math.max(1, Number(maxPages) || 1)),
    };

    const response = await fetch(`${API_BASE}/scan_sqlmap`, {
      method: "POST",
      headers: buildHeaders(),
      body: JSON.stringify(sqlmapPayload),
    });

    if (!response.ok) {
      throw new Error(`sqlmap start failed ${response.status}: ${await response.text()}`);
    }

    const startPayload = await response.json();
    if (!isActiveRun(runId)) {
      return;
    }
    onSqlmapStart?.(startPayload);

    const immediateStatus = startPayload?.parts?.sqlmap?.status || startPayload?.job?.status;
    const jobId = startPayload?.job?.job_id || startPayload?.parts?.sqlmap?.job_id;

    if (!jobId || immediateStatus === "completed") {
      onSqlmapDone?.(startPayload);
      return;
    }
    if (immediateStatus === "failed") {
      onSqlmapError?.(startPayload?.parts?.sqlmap?.error || "sqlmap failed.", startPayload);
      return;
    }

    try {
      const finalPayload = await pollSqlmapJob(jobId, runId);
      if (finalPayload && isActiveRun(runId)) {
        onSqlmapDone?.(finalPayload);
      }
    } catch (error) {
      if (isActiveRun(runId)) {
        onSqlmapError?.(error instanceof Error ? error.message : String(error), startPayload);
      }
    }
  }

  async function submit(e) {
    e.preventDefault();

    const normalizedUrl = url.trim();
    if (!normalizedUrl) {
      onError?.(new Error("Enter a target URL."));
      return;
    }

    const safeMaxPages = Math.min(50, Math.max(1, Number(maxPages) || 1));
    const safeConcurrency = Math.min(5, Math.max(1, Number(concurrency) || 1));
    const safeLevel = Math.min(5, Math.max(1, Number(level) || 1));
    const safeRisk = Math.min(3, Math.max(1, Number(risk) || 1));
    const safeThreads = Math.min(10, Math.max(1, Number(threads) || 1));
    const runId = activeRunRef.current + 1;
    activeRunRef.current = runId;

    const sqlmapArgs = [`--level=${safeLevel}`, `--risk=${safeRisk}`, `--threads=${safeThreads}`, "--random-agent", "--batch"];
    if (tamper.trim()) {
      sqlmapArgs.push(`--tamper=${tamper.trim()}`);
    }

    const currentTarget = normalizeTarget(currentReport?.target);
    const canReuseCurrentScan = Boolean(
      runSqlmap &&
      currentReport?.scan_id &&
      currentTarget &&
      currentTarget === normalizeTarget(normalizedUrl)
    );

    try {
      if (canReuseCurrentScan) {
        await startSqlmap(currentReport.scan_id, normalizedUrl, safeConcurrency, sqlmapArgs, runId);
        return;
      }

      onBaseStart?.();

      const jsonBase = await startBaseScan(normalizedUrl, safeMaxPages, safeConcurrency, runId);
      if (!jsonBase) {
        return;
      }
      onBaseDone?.(jsonBase);

      if (!runSqlmap) {
        return;
      }

      const scanId = jsonBase.scan_id;
      if (!scanId) {
        throw new Error("scan_id was not returned by the backend, so sqlmap cannot start.");
      }

      await startSqlmap(scanId, normalizedUrl, safeConcurrency, sqlmapArgs, runId);
    } catch (err) {
      if (isActiveRun(runId)) {
        onError?.(err);
      }
    }
  }

  return (
    <form className="card form" onSubmit={submit}>
      <div className="form-row">
        <label className="label">Target URL</label>
        <input
          className="input"
          type="url"
          value={url}
          onChange={e => setUrl(e.target.value)}
          placeholder="https://example.com"
          required
        />
      </div>

      <div className="form-grid">
        <div className="form-row">
          <label className="label">Max pages</label>
          <input
            className="input"
            type="number"
            value={maxPages}
            onChange={e => setMaxPages(e.target.value)}
            min={1}
            max={50}
          />
        </div>
        <div className="form-row">
          <label className="label">Concurrency</label>
          <input
            className="input"
            type="number"
            value={concurrency}
            onChange={e => setConcurrency(e.target.value)}
            min={1}
            max={5}
          />
        </div>
        <div className="form-row inline">
          <label>
            <input type="checkbox" checked={runSqlmap} onChange={e => setRunSqlmap(e.target.checked)} /> Run sqlmap
          </label>
        </div>
      </div>

      {runSqlmap && (
        <div className="card small">
          <div className="form-grid">
            <div className="form-row">
              <label className="label">Level (1-5)</label>
              <input
                className="input"
                type="number"
                value={level}
                onChange={e => setLevel(Number(e.target.value))}
                min={1}
                max={5}
              />
            </div>
            <div className="form-row">
              <label className="label">Risk (1-3)</label>
              <input
                className="input"
                type="number"
                value={risk}
                onChange={e => setRisk(Number(e.target.value))}
                min={1}
                max={3}
              />
            </div>
            <div className="form-row">
              <label className="label">Threads</label>
              <input
                className="input"
                type="number"
                value={threads}
                onChange={e => setThreads(Number(e.target.value))}
                min={1}
                max={10}
              />
            </div>
            <div className="form-row">
              <label className="label">Tamper (optional)</label>
              <input
                className="input"
                type="text"
                value={tamper}
                onChange={e => setTamper(e.target.value)}
                placeholder="space2comment"
              />
            </div>
          </div>
          {currentReport?.scan_id && normalizeTarget(currentReport?.target) === normalizeTarget(url) && (
            <div className="muted" style={{ marginTop: 10 }}>
              Existing results for this target are already on screen. sqlmap will reuse the current scan and only update the sqlmap tab.
            </div>
          )}
        </div>
      )}

      <div style={{ display: "flex", gap: 8, marginTop: 12 }}>
        <button className="btn primary" type="submit">Start scan</button>
        <button
          className="btn"
          type="button"
          onClick={() => {
            setUrl("");
            setMaxPages(50);
            setConcurrency(5);
            setRunSqlmap(false);
            setLevel(3);
            setRisk(2);
            setThreads(5);
            setTamper("");
          }}
        >
          Clear
        </button>
      </div>
    </form>
  );
}
