import { useEffect, useState, useCallback } from "react";
import { C } from "./theme";
import Splash from "./components/Splash";
import { api } from "./api";
import { buildCollection } from "./collection";

import DashboardPage from "./pages/DashboardPage";
import TargetsPage from "./pages/TargetsPage";
import HttpPage from "./pages/HttpPage";
import EndpointsPage from "./pages/EndpointsPage";
import JavaScriptPage from "./pages/JavaScriptPage";
import SqliPage from "./pages/SqliPage";
import FindingsPage from "./pages/FindingsPage";
import ReportsPage from "./pages/ReportsPage";

const TABS = [
  { id: "dashboard", label: "Dashboard" },
  { id: "targets", label: "Targets" },
  { id: "http", label: "HTTP Analysis" },
  { id: "endpoints", label: "Endpoint Discovery" },
  { id: "javascript", label: "JavaScript" },
  { id: "sqli", label: "SQLi Test" },
  { id: "findings", label: "Findings" },
  { id: "reports", label: "Reports" },
];

function Page({ id, ctx }) {
  switch (id) {
    case "dashboard": return <DashboardPage ctx={ctx} />;
    case "targets": return <TargetsPage ctx={ctx} />;
    case "http": return <HttpPage ctx={ctx} />;
    case "endpoints": return <EndpointsPage ctx={ctx} />;
    case "javascript": return <JavaScriptPage ctx={ctx} />;
    case "sqli": return <SqliPage ctx={ctx} />;
    case "findings": return <FindingsPage ctx={ctx} />;
    case "reports": return <ReportsPage ctx={ctx} />;
    default: return <DashboardPage ctx={ctx} />;
  }
}

export default function App() {
  const [showSplash, setShowSplash] = useState(true);
  const dismissSplash = useCallback(() => setShowSplash(false), []);
  const [tab, setTab] = useState("dashboard");
  const [targets, setTargets] = useState([]);
  const [activeId, setActiveId] = useState(null);
  const [findings, setFindings] = useState([]);
  const [findingSeed, setFindingSeed] = useState(null);
  const [sqliSeed, setSqliSeed] = useState(null);
  const [scanData, setScanDataState] = useState({}); // { [targetId]: { http, endpoints, js, collection, sqliHistory, sqliAdvancedResult, sqliAdvancedStages, fullScanSqli } }
  const [scanProgress, setScanProgress] = useState([]); // live Full Scan stage list
  const [fullScanRunning, setFullScanRunning] = useState(false);
  const [log, setLog] = useState([]);
  const [apiDown, setApiDown] = useState(false);
  const [totalScans, setTotalScans] = useState(0);
  const [time, setTime] = useState(() => new Date().toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false }));
  const [startedAt] = useState(() => Date.now());

  useEffect(() => {
    const t = setInterval(() => setTime(new Date().toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false })), 1000);
    return () => clearInterval(t);
  }, []);

  const pushLog = useCallback((level, msg) => {
    const t = new Date().toLocaleTimeString("en-GB", { hour12: false });
    setLog((prev) => [...prev.slice(-300), { level, msg, time: t }]);
  }, []);

  const refreshTargets = useCallback(async () => {
    try {
      const rows = await api.listTargets();
      setTargets(rows);
      setApiDown(false);
      return rows;
    } catch {
      setApiDown(true);
      return [];
    }
  }, []);

  useEffect(() => {
    refreshTargets().then((rows) => {
      if (rows.length && !activeId) setActiveId(rows[0].id);
    });
    pushLog("info", "PENTIII initialized — backend expected at http://localhost:5050");
  }, []);

  const activeTarget = targets.find((t) => t.id === activeId) || null;

  const refreshFindings = useCallback(async () => {
    if (!activeId) { setFindings([]); return; }
    try {
      const rows = await api.listFindings(activeId);
      setFindings(rows);
    } catch {
      setFindings([]);
    }
  }, [activeId]);

  // Auto-detected findings (from the SQLi engine's scan history) are a
  // separate data source from manually-created ones -- see
  // build_auto_findings() on the backend. Lifted here (rather than fetched
  // locally inside FindingsPage, as before) so the Dashboard's summary
  // stats can reflect real scan results too, not just whatever's been
  // manually promoted into a saved finding.
  const [autoFindings, setAutoFindings] = useState([]);
  const refreshAutoFindings = useCallback(async () => {
    if (!activeId) { setAutoFindings([]); return; }
    try {
      const rows = await api.listAutoFindings(activeId);
      setAutoFindings(rows);
    } catch {
      setAutoFindings([]);
    }
  }, [activeId]);

  useEffect(() => {
    refreshFindings();
    refreshAutoFindings();
    if (activeId) {
      api.getScans(activeId).then((s) => setTotalScans(s.length)).catch(() => setTotalScans(0));
    } else {
      setTotalScans(0);
    }
    setScanProgress([]); // don't show a previous target's stale Full Scan progress
  }, [activeId, refreshFindings, refreshAutoFindings]);

  function setScanDataForTarget(targetId, key, value) {
    setScanDataState((prev) => ({ ...prev, [targetId]: { ...(prev[targetId] || {}), [key]: value } }));
  }

  async function runFullScan() {
    if (!activeTarget || fullScanRunning) return;
    const target = activeTarget;
    const targetId = target.id;
    setFullScanRunning(true);

    let stages = [
      { stage: "HTTP Analysis", status: "Pending" },
      { stage: "Endpoint Discovery", status: "Pending" },
      { stage: "JavaScript Analysis", status: "Pending" },
      { stage: "Endpoint Collection", status: "Pending" },
      { stage: "SQL Injection Testing", status: "Pending" },
    ];
    setScanProgress(stages);
    const update = (i, status, detail) => {
      stages = stages.map((s, idx) => (idx === i ? { ...s, status, ...(detail ? { detail } : {}) } : s));
      setScanProgress(stages);
    };

    pushLog("run", `full scan started → ${target.url}`);
    let scansSaved = 0;

    try {
      update(0, "Running");
      const httpResult = await api.scanHttp(targetId);
      setScanDataForTarget(targetId, "http", httpResult);
      scansSaved++;
      update(0, httpResult.ok ? "Complete" : "Failed", httpResult.ok ? `status ${httpResult.status_code}, ${httpResult.flags.length} flag(s)` : httpResult.error);
      pushLog(httpResult.ok ? "ok" : "fail", `HTTP analysis: ${httpResult.ok ? `status ${httpResult.status_code}` : httpResult.error}`);

      update(1, "Running");
      const endpointResult = await api.scanEndpoints(targetId);
      setScanDataForTarget(targetId, "endpoints", endpointResult);
      scansSaved++;
      update(1, "Complete", `${endpointResult.found.length} of ${endpointResult.checked} responded`);
      pushLog("ok", `endpoint discovery: ${endpointResult.found.length} of ${endpointResult.checked} responded`);

      update(2, "Running");
      const jsResult = await api.scanJs(targetId);
      setScanDataForTarget(targetId, "js", jsResult);
      scansSaved++;
      update(2, jsResult.ok ? "Complete" : "Failed", jsResult.ok ? `${jsResult.scripts_found} script(s)` : jsResult.error);
      pushLog(jsResult.ok ? "ok" : "fail", `JS analysis: ${jsResult.ok ? `${jsResult.scripts_found} script(s), ${jsResult.unique_endpoints.length} endpoint-like string(s)` : jsResult.error}`);

      update(3, "Running");
      const collection = buildCollection(target.url, endpointResult, jsResult.ok ? jsResult : null);
      setScanDataForTarget(targetId, "collection", collection);
      update(3, "Complete", `${collection.parameterized_endpoints} parameterized endpoint(s)`);
      pushLog("ok", `endpoint collection: ${collection.total_endpoints} total, ${collection.parameterized_endpoints} parameterized`);

      update(4, "Running");
      const paramEndpoints = collection.endpoints.filter((e) => e.has_parameters);
      if (paramEndpoints.length === 0) {
        update(4, "Skipped", "no parameterized endpoints found");
        pushLog("info", "SQL injection testing skipped — no parameterized endpoints discovered");
      } else {
        const sqliResults = [];
        for (const ep of paramEndpoints) {
          for (const param of ep.parameters) {
            let originalValue = "1";
            try {
              originalValue = new URL(ep.url).searchParams.get(param) ?? "1";
            } catch {
              // fall back to default
            }
            try {
              const r = await api.scanSqliAdvanced(targetId, {
                url: ep.url, parameter: param, original_value: originalValue,
                enabled: { error: true, boolean: false, time: false, union: false },
              });
              sqliResults.push({ url: ep.url, parameter: param, ...r });
              scansSaved++;
              if (r.ok && r.vulnerable) {
                pushLog("fail", `SQLi: possible injection on "${param}" at ${ep.url} (confidence: ${r.confidence})`);
              }
            } catch (e) {
              sqliResults.push({ url: ep.url, parameter: param, ok: false, error: e.message });
            }
          }
        }
        setScanDataForTarget(targetId, "fullScanSqli", sqliResults);
        const vulnCount = sqliResults.filter((r) => r.ok && r.vulnerable).length;
        update(4, "Complete", `${sqliResults.length} parameter(s) tested, ${vulnCount} flagged`);
        pushLog(vulnCount ? "fail" : "ok", `SQL injection testing complete: ${sqliResults.length} parameter(s) tested, ${vulnCount} flagged`);
      }

      bumpScans(scansSaved);
      refreshTargets();
      refreshFindings();
      refreshAutoFindings();
      pushLog("ok", `full scan complete for ${target.name}`);
    } catch (e) {
      pushLog("fail", `full scan error: ${e.message}`);
      refreshAutoFindings(); // scan may have run partially -- still worth reflecting what it found
    } finally {
      setFullScanRunning(false);
    }
  }

  function seedFinding(f) {
    setFindingSeed(f);
    setTab("findings");
  }

  const clearFindingSeed = useCallback(() => setFindingSeed(null), []);
  const clearSqliSeed = useCallback(() => setSqliSeed(null), []);

  function bumpScans(n = 1) {
    setTotalScans((t) => t + n);
  }

  // Scan results are keyed per target so switching tabs -- or switching targets --
  // never silently discards a result you already have. Only re-running a scan
  // (or explicitly clearing) changes what's shown.
  function setScanData(key, value) {
    if (!activeId) return;
    setScanDataState((prev) => ({ ...prev, [activeId]: { ...(prev[activeId] || {}), [key]: value } }));
  }
  const currentScanData = scanData[activeId] || {};

  function seedSqli(s) {
    setSqliSeed(s);
    setTab("sqli");
  }

  const sessionMinutes = Math.floor((Date.now() - startedAt) / 60000);
  const findingsHigh = findings.filter((f) => f.severity === "High").length;
  const findingsMed = findings.filter((f) => f.severity === "Medium").length;
  const findingsLow = findings.filter((f) => f.severity === "Low").length;

  const baseCtx = {
    targets, activeId, activeTarget, setActiveId,
    findings, refreshFindings, findingSeed, clearFindingSeed, seedFinding,
    autoFindings, refreshAutoFindings,
    sqliSeed, clearSqliSeed, seedSqli,
    api, apiDown, totalScans, refreshTargets, bumpScans,
    scanData: currentScanData, setScanData,
    runFullScan, scanProgress, fullScanRunning,
    setFullScanRunning, setScanProgress,
    showAddTarget: () => setTab("targets"),
  };
  // Every page gets `log` as a callable logger. The Dashboard additionally needs
  // the raw log array to render the activity feed, so it gets its own context shape.
  const pageCtx = { ...baseCtx, log: pushLog };
  const dashboardCtx = { ...baseCtx, log };

  return (
    <>
      {showSplash && <Splash duration={2000} onDone={dismissSplash} />}
      <div style={{ display: "flex", flexDirection: "column", height: "100vh", background: C.bg, overflow: "hidden", fontFamily: "var(--font-display)" }}>
      <div style={{ display: "flex", alignItems: "center", height: 34, background: C.panel, borderBottom: `1px solid ${C.border}`, flexShrink: 0 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "0 14px", borderRight: `1px solid ${C.border}`, height: "100%" }}>
          <img src="/logo.png" alt="PENTIII" style={{ width: 22, height: 22, objectFit: "contain", display: "block" }} />
          <span style={{ fontSize: 12, fontWeight: 700, color: C.fg, letterSpacing: "0.06em" }}>PENTIII</span>
          <span style={{ fontSize: 10, color: C.fgDim, letterSpacing: "0.04em" }}>v1.0</span>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 6, padding: "0 14px", borderRight: `1px solid ${C.border}`, height: "100%" }}>
          <span style={{ fontSize: 11, color: C.fgDim }}>Target</span>
          <select
            value={activeId || ""}
            onChange={(e) => setActiveId(e.target.value ? Number(e.target.value) : null)}
            aria-label="Active target"
            style={{ maxWidth: 230, background: "transparent", border: "none", color: C.fgMid, fontSize: 11.5, fontFamily: "var(--font-mono)", outline: "none" }}
          >
            {!targets.length && <option value="">none selected</option>}
            {targets.map((target) => <option key={target.id} value={target.id}>{target.name}</option>)}
          </select>
        </div>
        <div style={{ flex: 1 }} />
        <div style={{ display: "flex", alignItems: "center", gap: 10, padding: "0 14px", height: "100%" }}>
          <div className={apiDown ? "" : "pulse-dot"} style={{ width: 6, height: 6, borderRadius: "50%", background: apiDown ? C.critical : C.accent }} />
          <span style={{ fontSize: 11, color: C.fgDim }}>{apiDown ? "backend unreachable" : activeTarget ? `${activeTarget.url} · active` : "no target"}</span>
          <span style={{ fontSize: 11, color: C.fgDim, fontFamily: "var(--font-mono)", borderLeft: `1px solid ${C.border}`, paddingLeft: 10 }}>{time}</span>
          <span style={{ fontSize: 11, color: C.medium, borderLeft: `1px solid ${C.border}`, paddingLeft: 10 }}>{findings.length} findings</span>
        </div>
      </div>

      <div className="scrollbar-thin" style={{ display: "flex", alignItems: "stretch", height: 32, background: C.panelB, borderBottom: `1px solid ${C.border}`, flexShrink: 0, overflowX: "auto" }}>
        {TABS.map((t) => (
          <button key={t.id} onClick={() => setTab(t.id)} style={{ display: "flex", alignItems: "center", gap: 6, padding: "0 16px", border: "none", cursor: "pointer", fontFamily: "inherit", fontSize: 12, whiteSpace: "nowrap", background: tab === t.id ? C.panelC : "transparent", color: tab === t.id ? C.fg : C.fgMid, borderBottom: tab === t.id ? `2px solid ${C.accent}` : "2px solid transparent", borderRight: `1px solid ${C.border}`, fontWeight: tab === t.id ? 600 : 400 }}>
            {t.label}{t.id === "findings" && findings.length > 0 && <span style={{ fontSize: 10, fontWeight: 700, color: C.critical, background: "rgba(224,85,85,0.12)", borderRadius: 3, padding: "1px 5px" }}>{findings.length}</span>}
          </button>
        ))}
      </div>

      {apiDown && (
        <div style={{ padding: "6px 14px", background: "rgba(224,85,85,0.1)", borderBottom: "1px solid rgba(224,85,85,0.3)", color: C.critical, fontSize: 11, fontFamily: "var(--font-mono)" }}>
          Can't reach the API at localhost:5050 — start the Flask backend (`python app.py` in /backend).
        </div>
      )}

      <div className="scrollbar-thin" style={{ display: "flex", flex: 1, overflow: "auto", minHeight: 0 }}>
        <Page id={tab} ctx={tab === "dashboard" ? dashboardCtx : pageCtx} />
      </div>

      <div style={{ display: "flex", alignItems: "center", gap: 0, height: 22, background: C.panelB, borderTop: `1px solid ${C.border}`, flexShrink: 0 }}>
        {[
          activeTarget ? activeTarget.url : "no target",
          `Session: ${sessionMinutes}m`,
          `Scans: ${totalScans}`,
          `Findings: ${findings.length} (${findingsHigh}H · ${findingsMed}M · ${findingsLow}L)`,
          `Mode: Authorized assessment`,
        ].map((s, i) => (
          <span key={i} style={{ fontSize: 10.5, color: C.fgDim, padding: "0 10px", borderRight: `1px solid ${C.border}`, fontFamily: "var(--font-mono)", height: "100%", display: "flex", alignItems: "center" }}>
            {s}
          </span>
        ))}
        <div style={{ flex: 1 }} />
        <span style={{ fontSize: 10.5, color: apiDown ? C.critical : C.fgDim, padding: "0 10px", fontFamily: "var(--font-mono)", borderLeft: `1px solid ${C.border}`, height: "100%", display: "flex", alignItems: "center" }}>
          {apiDown ? "Offline" : "Ready"}
        </span>
      </div>
    </div>
    </>
  );
}
