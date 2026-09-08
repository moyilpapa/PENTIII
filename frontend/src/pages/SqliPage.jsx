import { useEffect, useState } from "react";
import { C } from "../theme";
import { Toolbar, TBtn, TSep, TInput, SubTabs, SplitPane, PanelLabel, Th, Td, SevBadge, FieldRow, EmptyHint } from "../components/figma-ui";

const DEFAULT_ENABLED = { error: true, boolean: true, time: true, union: true };
const DEFAULT_CONFIG = { request_timeout: 8, max_requests: 25, verification_attempts: 2, timing_threshold: 3.0, rate_limit_delay: 0 };

function QuickTest({ ctx }) {
  const { activeTarget, api, log, seedFinding, bumpScans, scanData, setScanData, refreshAutoFindings } = ctx;
  const [running, setRunning] = useState(false);
  const [sel, setSel] = useState(null);
  const history = scanData.sqliHistory || [];

  // This component stays mounted across target switches (only switching tabs
  // unmounts it) -- without this, a scan left running for a *previous* target
  // would leave this button permanently stuck on "Testing..." after you
  // switch to a different target, and the parameter field would keep
  // showing the old target's leftover value.
  useEffect(() => {
    setParam("id");
    setRunning(false);
    setSel(null);
  }, [activeTarget.id]);

  async function run() {
    if (!param.trim()) return;
    setRunning(true);
    log("run", `error-based SQLi test → parameter "${param}"`);
    try {
      const r = await api.scanSqli(activeTarget.id, param.trim());
      bumpScans();
      const next = [...history, { ...r, parameter: param.trim() }];
      setScanData("sqliHistory", next);
      setSel(next.length - 1);
      if (!r.ok) log("fail", r.error);
      else if (r.vulnerable) log("fail", `possible SQL injection on "${param}" — ${r.matched_signatures.length} signature(s) matched`);
      else log("ok", `no error-based signatures found on "${param}"`);
      refreshAutoFindings();
    } catch (e) {
      log("fail", e.message);
    } finally {
      setRunning(false);
    }
  }

  const p = sel !== null ? history[sel] : null;

  return (
    <div style={{ display: "flex", flexDirection: "column", flex: 1, minHeight: 0 }}>
      <Toolbar>
        <span style={{ fontSize: 11, color: C.fgDim, whiteSpace: "nowrap" }}>Base URL</span>
        <TInput value={activeTarget.url} disabled style={{ width: 230, flex: "none" }} />
        <span style={{ fontSize: 11, color: C.fgDim, whiteSpace: "nowrap" }}>Parameter</span>
        <TInput value={param} onChange={setParam} style={{ width: 140, flex: "none" }} placeholder="id" onKeyDown={(e) => e.key === "Enter" && run()} />
        <TSep />
        <TBtn icon="play" label={running ? "Testing…" : "Run Test"} accent disabled={running || !param.trim()} onClick={run} />
      </Toolbar>

      <SplitPane
        defaultSplit={55}
        left={
          <div style={{ display: "flex", flexDirection: "column", height: "100%" }}>
            <PanelLabel>Probes ({history.length})</PanelLabel>
            <div style={{ flex: 1, overflowY: "auto" }}>
              {history.length === 0 ? (
                <EmptyHint>Run a test against a parameter to see probes here.</EmptyHint>
              ) : (
                <table style={{ width: "100%", borderCollapse: "collapse" }}>
                  <thead>
                    <tr>
                      <Th w={34}>#</Th>
                      <Th>Parameter</Th>
                      <Th w={70}>Status</Th>
                      <Th>Result</Th>
                      <Th w={70}>Flag</Th>
                    </tr>
                  </thead>
                  <tbody>
                    {history.map((h, i) => (
                      <tr
                        key={i}
                        className={`trow${sel === i ? " selected" : ""}`}
                        onClick={() => setSel(i)}
                        style={{ background: h.ok && h.vulnerable ? "rgba(224,85,85,0.05)" : "transparent" }}
                      >
                        <Td style={{ color: C.fgDim, textAlign: "center" }}>{i + 1}</Td>
                        <Td mono style={{ color: C.fg }}>{h.parameter}</Td>
                        <Td mono style={{ color: h.ok ? C.low : C.critical }}>{h.ok ? h.injected_status : "err"}</Td>
                        <Td style={{ color: h.ok && h.vulnerable ? C.medium : C.fgDim, fontSize: 11 }}>
                          {h.ok ? (h.vulnerable ? `${h.matched_signatures.length} signature(s) matched` : "No signatures found") : h.error}
                        </Td>
                        <Td>{h.ok && h.vulnerable ? <SevBadge s="HIGH" /> : <span style={{ color: C.fgDim, fontSize: 11 }}>—</span>}</Td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </div>
        }
        right={
          <div style={{ display: "flex", flexDirection: "column", height: "100%", borderLeft: `1px solid ${C.border}` }}>
            <PanelLabel
              actions={
                p?.ok && p.vulnerable && (
                  <TBtn
                    icon="add"
                    label="Add to Findings"
                    onClick={() =>
                      seedFinding({
                        name: `Possible SQL Injection — parameter "${p.parameter}"`,
                        location: p.injected_url,
                        parameter: p.parameter,
                        description: "Injecting a single quote into this parameter produced a response matching known SQL error signatures.",
                        severity: "High",
                        detection_method: "Error-Based",
                        http_method: "GET",
                        confidence: "Medium",
                        evidence: p.matched_signatures.join(", "),
                      })
                    }
                  />
                )
              }
            >
              {p ? "Probe Detail" : "Select a probe"}
            </PanelLabel>
            {!p ? (
              <EmptyHint>Run a test to see probe detail here.</EmptyHint>
            ) : !p.ok ? (
              <div style={{ padding: 14 }}><FieldRow label="Error" value={p.error} /></div>
            ) : (
              <div style={{ flex: 1, overflowY: "auto", padding: 14 }}>
                <FieldRow label="Parameter" value={p.parameter} mono />
                <FieldRow label="Normal URL" value={p.normal_url} mono />
                <FieldRow label="Injected URL" value={p.injected_url} mono />
                <FieldRow label="Normal Status" value={p.normal_status} mono />
                <FieldRow label="Injected Status" value={p.injected_status} mono />
                <FieldRow label="Flag" value={p.vulnerable ? "Possible SQL Injection" : "Clean (no known signature)"} />
                {p.matched_signatures.length > 0 && (
                  <FieldRow label="Matched Signatures" value={p.matched_signatures.join(", ")} mono />
                )}
                <div style={{ marginTop: 4, padding: "10px", background: C.panelB, border: `1px solid ${C.border}`, borderRadius: 4 }}>
                  <div style={{ fontSize: 10.5, fontWeight: 600, color: C.fgDim, marginBottom: 6, letterSpacing: "0.06em", textTransform: "uppercase" }}>
                    Note
                  </div>
                  <div style={{ fontSize: 11.5, color: C.fgMid, lineHeight: 1.7 }}>{p.note}</div>
                </div>
              </div>
            )}
          </div>
        }
      />
    </div>
  );
}

function ConfigRow({ label, value, onChange, step, min }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
      <span style={{ fontSize: 11, color: C.fgDim, whiteSpace: "nowrap" }}>{label}</span>
      <input
        type="number"
        value={value}
        step={step || 1}
        min={min ?? 0}
        onChange={(e) => onChange(parseFloat(e.target.value))}
        style={{
          width: 62, background: "rgba(255,255,255,0.04)", border: `1px solid ${C.border}`, borderRadius: 4,
          padding: "3px 6px", fontSize: 11, color: C.fg, fontFamily: "var(--font-mono)",
        }}
      />
    </div>
  );
}

function AdvancedEngine({ ctx }) {
  const { activeTarget, api, log, seedFinding, sqliSeed, clearSqliSeed, bumpScans, scanData, setScanData, refreshAutoFindings } = ctx;
  const [url, setUrl] = useState(activeTarget.url);
  const [param, setParam] = useState("id");
  const [originalValue, setOriginalValue] = useState("1");
  const [enabled, setEnabled] = useState(DEFAULT_ENABLED);
  const [config, setConfig] = useState(DEFAULT_CONFIG);
  const [requestMethod, setRequestMethod] = useState("GET");
  const [parameterLocation, setParameterLocation] = useState("QUERY");
  const [otherFields, setOtherFields] = useState("");
  const [showConfig, setShowConfig] = useState(false);
  const [cookieInput, setCookieInput] = useState("");
  const [running, setRunning] = useState(false);
  const stages = scanData.sqliAdvancedStages || [];
  const result = scanData.sqliAdvancedResult || null;

  // Re-sync per-target UI state whenever the *active target* changes --
  // this component stays mounted across target switches (only switching
  // *tabs* unmounts it), so without this a scan left running for a
  // *previous* target would leave this button stuck on "Running..." after
  // switching targets, and the parameter/value fields would keep showing
  // the previous target's leftover input.
  useEffect(() => {
    setUrl(activeTarget.url);
    setParam("id");
    setOriginalValue("1");
    if (/\/api\/challenges\//i.test(activeTarget.url)) {
      setParam("username");
      setRequestMethod("POST");
      setParameterLocation("JSON");
      setOtherFields("password=test");
    } else {
      setRequestMethod("GET");
      setParameterLocation("QUERY");
      setOtherFields("");
    }
    setRunning(false);
  }, [activeTarget.id]);

  useEffect(() => {
    if (sqliSeed) {
      setUrl(sqliSeed.url);
      setParam(sqliSeed.parameter);
      if (sqliSeed.originalValue !== undefined) setOriginalValue(sqliSeed.originalValue);
      clearSqliSeed();
    }
  }, [sqliSeed]);

  const METHOD_LABELS = {
    error: "Error-Based SQLi", boolean: "Boolean-Based Blind SQLi",
    time: "Time-Based Blind SQLi", union: "UNION-Based Analysis",
  };

  async function run() {
    if (!param.trim() || !url.trim()) return;
    setRunning(true);
    setScanData("sqliAdvancedResult", null);
    const plannedStages = [
      { stage: "Baseline Request", status: "Running" },
      { stage: "Stability Check", status: "Pending" },
      ...Object.entries(enabled).filter(([, v]) => v).map(([k]) => ({ stage: METHOD_LABELS[k], status: "Pending" })),
      { stage: "Response Analysis", status: "Pending" },
      { stage: "Validation", status: "Pending" },
      { stage: "Confidence Calculation", status: "Pending" },
    ];
    setScanData("sqliAdvancedStages", plannedStages);
    log("run", `advanced SQLi engine → ${url} [${param}], methods: ${Object.entries(enabled).filter(([, v]) => v).map(([k]) => k).join(", ")}`);

    try {
      const cookies = {};
      cookieInput.split(";").forEach((pair) => {
        const idx = pair.indexOf("=");
        if (idx > 0) {
          const name = pair.slice(0, idx).trim();
          const value = pair.slice(idx + 1).trim();
          if (name) cookies[name] = value;
        }
      });
      const formParams = {};
      otherFields.split(",").forEach((pair) => {
        const idx = pair.indexOf("=");
        if (idx > 0) formParams[pair.slice(0, idx).trim()] = pair.slice(idx + 1).trim();
      });
      const r = await api.scanSqliAdvanced(activeTarget.id, {
        url, parameter: param.trim(), original_value: originalValue, enabled,
        config: { ...config, method: requestMethod, parameter_location: parameterLocation, form_params: formParams, ...(Object.keys(cookies).length ? { cookies } : {}) },
      });
      setScanData("sqliAdvancedResult", r);
      bumpScans();
      if (r.ok) {
        setScanData("sqliAdvancedStages", r.stages);
        log(r.vulnerable ? "fail" : "ok", r.summary + ` (${r.requests_used} request(s) used)`);
      } else {
        log("fail", r.error);
        setScanData("sqliAdvancedStages", r.stages?.length ? r.stages : [{ stage: "Baseline Request", status: "Failed" }]);
      }
      refreshAutoFindings();
    } catch (e) {
      log("fail", e.message);
    } finally {
      setRunning(false);
    }
  }

  const stageColor = (status) =>
    status === "Complete" ? C.low : status === "Skipped" ? C.fgDim : status?.startsWith("Stopped") || status === "Failed" ? C.critical : C.medium;

  return (
    <div style={{ display: "flex", flexDirection: "column", flex: 1, minHeight: 0 }}>
      <Toolbar>
        <span style={{ fontSize: 11, color: C.fgDim, whiteSpace: "nowrap" }}>URL</span>
        <TInput value={url} onChange={setUrl} style={{ width: 260, flex: "none" }} />
        <span style={{ fontSize: 11, color: C.fgDim, whiteSpace: "nowrap" }}>Param</span>
        <TInput value={param} onChange={setParam} style={{ width: 90, flex: "none" }} />
        <span style={{ fontSize: 11, color: C.fgDim, whiteSpace: "nowrap" }}>Baseline value</span>
        <TInput value={originalValue} onChange={setOriginalValue} style={{ width: 70, flex: "none" }} />
        <TSep />
        <TBtn icon="play" label={running ? "Running…" : "Run Engine"} accent disabled={running || !param.trim()} onClick={run} />
        <TBtn icon="filter" label="Configure" onClick={() => setShowConfig((v) => !v)} />
      </Toolbar>

      <div style={{ display: "flex", alignItems: "center", gap: 14, padding: "6px 10px", background: C.panelB, borderBottom: `1px solid ${C.border}`, flexShrink: 0, flexWrap: "wrap" }}>
        {Object.keys(DEFAULT_ENABLED).map((k) => (
          <label key={k} style={{ display: "flex", alignItems: "center", gap: 5, fontSize: 11.5, color: enabled[k] ? C.fg : C.fgDim, cursor: "pointer" }}>
            <input type="checkbox" checked={enabled[k]} onChange={(e) => setEnabled({ ...enabled, [k]: e.target.checked })} />
            {METHOD_LABELS[k]}
          </label>
        ))}
      </div>

      {showConfig && (
        <div style={{ display: "flex", flexDirection: "column", gap: 8, padding: "8px 10px", background: C.panelC, borderBottom: `1px solid ${C.border}` }}>
          <div style={{ display: "flex", alignItems: "center", gap: 16, flexWrap: "wrap" }}>
            <label style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 11, color: C.fgDim }}>
              Method
              <select value={requestMethod} onChange={(e) => setRequestMethod(e.target.value)} style={{ background: C.panelB, color: C.fg, border: `1px solid ${C.border}`, padding: "3px 5px", fontSize: 11 }}>
                <option>GET</option>
                <option>POST</option>
              </select>
            </label>
            <label style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 11, color: C.fgDim }}>
              Location
              <select value={parameterLocation} onChange={(e) => setParameterLocation(e.target.value)} style={{ background: C.panelB, color: C.fg, border: `1px solid ${C.border}`, padding: "3px 5px", fontSize: 11 }}>
                <option value="QUERY">Query</option>
                <option value="FORM">Form</option>
                <option value="JSON">JSON</option>
              </select>
            </label>
            <TInput value={otherFields} onChange={setOtherFields} placeholder="Other fields: password=test" style={{ width: 220, flex: "none" }} />
            <ConfigRow label="Timeout (s)" value={config.request_timeout} onChange={(v) => setConfig({ ...config, request_timeout: v })} />
            <ConfigRow label="Max Requests" value={config.max_requests} onChange={(v) => setConfig({ ...config, max_requests: v })} />
            <ConfigRow label="Verification Attempts" value={config.verification_attempts} onChange={(v) => setConfig({ ...config, verification_attempts: v })} min={1} />
            <ConfigRow label="Timing Threshold (s)" value={config.timing_threshold} step={0.5} onChange={(v) => setConfig({ ...config, timing_threshold: v })} />
            <ConfigRow label="Rate Limit (s)" value={config.rate_limit_delay} step={0.1} onChange={(v) => setConfig({ ...config, rate_limit_delay: v })} />
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <span style={{ fontSize: 11, color: C.fgDim, whiteSpace: "nowrap" }}>Session Cookie (name=value)</span>
            <TInput
              value={cookieInput}
              onChange={setCookieInput}
              placeholder="PHPSESSID=abc123; security=low"
              style={{ flex: 1, maxWidth: 340 }}
            />
          </div>
        </div>
      )}

      <SplitPane
        defaultSplit={40}
        direction="vertical"
        left={
          <div style={{ display: "flex", flexDirection: "column", height: "100%" }}>
            <PanelLabel>Scan Progress</PanelLabel>
            <div style={{ flex: 1, overflowY: "auto", padding: "8px 14px" }}>
              {stages.length === 0 ? (
                <EmptyHint>Run the engine to see live stage progress here.</EmptyHint>
              ) : (
                stages.map((s, i) => (
                  <div key={i} style={{ display: "flex", flexDirection: "column", padding: "4px 0", borderBottom: i < stages.length - 1 ? `1px dotted ${C.border}` : "none" }}>
                    <div style={{ display: "flex", justifyContent: "space-between" }}>
                      <span style={{ fontSize: 11.5, color: C.fgMid, fontFamily: "var(--font-mono)" }}>{s.stage}</span>
                      <span style={{ fontSize: 11, fontWeight: 600, color: stageColor(s.status) }}>{s.status}</span>
                    </div>
                    {s.detail && <span style={{ fontSize: 10.5, color: C.fgDim, marginTop: 1 }}>{s.detail}</span>}
                  </div>
                ))
              )}
              {result?.ok && (
                <div style={{ marginTop: 10, padding: "8px 10px", background: C.panelB, border: `1px solid ${C.border}`, borderRadius: 4 }}>
                  <div>
                    <span style={{ fontSize: 11.5, color: C.fg }}>Result: </span>
                    <span style={{ fontSize: 11.5, color: result.vulnerable ? C.critical : C.low, fontWeight: 600 }}>
                      {result.vulnerable ? "Potential SQL Injection" : "No vulnerability detected"}
                    </span>
                    {result.state && (
                      <span style={{
                        marginLeft: 8, fontSize: 10, fontWeight: 700, letterSpacing: "0.04em", padding: "1px 6px", borderRadius: 3,
                        color: result.state === "CONFIRMED" ? C.critical : result.state === "LIKELY" ? C.medium : C.fgDim,
                        background: result.state === "CONFIRMED" ? "rgba(224,85,85,0.12)" : result.state === "LIKELY" ? "rgba(201,152,26,0.12)" : "rgba(255,255,255,0.05)",
                      }}>
                        {result.state}
                      </span>
                    )}
                  </div>
                  {result.confidence_score !== undefined && (
                    <div style={{ marginTop: 6, fontSize: 11, color: C.fgDim }}>
                      Confidence score: <span style={{ color: C.fg, fontFamily: "var(--font-mono)" }}>{result.confidence_score}/100</span>
                      {" — "}{result.confidence_label}
                      {result.validated_methods?.length > 0 && (
                        <span> · validated: {result.validated_methods.join(", ")}</span>
                      )}
                    </div>
                  )}
                  {result.stability?.checked && !result.stability.stable && (
                    <div style={{ marginTop: 4, fontSize: 10.5, color: C.medium }}>
                      ⚠ Page content is not stable between identical requests (similarity {result.stability.similarity}) —
                      content-based results were discounted accordingly.
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        }
        right={
          <div style={{ display: "flex", flexDirection: "column", height: "100%", borderTop: `1px solid ${C.border}` }}>
            <PanelLabel
              actions={
                result?.ok && result.vulnerable && (
                  <TBtn
                    icon="add"
                    label="Add to Findings"
                    accent
                    onClick={() =>
                      seedFinding({
                        name: `Possible SQL Injection — parameter "${result.parameter}"`,
                        location: result.url,
                        parameter: result.parameter,
                        severity: result.confidence === "High" ? "High" : result.confidence === "Medium" ? "Medium" : "Low",
                        detection_method: result.triggered_methods.join(", "),
                        http_method: result.http_method,
                        confidence: result.confidence,
                        description: `${result.summary}${result.confidence_score !== undefined ? ` (score: ${result.confidence_score}/100, ${result.confidence_label})` : ""}`,
                        evidence: result.tests.filter((t) => t.triggered).map((t) => `${t.method}: ${t.evidence_note || "triggered"}`).join(" | "),
                      })
                    }
                  />
                )
              }
            >
              Test Results
            </PanelLabel>
            <div style={{ flex: 1, overflowY: "auto" }}>
              {!result ? (
                <EmptyHint>Run the engine to see per-method results here.</EmptyHint>
              ) : !result.ok ? (
                <div style={{ padding: 14, fontSize: 11.5, color: C.critical, fontFamily: "var(--font-mono)" }}>{result.error}</div>
              ) : (
                <table style={{ width: "100%", borderCollapse: "collapse" }}>
                  <thead>
                    <tr>
                      <Th w={150}>Method</Th>
                      <Th w={90}>State</Th>
                      <Th w={70}>Triggered</Th>
                      <Th w={70}>Validated</Th>
                      <Th>Evidence</Th>
                    </tr>
                  </thead>
                  <tbody>
                    {result.tests.map((t, i) => (
                      <tr key={i} className="trow">
                        <Td style={{ color: C.fg }}>{t.method}</Td>
                        <Td style={{
                          fontWeight: 700, fontSize: 10.5,
                          color: t.state === "CONFIRMED" ? C.critical : t.state === "LIKELY" ? C.medium : t.state === "INCONCLUSIVE" ? C.info : C.fgDim,
                        }}>
                          {t.state || "—"}
                        </Td>
                        <Td style={{ color: t.triggered ? C.critical : C.low, fontWeight: 600 }}>{t.ran ? (t.triggered ? "Yes" : "No") : "N/A"}</Td>
                        <Td style={{ color: t.validated ? C.low : C.fgDim, fontWeight: 600 }}>{t.triggered ? (t.validated ? "Yes" : "No") : "—"}</Td>
                        <Td style={{ fontSize: 11, color: C.fgMid }}>{t.error || t.evidence_note || "—"}</Td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </div>
        }
      />
    </div>
  );
}

function FullScanResults({ ctx }) {
  const { activeTarget, scanData, seedFinding } = ctx;
  const results = scanData.fullScanSqli || [];

  if (results.length === 0) {
    return (
      <div style={{ flex: 1, display: "flex" }}>
        <EmptyHint>
          No Full Scan results yet for {activeTarget.name}. Run "Run Full Scan" from the Dashboard to
          automatically test every parameterized endpoint discovered for this target.
        </EmptyHint>
      </div>
    );
  }

  const flagged = results.filter((r) => r.ok && r.vulnerable);

  return (
    <div style={{ display: "flex", flexDirection: "column", flex: 1, minHeight: 0 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 14, padding: "6px 10px", background: C.panelB, borderBottom: `1px solid ${C.border}`, flexShrink: 0 }}>
        <span style={{ fontSize: 11, color: C.fgDim }}>{results.length} parameter(s) tested automatically</span>
        <span style={{ fontSize: 11, color: flagged.length ? C.critical : C.low }}>{flagged.length} flagged</span>
      </div>
      <div style={{ flex: 1, overflowY: "auto" }}>
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead>
            <tr>
              <Th w={90}>State</Th>
              <Th>URL</Th>
              <Th w={100}>Parameter</Th>
              <Th w={90}>Confidence</Th>
              <Th w={110}>Action</Th>
            </tr>
          </thead>
          <tbody>
            {results.map((r, i) => (
              <tr key={i} className="trow" style={{ background: r.ok && r.vulnerable ? "rgba(224,85,85,0.05)" : "transparent" }}>
                <Td style={{
                  fontWeight: 700, fontSize: 10.5,
                  color: r.ok ? (r.state === "CONFIRMED" ? C.critical : r.state === "LIKELY" ? C.medium : r.state === "INCONCLUSIVE" ? C.info : C.fgDim) : C.critical,
                }}>
                  {r.ok ? (r.state || "—") : "err"}
                </Td>
                <Td mono style={{ fontSize: 11, color: C.fg }}>{r.url}</Td>
                <Td mono style={{ color: C.accent }}>{r.parameter}</Td>
                <Td style={{ color: r.ok ? (r.vulnerable ? C.critical : C.fgDim) : C.fgDim, fontSize: 11 }}>
                  {r.ok ? `${r.confidence}${r.confidence_score !== undefined ? ` (${r.confidence_score}/100)` : ""}` : r.error}
                </Td>
                <Td>
                  {r.ok && r.vulnerable && (
                    <TBtn
                      icon="add"
                      label="Add"
                      onClick={() =>
                        seedFinding({
                          name: `Possible SQL Injection — parameter "${r.parameter}"`,
                          location: r.url,
                          parameter: r.parameter,
                          severity: r.confidence === "High" ? "High" : r.confidence === "Medium" ? "Medium" : "Low",
                          detection_method: r.triggered_methods.join(", "),
                          http_method: r.http_method,
                          confidence: r.confidence,
                          description: `${r.summary}${r.confidence_score !== undefined ? ` (score: ${r.confidence_score}/100, ${r.confidence_label})` : ""}`,
                          evidence: r.tests.filter((t) => t.triggered).map((t) => `${t.method}: ${t.evidence_note || "triggered"}`).join(" | "),
                        })
                      }
                    />
                  )}
                </Td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export default function SqliPage({ ctx }) {
  const { activeTarget, scanData } = ctx;
  const [sub, setSub] = useState("advanced");

  if (!activeTarget) {
    return <div style={{ flex: 1, display: "flex" }}><EmptyHint>Select or add a target in the Targets tab first.</EmptyHint></div>;
  }

  const fullScanCount = (scanData.fullScanSqli || []).length;

  return (
    <div style={{ display: "flex", flexDirection: "column", flex: 1, minHeight: 0 }}>
      <SubTabs
        tabs={[
          { id: "advanced", label: "Advanced Engine" },
          { id: "quick", label: "Quick Test (Error-Based)" },
          { id: "fullscan", label: `Full Scan Results${fullScanCount ? ` (${fullScanCount})` : ""}` },
        ]}
        active={sub}
        set={setSub}
      />
      <div style={{ display: "flex", flex: 1, minHeight: 0 }}>
        {sub === "advanced" && <AdvancedEngine ctx={ctx} />}
        {sub === "quick" && <QuickTest ctx={ctx} />}
        {sub === "fullscan" && <FullScanResults ctx={ctx} />}
      </div>
    </div>
  );
}
