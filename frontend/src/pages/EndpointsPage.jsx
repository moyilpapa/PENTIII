import { useState } from "react";
import { C } from "../theme";
import { Toolbar, TBtn, TSep, SubTabs, SplitPane, PanelLabel, Th, Td, FieldRow, EmptyHint } from "../components/figma-ui";

export default function EndpointsPage({ ctx }) {
  const { activeTarget, api, log, seedFinding, seedSqli, bumpScans, scanData, setScanData, refreshAutoFindings } = ctx;
  const [sub, setSub] = useState("discovery");
  const [running, setRunning] = useState(false);
  const [sel, setSel] = useState(null);
  const [collecting, setCollecting] = useState(false);
  const [selEp, setSelEp] = useState(null);
  const result = scanData.endpoints || null;
  const collection = scanData.collection || null;

  // A reachable .env/.git/backup path commonly exposes actual secrets,
  // credentials, or full source history the moment it's reachable -- a
  // materially different risk than an admin/config/debug/swagger panel
  // being *reachable*, which is worth investigating but doesn't by itself
  // confirm anything sensitive was exposed. Treating every match here as
  // the same "Medium" severity understated the first group and could
  // overstate the second.
  function sensitivePathSeverity(path) {
    if (/\.env|\.git|backup/i.test(path)) return "High";
    return "Medium";
  }

  if (!activeTarget) {
    return <div style={{ flex: 1, display: "flex" }}><EmptyHint>Select or add a target in the Targets tab first.</EmptyHint></div>;
  }

  async function run() {
    setRunning(true);
    log("run", `endpoint discovery → ${activeTarget.url} (fixed wordlist)`);
    try {
      const r = await api.scanEndpoints(activeTarget.id);
      setScanData("endpoints", r);
      bumpScans();
      setSel(0);
      log(r.found.length ? "warn" : "ok", `checked ${r.checked} paths, ${r.found.length} responded`);
      refreshAutoFindings();
    } catch (e) {
      log("fail", e.message);
    } finally {
      setRunning(false);
    }
  }

  async function runCollect() {
    setCollecting(true);
    log("run", `endpoint collection → merging Endpoint Discovery + JavaScript Analysis for ${activeTarget.url}`);
    try {
      const r = await api.collectEndpoints(activeTarget.id);
      setScanData("collection", r);
      bumpScans(3); // collect saves endpoint + javascript + collection scan rows server-side
      setSelEp(0);
      log("ok", `${r.total_endpoints} endpoint(s) collected, ${r.parameterized_endpoints} with parameters`);
      refreshAutoFindings();
    } catch (e) {
      log("fail", e.message);
    } finally {
      setCollecting(false);
    }
  }

  const rows = result?.all_results || [];
  const p = sel !== null ? rows[sel] : null;
  const statusColor = (s) => (s == null ? C.fgDim : String(s).startsWith("2") ? C.low : String(s).startsWith("4") ? C.medium : C.critical);

  const epRows = collection?.endpoints || [];
  const ep = selEp !== null ? epRows[selEp] : null;

  return (
    <div style={{ display: "flex", flexDirection: "column", flex: 1, minHeight: 0 }}>
      <SubTabs tabs={[{ id: "discovery", label: "Discovery" }, { id: "collection", label: "Collection (+ JS)" }]} active={sub} set={setSub} />

      {sub === "discovery" && (
        <>
          <Toolbar>
            <span style={{ fontSize: 11, color: C.fgDim, fontFamily: "var(--font-mono)" }}>{activeTarget.url}</span>
            <TSep />
            <TBtn icon="play" label={running ? "Running…" : "Discover"} accent disabled={running} onClick={run} />
          </Toolbar>

          {result && (
            <div style={{ display: "flex", alignItems: "center", gap: 10, padding: "3px 10px", background: C.panelB, borderBottom: `1px solid ${C.border}`, flexShrink: 0 }}>
              <div style={{ flex: 1, height: 2, background: "rgba(255,255,255,0.06)", borderRadius: 2, overflow: "hidden" }}>
                <div style={{ height: "100%", width: "100%", background: C.accent, borderRadius: 2 }} />
              </div>
              <span style={{ fontSize: 10.5, color: C.fgDim, whiteSpace: "nowrap" }}>
                {result.checked}/{result.checked} paths · {result.found.length} responded · Complete
              </span>
            </div>
          )}

          <SplitPane
            defaultSplit={58}
            left={
              <div style={{ display: "flex", flexDirection: "column", height: "100%" }}>
                <PanelLabel>Discovered Paths {result && `(${result.checked} checked)`}</PanelLabel>
                <div style={{ flex: 1, overflowY: "auto" }}>
                  {rows.length === 0 ? (
                    <EmptyHint>No discovery results.</EmptyHint>
                  ) : (
                    <table style={{ width: "100%", borderCollapse: "collapse" }}>
                      <thead>
                        <tr>
                          <Th w={34}>#</Th>
                          <Th>Path</Th>
                          <Th w={70}>Status</Th>
                          <Th w={80}>Length</Th>
                        </tr>
                      </thead>
                      <tbody>
                        {rows.map((r, i) => (
                          <tr key={r.path} className={`trow${sel === i ? " selected" : ""}`} onClick={() => setSel(i)}>
                            <Td style={{ color: C.fgDim, textAlign: "center" }}>{i + 1}</Td>
                            <Td mono style={{ color: r.exists ? C.fg : C.fgDim }}>{r.path}</Td>
                            <Td mono style={{ color: statusColor(r.status_code) }}>{r.status_code ?? "err"}</Td>
                            <Td mono style={{ color: C.fgDim }}>{r.content_length ?? "—"}</Td>
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
                <PanelLabel>Path Detail</PanelLabel>
                {!p ? (
                  <EmptyHint>Select a discovered path.</EmptyHint>
                ) : (
                  <div style={{ flex: 1, overflowY: "auto", padding: 14 }}>
                    <FieldRow label="Path" value={p.path} mono />
                    <FieldRow label="URL" value={p.url} mono />
                    <FieldRow label="Request Method" value="GET" mono />
                    <FieldRow label="Status" value={p.status_code ?? "no response"} mono />
                    <FieldRow label="Content Length" value={p.content_length ?? "—"} mono />
                    <FieldRow label="Content Type" value={p.content_type || "unknown"} />
                    <FieldRow label="Server" value={p.server || "unknown"} />
                    <FieldRow label="Assessment" value={p.classification || "Not Confirmed"} />
                    {p.final_url && p.final_url !== p.url && <FieldRow label="Final URL" value={p.final_url} mono />}
                    {p.redirect_location && <FieldRow label="Redirect Location" value={p.redirect_location} mono />}
                    <FieldRow label="Exists" value={p.exists ? "Yes — responded" : "No / not found"} />
                    {p.error && <FieldRow label="Error" value={p.error} />}
                    {p.assessment && (
                      <div style={{ margin: "4px 0 12px", padding: 10, background: C.panelB, border: `1px solid ${C.border}`, borderLeft: `3px solid ${p.classification === "Reachable" ? C.medium : C.accent}`, borderRadius: 3 }}>
                        <div style={{ fontSize: 10, fontWeight: 600, letterSpacing: "0.08em", textTransform: "uppercase", color: C.fgDim, marginBottom: 4 }}>Interpretation</div>
                        <div style={{ fontSize: 11.5, color: C.fgMid, lineHeight: 1.55 }}>{p.assessment}</div>
                        <div style={{ marginTop: 7, fontSize: 11, color: C.fgDim, lineHeight: 1.5 }}><strong style={{ color: C.fgMid }}>Next checks:</strong> {p.next_checks}</div>
                      </div>
                    )}
                    {p.body_snippet && (
                      <div style={{ marginTop: 12 }}>
                        <div style={{ fontSize: 10, fontWeight: 600, letterSpacing: "0.08em", textTransform: "uppercase", color: C.fgDim, marginBottom: 5 }}>
                          Response Preview
                        </div>
                        <pre style={{ margin: 0, padding: 10, maxHeight: 180, overflow: "auto", whiteSpace: "pre-wrap", wordBreak: "break-word", background: C.panelB, border: `1px solid ${C.border}`, borderRadius: 4, color: C.fgMid, fontSize: 10.5, lineHeight: 1.5 }}>
                          {p.body_snippet}
                        </pre>
                      </div>
                    )}
                    {p.headers && Object.keys(p.headers).length > 0 && (
                      <div style={{ marginTop: 12 }}>
                        <div style={{ fontSize: 10, fontWeight: 600, letterSpacing: "0.08em", textTransform: "uppercase", color: C.fgDim, marginBottom: 5 }}>
                          Response Headers
                        </div>
                        <pre style={{ margin: 0, padding: 10, maxHeight: 180, overflow: "auto", whiteSpace: "pre-wrap", wordBreak: "break-word", background: C.panelB, border: `1px solid ${C.border}`, borderRadius: 4, color: C.fgMid, fontSize: 10.5, lineHeight: 1.5 }}>
                          {Object.entries(p.headers).map(([name, value]) => `${name}: ${value}`).join("\n")}
                        </pre>
                      </div>
                    )}
                    {p.status_code != null && p.status_code < 300 && p.path.match(/admin|config|backup|\.env|\.git|swagger|actuator|debug/i) && (
                      <div style={{ marginTop: 16 }}>
                        <TBtn
                          icon="add"
                          label="Add to Findings"
                          accent
                          onClick={() =>
                            seedFinding({
                              name: `Review access control: ${p.path}`,
                              location: `${result.base_url}${p.path}`,
                              description: `A sensitive-looking path returned a reachable HTTP response. This is an assessment lead, not proof of unauthorized access or data exposure.`,
                              severity: sensitivePathSeverity(p.path),
                              evidence: `HTTP ${p.status_code} on ${p.path}; Content-Type: ${p.content_type || "unknown"}`,
                            })
                          }
                        />
                      </div>
                    )}
                  </div>
                )}
              </div>
            }
          />
        </>
      )}

      {sub === "collection" && (
        <>
          <Toolbar>
            <span style={{ fontSize: 11, color: C.fgDim, fontFamily: "var(--font-mono)" }}>{activeTarget.url}</span>
            <TSep />
            <TBtn icon="refresh" label={collecting ? "Collecting…" : "Collect Endpoints"} accent disabled={collecting} onClick={runCollect} />
          </Toolbar>

          {collection && (
            <div style={{ display: "flex", alignItems: "center", gap: 16, padding: "3px 10px", background: C.panelB, borderBottom: `1px solid ${C.border}`, flexShrink: 0 }}>
              <span style={{ fontSize: 11, color: C.fgDim }}>{collection.total_endpoints} total endpoint(s)</span>
              <span style={{ fontSize: 11, color: C.accent }}>{collection.parameterized_endpoints} with parameters (SQLi-eligible)</span>
            </div>
          )}

          <SplitPane
            defaultSplit={60}
            left={
              <div style={{ display: "flex", flexDirection: "column", height: "100%" }}>
                <PanelLabel>Endpoint Collection</PanelLabel>
                <div style={{ flex: 1, overflowY: "auto" }}>
                  {epRows.length === 0 ? (
                    <EmptyHint>
                      {collecting ? "Discovering and analyzing…" : "Run Collect Endpoints to merge wordlist discovery with JavaScript-extracted URLs."}
                    </EmptyHint>
                  ) : (
                    <table style={{ width: "100%", borderCollapse: "collapse" }}>
                      <thead>
                        <tr>
                          <Th w={34}>#</Th>
                          <Th>URL</Th>
                          <Th w={110}>Parameters</Th>
                          <Th w={130}>Source</Th>
                        </tr>
                      </thead>
                      <tbody>
                        {epRows.map((e, i) => (
                          <tr key={e.url} className={`trow${selEp === i ? " selected" : ""}`} onClick={() => setSelEp(i)}>
                            <Td style={{ color: C.fgDim, textAlign: "center" }}>{i + 1}</Td>
                            <Td mono style={{ color: e.has_parameters ? C.fg : C.fgDim, fontSize: 11 }}>{e.url}</Td>
                            <Td style={{ color: e.has_parameters ? C.accent : C.fgDim }}>{e.parameters.join(", ") || "—"}</Td>
                            <Td style={{ fontSize: 10.5, color: C.fgDim }}>{e.sources.join(" + ")}</Td>
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
                <PanelLabel>Endpoint Detail</PanelLabel>
                {!ep ? (
                  <EmptyHint>Select an endpoint to view detail, or send it to the SQLi engine.</EmptyHint>
                ) : (
                  <div style={{ flex: 1, overflowY: "auto", padding: 14 }}>
                    <FieldRow label="URL" value={ep.url} mono />
                    <FieldRow label="Discovered Via" value={ep.sources.join(", ")} />
                    <FieldRow label="Parameters" value={ep.parameters.length ? ep.parameters.join(", ") : "none"} mono />
                    {ep.has_parameters && (
                      <div style={{ marginTop: 16, display: "flex", flexDirection: "column", gap: 6 }}>
                        {ep.parameters.map((param) => (
                          <TBtn
                            key={param}
                            icon="send"
                            label={`Test "${param}" with SQLi Engine`}
                            accent
                            onClick={() => {
                              const currentValue = new URL(ep.url).searchParams.get(param) ?? "1";
                              seedSqli({ url: ep.url, parameter: param, originalValue: currentValue });
                            }}
                          />
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </div>
            }
          />
        </>
      )}
    </div>
  );
}
