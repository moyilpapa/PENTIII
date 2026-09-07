import { useState } from "react";
import { C, ICO } from "../theme";
import { SplitPane, PanelLabel, TBtn, Th, Td, SevBadge, Ico, EmptyHint } from "../components/figma-ui";

export default function DashboardPage({ ctx }) {
  const { targets, activeId, activeTarget, setActiveId, findings, autoFindings, log, showAddTarget, runFullScan, scanProgress, fullScanRunning } = ctx;
  const [openHost, setOpenHost] = useState(activeId);

  // The Dashboard is the primary landing page after running a scan, so it
  // needs to reflect what that scan actually found -- not just findings
  // someone has manually reviewed and saved. `findings` (manual, curated)
  // and `autoFindings` (derived live from scan history, unreviewed) are
  // deliberately separate data sources -- see FindingsPage's Auto/Manual
  // toggle -- but showing only the manual side here means a real scan
  // result could silently read as "0 findings" until someone happens to
  // open the Findings tab and notice it under the Auto view.
  const combinedFindings = [...findings, ...autoFindings];
  const severityRank = { High: 0, Medium: 1, Low: 2 };
  const sortedFindings = [...combinedFindings].sort(
    (a, b) => (severityRank[a.severity] ?? 3) - (severityRank[b.severity] ?? 3)
  );

  const findingsBySeverity = { High: 0, Medium: 0, Low: 0 };
  for (const f of combinedFindings) if (findingsBySeverity[f.severity] !== undefined) findingsBySeverity[f.severity]++;

  const stats = [
    { label: "Targets", val: String(targets.length), dot: C.accent },
    { label: "Scans Run", val: String(ctx.totalScans ?? 0), dot: C.info },
    { label: "Findings", val: String(combinedFindings.length), dot: C.high },
    { label: "High", val: String(findingsBySeverity.High), dot: C.critical },
    { label: "Medium", val: String(findingsBySeverity.Medium), dot: C.medium },
    { label: "Low", val: String(findingsBySeverity.Low), dot: C.low },
  ];

  const stageColor = (status) =>
    status === "Complete" ? C.low : status === "Skipped" ? C.fgDim
      : status === "Failed" ? C.critical : status === "Running" ? C.medium : C.fgDim;

  return (
    <div style={{ display: "flex", flexDirection: "column", flex: 1, minHeight: 0 }}>
      <div style={{ display: "flex", alignItems: "center", background: C.panelB, borderBottom: `1px solid ${C.border}`, flexShrink: 0 }}>
        {stats.map((s) => (
          <div key={s.label} style={{ display: "flex", alignItems: "center", gap: 6, padding: "5px 14px", borderRight: `1px solid ${C.border}` }}>
            <div style={{ width: 6, height: 6, borderRadius: "50%", background: s.dot, flexShrink: 0 }} />
            <span style={{ fontSize: 10.5, color: C.fgDim, textTransform: "uppercase", letterSpacing: "0.06em" }}>{s.label}</span>
            <span style={{ fontSize: 12, fontWeight: 700, color: C.fg, fontFamily: "var(--font-mono)" }}>{s.val}</span>
          </div>
        ))}
        <div style={{ flex: 1 }} />
          <div style={{ padding: "0 12px" }}>
            <TBtn
              icon="play"
              label={fullScanRunning ? "Scanning…" : "Run Scan"}
              accent
              disabled={!activeTarget || fullScanRunning}
              title={activeTarget ? `Run checks against ${activeTarget.name}` : "Select a target first"}
              onClick={runFullScan}
            />
          </div>
      </div>

      {scanProgress.length > 0 && (
        <div style={{ display: "flex", alignItems: "stretch", background: C.panelC, borderBottom: `1px solid ${C.border}`, flexShrink: 0, overflowX: "auto" }}>
          {scanProgress.map((s, i) => (
            <div
              key={i}
              style={{
                display: "flex", flexDirection: "column", gap: 2, padding: "6px 14px",
                borderRight: i < scanProgress.length - 1 ? `1px solid ${C.border}` : "none", minWidth: 140,
              }}
            >
              <span style={{ fontSize: 10, color: C.fgDim, letterSpacing: "0.04em" }}>{s.stage}</span>
              <span style={{ fontSize: 11, fontWeight: 600, color: stageColor(s.status) }}>
                {s.status}{s.detail ? ` — ${s.detail}` : ""}
              </span>
            </div>
          ))}
        </div>
      )}

      <SplitPane
        defaultSplit={28}
        left={
          <div style={{ display: "flex", flexDirection: "column", height: "100%", borderRight: `1px solid ${C.border}` }}>
            <PanelLabel actions={<TBtn icon="add" label="Add" title="Add target" onClick={showAddTarget} />}>Target Scope</PanelLabel>
            <div style={{ flex: 1, overflowY: "auto", padding: "4px 0" }}>
              {targets.length === 0 && <EmptyHint>No targets registered yet.</EmptyHint>}
              {targets.map((t) => (
                <div key={t.id}>
                  <div
                    onClick={() => { setOpenHost(openHost === t.id ? null : t.id); setActiveId(t.id); }}
                    className="trow"
                    style={{
                      display: "flex", alignItems: "center", gap: 6, padding: "4px 10px", cursor: "pointer",
                      background: activeId === t.id ? "rgba(255,255,255,0.04)" : "transparent",
                    }}
                  >
                    <Ico d={openHost === t.id ? ICO.chevD : ICO.chevR} s={10} c={C.fgDim} />
                    <span style={{ fontSize: 11.5, color: C.fg, fontFamily: "var(--font-mono)", flex: 1 }}>{t.name}</span>
                    <span style={{ fontSize: 10, color: t.status !== "Not Started" ? C.accent : C.fgDim, letterSpacing: "0.06em" }}>
                      {t.status === "Not Started" ? "idle" : "active"}
                    </span>
                  </div>
                  {openHost === t.id && (
                    <div style={{ display: "flex", alignItems: "center", gap: 6, padding: "3px 10px 3px 28px" }}>
                      <span style={{ color: C.fgDim, fontSize: 11 }}>—</span>
                      <span style={{ fontSize: 11, color: C.fgMid, fontFamily: "var(--font-mono)" }}>{t.url}</span>
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        }
        right={
          <SplitPane
            defaultSplit={55}
            direction="vertical"
            left={
              <div style={{ display: "flex", flexDirection: "column", height: "100%" }}>
                <PanelLabel>Activity Log</PanelLabel>
                <div style={{ flex: 1, overflowY: "auto", padding: "6px 0", background: C.bg }}>
                  {log.length === 0 && <EmptyHint>No activity yet — run a scan from any tab.</EmptyHint>}
                  {[...log].reverse().map((l, i) => (
                    <div
                      key={i}
                      style={{
                        padding: "2px 12px", fontFamily: "var(--font-mono)", fontSize: 11, lineHeight: 1.7,
                        color: l.level === "fail" ? C.critical : l.level === "warn" ? C.medium : l.level === "ok" ? C.low : C.fgDim,
                      }}
                    >
                      [{l.time}] {l.msg}
                    </div>
                  ))}
                </div>
              </div>
            }
            right={
              <div style={{ display: "flex", flexDirection: "column", height: "100%", borderTop: `1px solid ${C.border}` }}>
                <PanelLabel>Findings Summary</PanelLabel>
                <div style={{ flex: 1, overflowY: "auto" }}>
                  {combinedFindings.length === 0 ? (
                    <EmptyHint>No findings recorded yet.</EmptyHint>
                  ) : (
                    <table style={{ width: "100%", borderCollapse: "collapse" }}>
                      <thead>
                        <tr>
                          <Th>Severity</Th>
                          <Th>Issue</Th>
                          <Th>Endpoint</Th>
                          <Th>Status</Th>
                        </tr>
                      </thead>
                      <tbody>
                        {sortedFindings.slice(0, 8).map((f) => (
                          <tr key={f.status_mode === "auto" ? `auto-${f.id}` : f.id} className="trow">
                            <Td><SevBadge s={f.severity.toUpperCase()} /></Td>
                            <Td style={{ color: C.fg }}>{f.name}{f.status_mode === "auto" ? " (auto)" : ""}</Td>
                            <Td mono style={{ fontSize: 11 }}>{f.location || "—"}</Td>
                            <Td style={{ color: f.status === "Confirmed" ? C.low : C.fgDim, fontSize: 11 }}>{f.status}</Td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}
                </div>
              </div>
            }
          />
        }
      />
    </div>
  );
}
