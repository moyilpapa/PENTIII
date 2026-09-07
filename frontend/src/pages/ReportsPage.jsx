import { useState } from "react";
import { C, SEV } from "../theme";
import { Toolbar, TBtn, TSep, SubTabs, EmptyHint } from "../components/figma-ui";

function ReportPanel({ title, children, center }) {
  return <section style={{ minWidth: 0, padding: "14px 16px", background: C.panelB, border: `1px solid ${C.border}`, textAlign: center ? "center" : "left" }}><div style={{ color: C.fg, fontSize: 13, fontWeight: 650, marginBottom: 10 }}>{title}</div>{children}</section>;
}

function ReportField({ label, value, mono }) {
  return <div style={{ display: "grid", gridTemplateColumns: "104px minmax(0, 1fr)", gap: 12, padding: "9px 0", borderBottom: `1px solid ${C.border}`, textAlign: "left" }}><span style={{ color: C.fgDim, fontSize: 11 }}>{label}</span><span style={{ color: C.fgMid, fontSize: 11.5, fontFamily: mono ? "var(--font-mono)" : "inherit", wordBreak: "break-all" }}>{value}</span></div>;
}

function ReportBlock({ title, value, mono }) {
  return <div style={{ minWidth: 0 }}><div style={{ color: C.fgDim, fontSize: 10, fontWeight: 650, letterSpacing: "0.08em", textTransform: "uppercase", marginBottom: 5 }}>{title}</div><div style={{ minHeight: 38, padding: 9, background: C.bg, color: C.fgMid, fontSize: 10.5, lineHeight: 1.5, fontFamily: mono ? "var(--font-mono)" : "inherit", whiteSpace: "pre-wrap", wordBreak: "break-word" }}>{value}</div></div>;
}

function toMarkdown(report) {
  const sc = report.severity_counts;
  const findingsMd = report.findings
    .map(
      (f) =>
        `### F-${String(f.id).padStart(3, "0")} — ${f.name} [${f.severity.toUpperCase()}]\n\n**Endpoint:** \`${f.location || "—"}\`\n\n**Status:** ${f.status}${f.confidence ? `\n\n**Confidence:** ${f.confidence}` : ""}${f.detection_method ? `\n\n**Detection method:** ${f.detection_method}` : ""}\n\n${f.description || ""}\n\n**Evidence:**\n\`\`\`\n${f.evidence || "—"}\n\`\`\`\n\n**Remediation:** ${f.remediation || "—"}`
    )
    .join("\n\n---\n\n");
  return `# Security Assessment Report\n\n**Target:** ${report.target.name}\n**URL:** ${report.target.url}\n**Generated:** ${new Date(report.generated_at).toLocaleString()}\n\n## Summary\n\n| Severity | Count |\n|----------|-------|\n| High | ${sc.High} |\n| Medium | ${sc.Medium} |\n| Low | ${sc.Low} |\n\n## Methodology\n\n${report.methodology.map((m) => `- ${m}`).join("\n")}\n\n## Findings\n\n${findingsMd || "_No findings recorded._"}`;
}

export default function ReportsPage({ ctx }) {
  const { activeTarget, api, log, scanData, setScanData } = ctx;
  const [tab, setTab] = useState("preview");
  const [loading, setLoading] = useState(false);
  const [mode, setMode] = useState("auto");
  const report = scanData.report || null;
  const severityCounts = report?.severity_counts || { High: 0, Medium: 0, Low: 0 };
  const totalFindings = Object.values(severityCounts).reduce((sum, value) => sum + value, 0);
  const scanCounts = (report?.scans_performed || []).reduce((counts, scan) => {
    const key = scan.scan_type === "javascript" ? "JavaScript" : scan.scan_type === "sqli_advanced" ? "Advanced SQLi" : scan.scan_type === "sqli_sqlmap" ? "sqlmap" : scan.scan_type.charAt(0).toUpperCase() + scan.scan_type.slice(1);
    counts[key] = (counts[key] || 0) + 1;
    return counts;
  }, {});
  const riskScore = Math.min(100, severityCounts.High * 20 + severityCounts.Medium * 8 + severityCounts.Low * 2);
  const riskLabel = riskScore >= 70 ? "High Risk" : riskScore >= 35 ? "Moderate Risk" : "Low Risk";
  const scanTotal = Object.values(scanCounts).reduce((sum, value) => sum + value, 0);
  const scanProgress = Math.min(100, Math.round((scanTotal / 4) * 100));

  if (!activeTarget) {
    return <div style={{ flex: 1, display: "flex" }}><EmptyHint>Select or add a target in the Targets tab first.</EmptyHint></div>;
  }

  async function generate() {
    setLoading(true);
    try {
      const r = await api.getReport(activeTarget.id, mode);
      setScanData("report", r);
      log("ok", `report generated: ${r.findings.length} finding(s)`);
    } catch (e) {
      log("fail", e.message);
    } finally {
      setLoading(false);
    }
  }

  function copyMarkdown() {
    if (!report) return;
    navigator.clipboard?.writeText(toMarkdown(report));
    log("info", "report markdown copied to clipboard");
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", flex: 1, minHeight: 0 }}>
      <Toolbar>
        <TBtn icon="export" label={loading ? "Generating…" : "Generate Report"} accent disabled={loading} onClick={generate} />
        <button type="button" onClick={() => { setMode((current) => current === "auto" ? "manual" : "auto"); setScanData("report", null); }} aria-pressed={mode === "auto"} style={{ display: "flex", alignItems: "center", gap: 7, padding: "4px 9px", border: `1px solid ${mode === "auto" ? C.accent : C.border}`, borderRadius: 4, background: mode === "auto" ? C.accentDim : "transparent", color: mode === "auto" ? C.accent : C.fgMid, cursor: "pointer", font: "inherit", fontSize: 11.5 }}>
          <span style={{ width: 26, height: 15, padding: 2, background: mode === "auto" ? C.accentDim : C.panelC, border: `1px solid ${mode === "auto" ? C.accent : C.border}`, borderRadius: 8 }}><span style={{ display: "block", width: 9, height: 9, borderRadius: "50%", background: mode === "auto" ? C.accent : C.fgDim, transform: mode === "auto" ? "translateX(11px)" : "translateX(0)" }} /></span>
          {mode === "auto" ? "Auto Report" : "Manual Report"}
        </button>
        <TSep />
        <TBtn icon="copy" label="Copy Markdown" disabled={!report} onClick={copyMarkdown} />
      </Toolbar>
      <SubTabs
        tabs={[{ id: "preview", label: "Preview" }, { id: "raw", label: "Raw Markdown" }, { id: "summary", label: "Summary" }]}
        active={tab}
        set={setTab}
      />

      <div style={{ flex: 1, overflowY: "auto", padding: 20, background: C.bg }}>
        {!report && <EmptyHint>No report generated.</EmptyHint>}

        {report && tab === "preview" && (
          <div style={{ maxWidth: 1120, margin: "0 auto" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", padding: "18px 4px 20px", borderBottom: `1px solid ${C.borderMd}`, gap: 18 }}>
              <div><div style={{ fontSize: 25, fontWeight: 650, color: C.fg }}>Security <span style={{ color: C.accent }}>Assessment</span> Report</div><div style={{ marginTop: 7, fontSize: 14, color: C.info }}>PENTIII</div></div>
              <div style={{ color: C.fgMid, fontSize: 12, fontWeight: 700, letterSpacing: "0.08em" }}>PENTIII</div>
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "1.25fr 0.9fr 0.95fr", gap: 12, marginTop: 14 }}>
              <ReportPanel title="Overview">
                <ReportField label="Target" value={report.target.url} mono />
                <ReportField label="Scan Date" value={new Date(report.generated_at).toLocaleString()} />
                <ReportField label="Duration" value="Not recorded" />
                <ReportField label="Tester" value="PENTIII Scanner" />
              </ReportPanel>
              <ReportPanel title="Overall Risk Score" center>
                <div style={{ width: 150, height: 150, margin: "5px auto 0", borderRadius: "50%", background: `conic-gradient(from 220deg, ${C.critical} 0deg, ${C.high} ${riskScore * 2.4}deg, ${C.panelC} ${riskScore * 2.4}deg 300deg, transparent 300deg)`, padding: 10 }}>
                  <div style={{ width: "100%", height: "100%", borderRadius: "50%", background: C.panelB, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center" }}><strong style={{ fontSize: 34, color: C.fg, fontFamily: "var(--font-mono)" }}>{riskScore}</strong><span style={{ color: C.fgDim, fontSize: 11 }}>/100</span></div>
                </div>
                <div style={{ color: riskScore > 34 ? C.critical : C.low, fontSize: 14, fontWeight: 650, marginTop: 2 }}>{riskLabel}</div>
              </ReportPanel>
              <ReportPanel title="Risk Summary">
                {["Critical", "High", "Medium", "Low"].map((level) => { const count = level === "Critical" ? (severityCounts.Critical || 0) : severityCounts[level]; const color = level === "Critical" ? C.critical : SEV[level.toUpperCase()].fg; return <div key={level} style={{ display: "flex", alignItems: "center", gap: 9, padding: "9px 0", borderBottom: `1px solid ${C.border}` }}><span style={{ width: 10, height: 10, borderRadius: "50%", background: color }} /><span style={{ flex: 1, color: C.fgMid, fontSize: 12 }}>{level}</span><strong style={{ color: C.fg, fontFamily: "var(--font-mono)" }}>{count}</strong></div>; })}
              </ReportPanel>
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "1fr 1.05fr 0.95fr", gap: 12, marginTop: 12 }}>
              <ReportPanel title="Vulnerability Breakdown">
                {["Critical", "High", "Medium", "Low"].map((level) => { const count = level === "Critical" ? (severityCounts.Critical || 0) : severityCounts[level]; const color = level === "Critical" ? C.critical : SEV[level.toUpperCase()].fg; const width = totalFindings ? `${Math.max(4, (count / totalFindings) * 100)}%` : "0%"; return <div key={level} style={{ display: "grid", gridTemplateColumns: "58px 1fr 24px", alignItems: "center", gap: 8, margin: "14px 0", fontSize: 11, color: C.fgMid }}><span>{level}</span><div style={{ height: 14, background: C.panelC }}><div style={{ width, height: "100%", background: color }} /></div><span style={{ color: C.fg, fontFamily: "var(--font-mono)" }}>{count}</span></div>; })}
              </ReportPanel>
              <ReportPanel title="Top Vulnerabilities"><div style={{ color: C.fgDim, fontSize: 10, textAlign: "right", marginTop: -24, marginBottom: 6 }}>RISK</div>{report.findings.slice(0, 4).map((f) => { const severity = SEV[f.severity?.toUpperCase()] || SEV.INFO; return <div key={f.id} style={{ display: "flex", alignItems: "center", gap: 8, padding: "9px 0", borderBottom: `1px solid ${C.border}` }}><span style={{ flex: 1, color: C.fgMid, fontSize: 11.5, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{f.name}</span><span style={{ color: severity.fg, background: severity.bg, padding: "3px 8px", fontSize: 10, fontWeight: 700 }}>{f.severity?.toUpperCase()}</span></div>; })}{report.findings.length === 0 && <div style={{ color: C.fgDim, fontSize: 11.5 }}>No findings recorded.</div>}</ReportPanel>
              <ReportPanel title="Scan Progress" center><div style={{ width: 125, height: 125, margin: "8px auto 12px", borderRadius: "50%", background: `conic-gradient(${C.accent} ${scanProgress * 3.6}deg, ${C.panelC} 0deg)`, padding: 10 }}><div style={{ width: "100%", height: "100%", borderRadius: "50%", background: C.panelB, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center" }}><strong style={{ fontSize: 24, color: C.fg, fontFamily: "var(--font-mono)" }}>{scanProgress}%</strong><span style={{ color: C.accent, fontSize: 10 }}>Completed</span></div></div><div style={{ color: C.fgMid, fontSize: 11 }}>{scanTotal} scan runs recorded</div></ReportPanel>
            </div>

            <div style={{ marginTop: 22, borderBottom: `1px solid ${C.borderMd}`, paddingBottom: 8, color: C.fg, fontSize: 14, fontWeight: 650 }}>Findings <span style={{ float: "right", color: C.fgDim, fontSize: 10.5, fontWeight: 400, fontFamily: "var(--font-mono)" }}>{report.findings.length} recorded</span></div>
            <div style={{ marginTop: 10 }}>{report.findings.map((f, index) => { const severity = SEV[f.severity?.toUpperCase()] || SEV.INFO; return <article key={f.id} style={{ marginBottom: 12, padding: "14px 16px", background: C.panelB, border: `1px solid ${C.border}`, borderLeft: `3px solid ${severity.fg}` }}><div style={{ display: "flex", gap: 9, alignItems: "center" }}><span style={{ color: C.fgDim, fontSize: 10.5, fontFamily: "var(--font-mono)" }}>{String(index + 1).padStart(2, "0")}</span><span style={{ color: severity.fg, background: severity.bg, padding: "2px 6px", fontSize: 10, fontWeight: 700 }}>{f.severity?.toUpperCase() || "UNSPECIFIED"}</span><strong style={{ color: C.fg, fontSize: 13 }}>{f.name}</strong><span style={{ marginLeft: "auto", color: C.fgDim, fontSize: 10.5, fontFamily: "var(--font-mono)" }}>F-{String(f.id).padStart(3, "0")}</span></div><div style={{ margin: "10px 0", color: C.accent, fontSize: 11, fontFamily: "var(--font-mono)", wordBreak: "break-all" }}>{f.location || "Endpoint not specified"}</div><div style={{ display: "flex", gap: 18, color: C.fgDim, fontSize: 10.5, marginBottom: 8 }}><span>Status: <strong style={{ color: C.fgMid }}>{f.status || "Unconfirmed"}</strong></span>{f.confidence && <span>Confidence: <strong style={{ color: C.fgMid }}>{f.confidence}</strong></span>}{f.detection_method && <span>Method: <strong style={{ color: C.fgMid }}>{f.detection_method}</strong></span>}</div>{f.description && <div style={{ color: C.fgMid, fontSize: 11.5, lineHeight: 1.6, marginBottom: 10 }}>{f.description}</div>}<div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}><ReportBlock title="Evidence" value={f.evidence || "No evidence recorded."} mono /><ReportBlock title="Remediation" value={f.remediation || "No remediation recorded."} /></div></article>; })}</div>
          </div>
        )}

        {report && tab === "raw" && (
          <pre style={{ fontFamily: "var(--font-mono)", fontSize: 11.5, color: C.fgMid, lineHeight: 1.8, whiteSpace: "pre-wrap" }}>
            {toMarkdown(report)}
          </pre>
        )}

        {report && tab === "summary" && (
          <div style={{ maxWidth: 460 }}>
            {[
              ["Target", report.target.name],
              ["URL", report.target.url],
              ["Generated", new Date(report.generated_at).toLocaleString()],
              ["Total Findings", String(report.findings.length)],
              ["High", String(report.severity_counts.High)],
              ["Medium", String(report.severity_counts.Medium)],
              ["Low", String(report.severity_counts.Low)],
              ["Methodology", report.methodology.join("; ")],
            ].map(([k, v]) => (
              <div key={k} style={{ display: "flex", borderBottom: `1px solid ${C.border}`, padding: "7px 0" }}>
                <div style={{ width: 140, fontSize: 11, fontWeight: 600, color: C.fgDim, letterSpacing: "0.06em", textTransform: "uppercase", flexShrink: 0 }}>
                  {k}
                </div>
                <div style={{ fontSize: 11.5, color: C.fgMid }}>{v}</div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
