import { useEffect, useState } from "react";
import { C } from "../theme";
import { Toolbar, TBtn, TSep, SplitPane, PanelLabel, Th, Td, SevBadge, EmptyHint } from "../components/figma-ui";

const BLANK = {
  name: "", location: "", parameter: "", description: "", evidence: "",
  severity: "Medium", remediation: "", status: "Unconfirmed",
};

export default function FindingsPage({ ctx }) {
  const { activeTarget, api, log, findings, refreshFindings, autoFindings, findingSeed, clearFindingSeed } = ctx;
  const [filter, setFilter] = useState("ALL");
  const [sel, setSel] = useState(0);
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState(BLANK);
  const [saving, setSaving] = useState(false);
  const [viewMode, setViewMode] = useState("auto");

  useEffect(() => {
    if (findingSeed) {
      setForm({ ...BLANK, ...findingSeed });
      setShowForm(true);
      clearFindingSeed();
    }
  }, [findingSeed, clearFindingSeed]);

  if (!activeTarget) {
    return <div style={{ flex: 1, display: "flex" }}><EmptyHint>Select or add a target in the Targets tab first.</EmptyHint></div>;
  }

  const filters = ["ALL", "HIGH", "MEDIUM", "LOW"];
  const sourceFindings = viewMode === "auto" ? autoFindings : findings;
  const shown = filter === "ALL" ? sourceFindings : sourceFindings.filter((f) => f.severity.toUpperCase() === filter);
  const f = shown[sel] || shown[0];

  async function submit() {
    if (!form.name.trim()) return;
    setSaving(true);
    try {
      await api.createFinding({ ...form, target_id: activeTarget.id, status_mode: "manual" });
      log("ok", `finding recorded: ${form.name}`);
      setForm(BLANK);
      setShowForm(false);
      refreshFindings();
    } catch (e) {
      log("fail", e.message);
    } finally {
      setSaving(false);
    }
  }

  async function remove(id, name) {
    if (!confirm(`Delete finding "${name}"?`)) return;
    await api.deleteFinding(id);
    log("info", `finding deleted: ${name}`);
    refreshFindings();
  }

  async function setStatus(id, status) {
    try {
      await api.updateFinding(id, { status });
      refreshFindings();
    } catch (e) {
      log("fail", e.message);
    }
  }

  function exportJson() {
    const blob = new Blob([JSON.stringify(sourceFindings, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${activeTarget.name.replace(/\s+/g, "_")}_findings.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", flex: 1, minHeight: 0 }}>
      <Toolbar>
        <button type="button" onClick={() => setViewMode((mode) => mode === "auto" ? "manual" : "auto")} aria-pressed={viewMode === "auto"} style={{ display: "flex", alignItems: "center", gap: 7, padding: "4px 9px", border: `1px solid ${viewMode === "auto" ? C.accent : C.border}`, borderRadius: 4, background: viewMode === "auto" ? C.accentDim : "transparent", color: viewMode === "auto" ? C.accent : C.fgMid, cursor: "pointer", font: "inherit", fontSize: 11.5 }}>
          <span style={{ width: 26, height: 15, padding: 2, background: viewMode === "auto" ? C.accentDim : C.panelC, border: `1px solid ${viewMode === "auto" ? C.accent : C.border}`, borderRadius: 8 }}><span style={{ display: "block", width: 9, height: 9, borderRadius: "50%", background: viewMode === "auto" ? C.accent : C.fgDim, transform: viewMode === "auto" ? "translateX(11px)" : "translateX(0)" }} /></span>
          {viewMode === "auto" ? "Auto Findings" : "Manual Findings"}
        </button>
        {viewMode === "manual" && <>
          <TBtn icon="add" label="Add Finding" accent onClick={() => { setForm(BLANK); setShowForm((v) => !v); }} />
          <TBtn icon="trash" label="Remove" disabled={!f} onClick={() => f && remove(f.id, f.name)} />
        </>}
        <TSep />
        {filters.map((f2) => (
          <button
            key={f2}
            onClick={() => { setFilter(f2); setSel(0); }}
            style={{
              padding: "3px 10px", borderRadius: 3, border: `1px solid ${filter === f2 ? C.borderMd : C.border}`,
              cursor: "pointer", fontSize: 11, fontFamily: "inherit",
              background: filter === f2 ? "rgba(255,255,255,0.08)" : "transparent",
              color: filter === f2 ? C.fg : C.fgMid,
            }}
          >
            {f2}
          </button>
        ))}
        <TSep />
        <TBtn icon="export" label="Export JSON" disabled={!sourceFindings.length} onClick={exportJson} />
        <div style={{ flex: 1 }} />
        <span style={{ fontSize: 11, color: C.fgDim }}>{shown.length} issues</span>
      </Toolbar>

      {showForm && viewMode === "manual" && (
        <div style={{ padding: 12, background: C.panelB, borderBottom: `1px solid ${C.border}`, display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
          {[
            ["name", "Vulnerability name *", 2],
            ["location", "Affected URL / endpoint", 1],
            ["parameter", "Parameter (if applicable)", 1],
          ].map(([key, ph, span]) => (
            <input
              key={key}
              value={form[key]}
              onChange={(e) => setForm({ ...form, [key]: e.target.value })}
              placeholder={ph}
              style={{
                gridColumn: span === 2 ? "span 2" : "span 1", background: "rgba(255,255,255,0.04)",
                border: `1px solid ${C.border}`, borderRadius: 4, padding: "6px 9px", fontSize: 11.5,
                color: C.fg, fontFamily: "var(--font-mono)", outline: "none",
              }}
            />
          ))}
          {["description", "evidence", "remediation"].map((key) => (
            <textarea
              key={key}
              value={form[key]}
              onChange={(e) => setForm({ ...form, [key]: e.target.value })}
              placeholder={{ description: "Description", evidence: "Evidence", remediation: "Remediation recommendation" }[key]}
              rows={key === "description" ? 2 : 3}
              style={{
                gridColumn: "span 2", resize: "vertical", background: "rgba(255,255,255,0.04)",
                border: `1px solid ${C.border}`, borderRadius: 4, padding: "6px 9px", fontSize: 11.5,
                color: C.fg, fontFamily: "var(--font-mono)", outline: "none",
              }}
            />
          ))}
          <select
            value={form.severity}
            onChange={(e) => setForm({ ...form, severity: e.target.value })}
            style={{ background: "rgba(255,255,255,0.04)", border: `1px solid ${C.border}`, borderRadius: 4, padding: "6px 9px", fontSize: 11.5, color: C.fg }}
          >
            <option>Low</option><option>Medium</option><option>High</option>
          </select>
          <div style={{ display: "flex", justifyContent: "flex-end", gap: 8 }}>
            <TBtn label="Cancel" onClick={() => setShowForm(false)} />
            <TBtn label={saving ? "Saving…" : "Save Finding"} accent disabled={saving} onClick={submit} />
          </div>
        </div>
      )}

      <SplitPane
        defaultSplit={52}
        left={
          <div style={{ display: "flex", flexDirection: "column", height: "100%" }}>
            <PanelLabel>Issue List</PanelLabel>
            <div style={{ flex: 1, overflowY: "auto" }}>
              {shown.length === 0 ? (
                <EmptyHint>No findings recorded. Use the + button on flagged results in other tabs, or add one manually.</EmptyHint>
              ) : (
                <table style={{ width: "100%", borderCollapse: "collapse" }}>
                  <thead>
                    <tr>
                      <Th w={70}>Severity</Th>
                      <Th>Issue</Th>
                      <Th>Endpoint</Th>
                      <Th w={90}>Status</Th>
                    </tr>
                  </thead>
                  <tbody>
                    {shown.map((f2, i) => (
                      <tr key={f2.id} className={`trow${sel === i ? " selected" : ""}`} onClick={() => setSel(i)}>
                        <Td><SevBadge s={f2.severity.toUpperCase()} /></Td>
                        <Td style={{ color: C.fg, fontWeight: 500 }}>{f2.name}</Td>
                        <Td mono style={{ color: C.accent, fontSize: 11 }}>{f2.location || "—"}</Td>
                        <Td style={{ color: f2.status === "Confirmed" ? C.low : C.fgDim, fontSize: 11 }}>{f2.status}</Td>
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
            <PanelLabel actions={f && viewMode === "manual" && <TBtn icon="trash" title="Delete" onClick={() => remove(f.id, f.name)} />}>
              {f ? `F-${String(f.id).padStart(3, "0")} — ${f.name}` : "No finding selected"}
            </PanelLabel>
            {!f ? (
              <EmptyHint>Select a finding to view its detail.</EmptyHint>
            ) : (
              <div style={{ flex: 1, overflowY: "auto", padding: "14px 16px" }}>
                <div style={{ display: "flex", gap: 16, marginBottom: 16, paddingBottom: 12, borderBottom: `1px solid ${C.border}` }}>
                  <div>
                    <div style={{ fontSize: 10, color: C.fgDim, letterSpacing: "0.06em", textTransform: "uppercase", marginBottom: 3 }}>Severity</div>
                    <SevBadge s={f.severity.toUpperCase()} />
                  </div>
                  <div>
                    <div style={{ fontSize: 10, color: C.fgDim, letterSpacing: "0.06em", textTransform: "uppercase", marginBottom: 3 }}>Endpoint</div>
                    <span style={{ fontSize: 11.5, color: C.accent, fontFamily: "var(--font-mono)" }}>{f.location || "—"}</span>
                  </div>
                  <div>
                    <div style={{ fontSize: 10, color: C.fgDim, letterSpacing: "0.06em", textTransform: "uppercase", marginBottom: 3 }}>Status</div>
                    {viewMode === "manual" ? (
                      <select value={f.status} onChange={(e) => setStatus(f.id, e.target.value)} style={{ background: "transparent", color: f.status === "Confirmed" ? C.low : C.fgMid, fontSize: 11.5, border: "none" }}>
                        <option>Unconfirmed</option><option>Confirmed</option>
                      </select>
                    ) : (
                      <span title="Auto findings aren't saved yet — use “+ Add to Findings” to track and confirm one." style={{ fontSize: 11.5, color: f.status === "Confirmed" ? C.low : C.fgMid }}>
                        {f.status}
                      </span>
                    )}
                  </div>
                  {f.confidence && (
                    <div>
                      <div style={{ fontSize: 10, color: C.fgDim, letterSpacing: "0.06em", textTransform: "uppercase", marginBottom: 3 }}>Confidence</div>
                      <span style={{ fontSize: 11.5, color: C.fg }}>{f.confidence}</span>
                    </div>
                  )}
                  {f.detection_method && (
                    <div>
                      <div style={{ fontSize: 10, color: C.fgDim, letterSpacing: "0.06em", textTransform: "uppercase", marginBottom: 3 }}>Method</div>
                      <span style={{ fontSize: 11.5, color: C.fg }}>{f.detection_method}</span>
                    </div>
                  )}
                </div>

                {[
                  { label: "Description", val: f.description || "—" },
                  { label: "Evidence", val: f.evidence || "—", mono: true },
                  { label: "Remediation", val: f.remediation || "—" },
                ].map((s) => (
                  <div key={s.label} style={{ marginBottom: 14 }}>
                    <div style={{ fontSize: 10, fontWeight: 600, letterSpacing: "0.08em", textTransform: "uppercase", color: C.fgDim, marginBottom: 5 }}>
                      {s.label}
                    </div>
                    <div
                      style={{
                        fontSize: 11.5, color: C.fgMid, lineHeight: 1.75,
                        fontFamily: s.mono ? "var(--font-mono)" : "inherit",
                        padding: s.mono ? "8px 10px" : undefined, background: s.mono ? C.panelB : undefined,
                        border: s.mono ? `1px solid ${C.border}` : undefined, borderRadius: s.mono ? 4 : undefined,
                      }}
                    >
                      {s.val}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        }
      />
    </div>
  );
}
