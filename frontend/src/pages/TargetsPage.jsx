import { useState } from "react";
import { C } from "../theme";
import { Toolbar, TBtn, TSep, TInput, SplitPane, PanelLabel, Th, Td, FieldRow, EmptyHint } from "../components/figma-ui";

export default function TargetsPage({ ctx }) {
  const { targets, activeId, setActiveId, api, log, refreshTargets, setFullScanRunning, setScanProgress } = ctx;
  const [filter, setFilter] = useState("");
  const [showForm, setShowForm] = useState(false);
  const [name, setName] = useState("");
  const [url, setUrl] = useState("");
  const [saving, setSaving] = useState(false);
  const [err, setErr] = useState("");

  const shown = targets.filter(
    (t) => !filter.trim() || t.name.toLowerCase().includes(filter.toLowerCase()) || t.url.toLowerCase().includes(filter.toLowerCase())
  );
  const selected = targets.find((t) => t.id === activeId) || null;

  async function createTarget() {
    if (!name.trim() || !url.trim()) return;
    setSaving(true);
    setErr("");
    try {
      const t = await api.createTarget(name.trim(), url.trim());
      log("ok", `target registered: ${t.name} (${t.url})`);
      setName("");
      setUrl("");
      setShowForm(false);
      await refreshTargets();
      setActiveId(t.id);
    } catch (e) {
      setErr(e.message);
    } finally {
      setSaving(false);
    }
  }

  async function removeTarget(id, tname) {
    if (!confirm(`Delete target "${tname}"? This removes its scans and findings too.`)) return;
    setFullScanRunning(false);
    setScanProgress([]);
    await api.deleteTarget(id);
    log("info", `target removed: ${tname}`);
    if (activeId === id) setActiveId(null);
    await refreshTargets();
  }

  const protoOf = (u) => (u.startsWith("https") ? "HTTPS" : "HTTP");

  return (
    <div style={{ display: "flex", flexDirection: "column", flex: 1, minHeight: 0 }}>
      <Toolbar>
        <TBtn icon="add" label="New Target" accent onClick={() => setShowForm((v) => !v)} />
        <TSep />
        <TBtn icon="trash" label="Remove" disabled={!selected} onClick={() => selected && removeTarget(selected.id, selected.name)} />
        <TSep />
        <TInput placeholder="Filter targets…" value={filter} onChange={setFilter} style={{ width: 220, flex: "none" }} />
      </Toolbar>

      {showForm && (
        <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "8px 10px", background: C.panelB, borderBottom: `1px solid ${C.border}` }}>
          <TInput placeholder="Target name (e.g. Juice Shop)" value={name} onChange={setName} style={{ width: 220, flex: "none" }} />
          <TInput placeholder="http://localhost:3000" value={url} onChange={setUrl} style={{ width: 260, flex: "none" }}
            onKeyDown={(e) => e.key === "Enter" && createTarget()} />
          <TBtn icon="add" label={saving ? "Adding…" : "Add"} accent disabled={saving} onClick={createTarget} />
          {err && <span style={{ fontSize: 11, color: C.critical }}>{err}</span>}
        </div>
      )}

      <SplitPane
        defaultSplit={60}
        left={
          <div style={{ display: "flex", flexDirection: "column", height: "100%" }}>
            <PanelLabel>Registered Targets ({shown.length})</PanelLabel>
            <div style={{ flex: 1, overflowY: "auto" }}>
              {shown.length === 0 ? (
                <EmptyHint>No targets match. Add an authorized test target above.</EmptyHint>
              ) : (
                <table style={{ width: "100%", borderCollapse: "collapse" }}>
                  <thead>
                    <tr>
                      <Th w={24}>#</Th>
                      <Th>Name</Th>
                      <Th>URL</Th>
                      <Th w={60}>Protocol</Th>
                      <Th w={90}>Status</Th>
                    </tr>
                  </thead>
                  <tbody>
                    {shown.map((t, i) => (
                      <tr key={t.id} className={`trow${activeId === t.id ? " selected" : ""}`} onClick={() => setActiveId(t.id)}>
                        <Td style={{ color: C.fgDim, textAlign: "center" }}>{i + 1}</Td>
                        <Td style={{ color: C.fg, fontWeight: 500 }}>{t.name}</Td>
                        <Td mono style={{ color: C.accent }}>{t.url}</Td>
                        <Td mono>{protoOf(t.url)}</Td>
                        <Td style={{ color: t.status === "In Progress" ? C.accent : t.status === "Complete" ? C.low : C.fgMid }}>
                          {t.status}
                        </Td>
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
            <PanelLabel actions={selected && <TBtn icon="trash" title="Remove target" onClick={() => removeTarget(selected.id, selected.name)} />}>
              Target Detail
            </PanelLabel>
            {!selected ? (
              <EmptyHint>Select a target to view details.</EmptyHint>
            ) : (
              <div style={{ flex: 1, overflowY: "auto", padding: 14 }}>
                <FieldRow label="Name" value={selected.name} />
                <FieldRow label="URL" value={selected.url} mono />
                <FieldRow label="Protocol" value={protoOf(selected.url)} mono />
                <FieldRow label="Status" value={selected.status} />
                <FieldRow label="Date Added" value={new Date(selected.date_added).toLocaleString()} />

              </div>
            )}
          </div>
        }
      />
    </div>
  );
}
