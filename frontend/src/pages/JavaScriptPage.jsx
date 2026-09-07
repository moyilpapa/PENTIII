import { useState } from "react";
import { C } from "../theme";
import { Toolbar, TBtn, TSep, SplitPane, PanelLabel, Th, Td, EmptyHint } from "../components/figma-ui";

export default function JavaScriptPage({ ctx }) {
  const { activeTarget, api, log, bumpScans, scanData, setScanData } = ctx;
  const [running, setRunning] = useState(false);
  const [selFile, setSelFile] = useState(0);
  const result = scanData.js || null;

  if (!activeTarget) {
    return <div style={{ flex: 1, display: "flex" }}><EmptyHint>Select or add a target in the Targets tab first.</EmptyHint></div>;
  }

  async function run() {
    setRunning(true);
    log("run", `JS discovery + regex scan → ${activeTarget.url}`);
    try {
      const r = await api.scanJs(activeTarget.id);
      setScanData("js", r);
      bumpScans();
      setSelFile(0);
      if (r.ok) {
        log("ok", `${r.scripts_found} script(s), ${r.unique_endpoints.length} endpoint-like strings`);
        if (r.possible_secrets_flagged > 0) log("warn", `${r.possible_secrets_flagged} possible secret-like string(s) flagged`);
      } else {
        log("fail", r.error);
      }
    } catch (e) {
      log("fail", e.message);
    } finally {
      setRunning(false);
    }
  }

  const files = result?.ok ? result.files : [];
  const f = files[selFile];

  return (
    <div style={{ display: "flex", flexDirection: "column", flex: 1, minHeight: 0 }}>
      <Toolbar>
        <span style={{ fontSize: 11, color: C.fgDim, fontFamily: "var(--font-mono)" }}>{activeTarget.url}</span>
        <TSep />
        <TBtn icon="play" label={running ? "Analyzing…" : "Analyze"} accent disabled={running} onClick={run} />
      </Toolbar>

      <SplitPane
        defaultSplit={38}
        direction="vertical"
        left={
          <div style={{ display: "flex", flexDirection: "column", height: "100%" }}>
            <PanelLabel>JavaScript Files {result?.ok && `(${result.scripts_found})`}</PanelLabel>
            <div style={{ flex: 1, overflowY: "auto" }}>
              {files.length === 0 ? (
                <EmptyHint>{result?.ok === false ? result.error : "Run analysis to discover linked JavaScript files."}</EmptyHint>
              ) : (
                <table style={{ width: "100%", borderCollapse: "collapse" }}>
                  <thead>
                    <tr>
                      <Th>File</Th>
                      <Th w={80}>Size</Th>
                      <Th w={110}>Matches</Th>
                      <Th>Resolved URL</Th>
                    </tr>
                  </thead>
                  <tbody>
                    {files.map((file, i) => (
                      <tr key={i} className={`trow${selFile === i ? " selected" : ""}`} onClick={() => setSelFile(i)}>
                        <Td mono style={{ color: C.fg }}>{file.src}</Td>
                        <Td mono style={{ color: C.fgDim }}>{file.ok ? `${file.size}B` : "—"}</Td>
                        <Td style={{ color: (file.endpoints_found?.length || 0) > 0 ? C.medium : C.fgDim, textAlign: "center" }}>
                          {file.ok ? file.endpoints_found?.length || 0 : "err"}
                        </Td>
                        <Td mono style={{ fontSize: 11, color: C.fgMid }}>{file.resolved_url}</Td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </div>
        }
        right={
          <div style={{ display: "flex", flexDirection: "column", height: "100%", borderTop: `1px solid ${C.border}` }}>
            <PanelLabel>Extracted Patterns {f && `— ${f.src}`}</PanelLabel>
            <div style={{ flex: 1, overflowY: "auto" }}>
              {!f?.ok ? (
                <EmptyHint>{f?.error || "Select a file to view extracted endpoint-like strings."}</EmptyHint>
              ) : (f.endpoints_found?.length || 0) === 0 ? (
                <EmptyHint>No endpoint-like strings matched in this file.</EmptyHint>
              ) : (
                <table style={{ width: "100%", borderCollapse: "collapse" }}>
                  <thead>
                    <tr>
                      <Th>Match</Th>
                      <Th w={90}>Type</Th>
                    </tr>
                  </thead>
                  <tbody>
                    {f.endpoints_found.map((e, i) => (
                      <tr key={i} className="trow">
                        <Td mono style={{ color: C.fg }}>{e}</Td>
                        <Td style={{ color: C.fgMid }}>{e.startsWith("http") ? "External" : "Endpoint"}</Td>
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
