import { useState } from "react";
import { C } from "../theme";
import { Toolbar, TBtn, TSep, TInput, SplitPane, EmptyHint } from "../components/figma-ui";

// Mirrors backend/scanner.py's SECURITY_HEADERS -- used only to render a
// complete Present/Missing checklist (the backend already tells us which of
// these are *missing* via result.flags; we just also want to show the ones
// that ARE present, which the raw flags list alone doesn't surface).
const SECURITY_HEADER_CHECKLIST = [
  { name: "Content-Security-Policy", why: "Mitigates XSS and data-injection by restricting allowed content sources." },
  { name: "X-Frame-Options", why: "Prevents clickjacking by controlling whether the page can be framed." },
  { name: "X-Content-Type-Options", why: "Prevents MIME-sniffing attacks (should be 'nosniff')." },
  { name: "Strict-Transport-Security", why: "Forces HTTPS, preventing SSL-stripping downgrade attacks." },
  { name: "Referrer-Policy", why: "Controls how much referrer information is leaked to other sites." },
  { name: "Permissions-Policy", why: "Restricts which browser features/APIs the page may use." },
];

// Headers that tend to reveal server/framework technology, shown as a quick
// "what is this built with" summary rather than buried in the raw list.
const TECH_HEADER_NAMES = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator", "Via", "X-Runtime"];

function renderRaw(text) {
  return text.split(/\r?\n/).map((line, i) => (
    <div key={i} style={{ lineHeight: 1.7, color: C.fgMid }}>{line || "\u00A0"}</div>
  ));
}

function getHeader(headers, name) {
  const key = Object.keys(headers).find((k) => k.toLowerCase() === name.toLowerCase());
  return key ? headers[key] : null;
}

function SectionLabel({ children }) {
  return (
    <div style={{ fontSize: 10.5, fontWeight: 700, letterSpacing: "0.08em", textTransform: "uppercase", color: C.fgDim, marginBottom: 8, marginTop: 18 }}>
      {children}
    </div>
  );
}

function ResponseTabs({ active, onChange }) {
  const tabs = [
    { id: "overview", label: "Overview" },
    { id: "headers", label: "Raw Headers" },
    { id: "body", label: "Raw Body" },
  ];
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 4 }}>
      {tabs.map((t) => (
        <button
          key={t.id}
          onClick={() => onChange(t.id)}
          style={{
            padding: "4px 11px", borderRadius: 4, fontSize: 10.5, fontFamily: "inherit", cursor: "pointer",
            border: `1px solid ${active === t.id ? C.borderMd : C.border}`,
            background: active === t.id ? "rgba(255,255,255,0.08)" : "transparent",
            color: active === t.id ? C.fg : C.fgMid,
          }}
        >
          {t.label}
        </button>
      ))}
    </div>
  );
}

function OverviewTab({ result }) {
  const techHeaders = TECH_HEADER_NAMES
    .map((name) => ({ name, value: getHeader(result.headers, name) }))
    .filter((h) => h.value);

  const missingHeaderNames = new Set(
    result.flags.filter((f) => !f.header.startsWith("Cookie:")).map((f) => f.header)
  );
  const cookieIssues = new Map(
    result.flags.filter((f) => f.header.startsWith("Cookie:")).map((f) => [f.header.replace("Cookie:", ""), f])
  );

  return (
    <div>
      <SectionLabel>Server &amp; Technology</SectionLabel>
        {techHeaders.length === 0 ? (
          <p style={{ fontSize: 11.5, color: C.fgDim }}>No server identifying headers.</p>
        ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
          {techHeaders.map((h) => (
            <div key={h.name} style={{ display: "flex", gap: 8, fontSize: 11.5 }}>
              <span style={{ color: C.fgDim, minWidth: 130 }}>{h.name}</span>
              <span style={{ color: C.fg, fontFamily: "var(--font-mono)" }}>{h.value}</span>
            </div>
          ))}
        </div>
      )}

      <SectionLabel>Security Headers ({SECURITY_HEADER_CHECKLIST.length - missingHeaderNames.size}/{SECURITY_HEADER_CHECKLIST.length} present)</SectionLabel>
      <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
        {SECURITY_HEADER_CHECKLIST.map((h) => {
          const present = !missingHeaderNames.has(h.name);
          return (
            <div key={h.name} style={{ display: "flex", alignItems: "flex-start", gap: 8, padding: "6px 10px", borderRadius: 4, background: C.panelB, border: `1px solid ${C.border}` }}>
              <span style={{ fontSize: 12, color: present ? C.low : C.medium, fontWeight: 700, minWidth: 14 }}>{present ? "✓" : "✗"}</span>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontSize: 11.5, color: C.fg, fontFamily: "var(--font-mono)" }}>{h.name}</div>
                {!present && <div style={{ fontSize: 11, color: C.fgDim, marginTop: 2 }}>{h.why}</div>}
              </div>
              <span style={{ fontSize: 10, fontWeight: 700, letterSpacing: "0.04em", color: present ? C.low : C.medium }}>
                {present ? "PRESENT" : "MISSING"}
              </span>
            </div>
          );
        })}
      </div>

      <SectionLabel>Cookies ({result.cookies.length})</SectionLabel>
        {result.cookies.length === 0 ? (
          <p style={{ fontSize: 11.5, color: C.fgDim }}>No cookies set.</p>
        ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
          {result.cookies.map((c) => {
            const issue = cookieIssues.get(c.name);
            return (
              <div key={c.name} style={{ padding: "6px 10px", borderRadius: 4, background: C.panelB, border: `1px solid ${C.border}` }}>
                <div style={{ fontSize: 11.5, color: C.fg, fontFamily: "var(--font-mono)", marginBottom: 3 }}>{c.name}</div>
                <div style={{ display: "flex", gap: 14, fontSize: 10.5 }}>
                  <span style={{ color: c.secure ? C.low : C.medium }}>{c.secure ? "✓ Secure" : "✗ Secure"}</span>
                  <span style={{ color: c.httponly ? C.low : C.medium }}>{c.httponly ? "✓ HttpOnly" : "✗ HttpOnly"}</span>
                </div>
                {issue && <div style={{ fontSize: 11, color: C.fgDim, marginTop: 3 }}>{issue.why}</div>}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

export default function HttpPage({ ctx }) {
  const { activeTarget, api, log, bumpScans, scanData, setScanData } = ctx;
  const [resTab, setResTab] = useState("overview");
  const [loading, setLoading] = useState(false);
  const result = scanData.http || null;

  if (!activeTarget) {
    return <div style={{ flex: 1, display: "flex" }}><EmptyHint>Select or add a target in the Targets tab first.</EmptyHint></div>;
  }

  async function run() {
    setLoading(true);
    log("run", `HTTP analysis → ${activeTarget.url}`);
    try {
      const r = await api.scanHttp(activeTarget.id);
      setScanData("http", r);
      bumpScans();
      if (!r.ok) log("fail", `request failed: ${r.error}`);
      else log("ok", `${r.status_code} · ${r.flags.length} header/cookie flag(s)`);
    } catch (e) {
      log("fail", e.message);
    } finally {
      setLoading(false);
    }
  }

  const reqRaw = `GET ${activeTarget.url} HTTP/1.1\r\nHost: ${new URL(/^https?:\/\//.test(activeTarget.url) ? activeTarget.url : "http://" + activeTarget.url).host}\r\nUser-Agent: WebAppSecurityTester/1.0\r\nAccept: */*\r\nConnection: close`;

  const resRaw = result?.ok
    ? `HTTP/1.1 ${result.status_code}\r\n${Object.entries(result.headers).map(([k, v]) => `${k}: ${v}`).join("\r\n")}\r\n\r\n${result.body_snippet || ""}`
    : "";

  return (
    <div style={{ display: "flex", flexDirection: "column", flex: 1, minHeight: 0 }}>
      <Toolbar>
        <TInput value={activeTarget.url} disabled style={{ flex: 1 }} />
        <TSep />
        <TBtn icon="send" label={loading ? "Sending…" : "Send"} accent disabled={loading} onClick={run} />
        <TBtn icon="clear" label="Clear" onClick={() => setScanData("http", null)} />
      </Toolbar>

      {result?.ok && (
        <div style={{ display: "flex", alignItems: "center", gap: 16, padding: "3px 10px", background: C.panelB, borderBottom: `1px solid ${C.border}`, flexShrink: 0 }}>
          <span style={{ fontSize: 11, fontFamily: "var(--font-mono)", color: result.status_code < 400 ? C.low : C.medium }}>
            {result.status_code}
          </span>
          <span style={{ fontSize: 11, color: C.fgDim }}>{result.elapsed_ms}ms</span>
          <span style={{ fontSize: 11, color: C.fgDim }}>{result.content_length} bytes</span>
          {getHeader(result.headers, "Server") && (
            <span style={{ fontSize: 11, color: C.fgDim, fontFamily: "var(--font-mono)" }}>{getHeader(result.headers, "Server")}</span>
          )}
          {result.flags.length > 0 && <span style={{ fontSize: 11, color: C.medium }}>{result.flags.length} flag(s)</span>}
        </div>
      )}
      {result && !result.ok && (
        <div style={{ padding: "6px 10px", fontSize: 11.5, color: C.critical, fontFamily: "var(--font-mono)" }}>{result.error}</div>
      )}

      <SplitPane
        left={
          <div style={{ display: "flex", flexDirection: "column", height: "100%" }}>
            <div style={{ display: "flex", alignItems: "center", background: C.panelB, borderBottom: `1px solid ${C.border}`, flexShrink: 0 }}>
              <span style={{ padding: "4px 10px", fontSize: 10.5, fontWeight: 600, letterSpacing: "0.08em", textTransform: "uppercase", color: C.fgDim }}>
                Request (Raw)
              </span>
              <div style={{ flex: 1 }} />
              <TBtn icon="copy" title="Copy request" onClick={() => navigator.clipboard?.writeText(reqRaw)} />
            </div>
            <div style={{ flex: 1, overflowY: "auto", padding: "10px 14px", background: C.bg, fontFamily: "var(--font-mono)", fontSize: 11.5 }}>
              {renderRaw(reqRaw)}
            </div>
          </div>
        }
        right={
          <div style={{ display: "flex", flexDirection: "column", height: "100%" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8, background: C.panelB, borderBottom: `1px solid ${C.border}`, flexShrink: 0, padding: "6px 8px" }}>
              <span style={{ fontSize: 10.5, fontWeight: 600, letterSpacing: "0.08em", textTransform: "uppercase", color: C.fgDim, marginRight: 4 }}>
                Response
              </span>
              {result?.ok && <ResponseTabs active={resTab} onChange={setResTab} />}
              <div style={{ flex: 1 }} />
              <TBtn icon="copy" title="Copy raw response" onClick={() => navigator.clipboard?.writeText(resRaw)} />
            </div>
            <div style={{ flex: 1, overflowY: "auto", padding: "12px 16px", background: C.bg }}>
              {!result && <span style={{ fontSize: 11.5, color: C.fgDim }}>Send a request to see the response.</span>}
              {result && !result.ok && <span style={{ fontSize: 11.5, color: C.critical, fontFamily: "var(--font-mono)" }}>{result.error}</span>}
              {result?.ok && resTab === "overview" && <OverviewTab result={result} />}
              {result?.ok && resTab === "headers" && (
                <div style={{ fontFamily: "var(--font-mono)", fontSize: 11.5 }}>
                  {renderRaw(Object.entries(result.headers).map(([k, v]) => `${k}: ${v}`).join("\n"))}
                </div>
              )}
              {result?.ok && resTab === "body" && (
                <div style={{ fontFamily: "var(--font-mono)", fontSize: 11.5 }}>
                  {renderRaw(result.body_snippet || "(empty body)")}
                </div>
              )}
            </div>
          </div>
        }
      />
    </div>
  );
}
