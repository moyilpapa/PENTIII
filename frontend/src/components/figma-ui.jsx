import { useState, useRef, useCallback } from "react";
import { C, SEV, ICO } from "../theme";

export function Ico({ d, s = 12, c = "currentColor" }) {
  return (
    <svg
      width={s}
      height={s}
      viewBox="0 0 16 16"
      fill="none"
      stroke={c}
      strokeWidth={1.5}
      strokeLinecap="round"
      strokeLinejoin="round"
      style={{ display: "block", flexShrink: 0 }}
    >
      <path d={d} />
    </svg>
  );
}

export function Toolbar({ children }) {
  return (
    <div
      style={{
        display: "flex", alignItems: "center", gap: 4, padding: "5px 8px",
        borderBottom: `1px solid ${C.border}`, background: C.panel, flexShrink: 0,
        flexWrap: "wrap", rowGap: 4,
      }}
    >
      {children}
    </div>
  );
}

export function TBtn({ icon, label, accent, disabled, onClick, title }) {
  return (
    <button
      onClick={onClick}
      title={title}
      disabled={disabled}
      className={accent ? "btn-accent" : "btn-ghost"}
      style={{
        display: "flex", alignItems: "center", gap: 5, padding: "4px 9px", borderRadius: 4,
        border: `1px solid ${accent ? "rgba(0,196,154,0.35)" : C.border}`,
        cursor: disabled ? "not-allowed" : "pointer",
        background: accent ? C.accentDim : "transparent",
        color: accent ? C.accent : C.fgMid, fontSize: 11.5, fontFamily: "inherit",
        whiteSpace: "nowrap", transition: "all 0.1s", opacity: disabled ? 0.45 : 1,
      }}
    >
      {icon && (
        <svg width={11} height={11} viewBox="0 0 16 16" fill="none" stroke="currentColor"
          strokeWidth={1.6} strokeLinecap="round" strokeLinejoin="round">
          <path d={ICO[icon]} />
        </svg>
      )}
      {label}
    </button>
  );
}

export function TSep() {
  return <div style={{ width: 1, height: 18, background: C.border, margin: "0 3px" }} />;
}

export function TInput({ value, onChange, placeholder, style, disabled, onKeyDown }) {
  return (
    <input
      value={value}
      onChange={(e) => onChange?.(e.target.value)}
      placeholder={placeholder}
      disabled={disabled}
      onKeyDown={onKeyDown}
      style={{
        flex: 1, background: "rgba(255,255,255,0.04)", border: `1px solid ${C.border}`,
        borderRadius: 4, padding: "4px 9px", fontSize: 11.5, color: C.fg,
        fontFamily: "var(--font-mono)", outline: "none",
        opacity: disabled ? 0.5 : 1, ...style,
      }}
    />
  );
}

export function SubTabs({ tabs, active, set }) {
  return (
    <div style={{ display: "flex", borderBottom: `1px solid ${C.border}`, background: C.panel, flexShrink: 0 }}>
      {tabs.map((t) => (
        <button
          key={t.id}
          onClick={() => set(t.id)}
          style={{
            padding: "5px 14px", border: "none", cursor: "pointer", fontSize: 11.5, fontFamily: "inherit",
            background: "transparent", borderBottom: active === t.id ? `2px solid ${C.accent}` : "2px solid transparent",
            color: active === t.id ? C.fg : C.fgMid, fontWeight: active === t.id ? 600 : 400,
            marginBottom: -1, transition: "color 0.1s",
          }}
        >
          {t.label}
        </button>
      ))}
    </div>
  );
}

export function Th({ children, w }) {
  return (
    <th
      style={{
        padding: "5px 10px", fontSize: 10.5, fontWeight: 600, letterSpacing: "0.08em",
        textTransform: "uppercase", color: C.fgDim, textAlign: "left", borderBottom: `1px solid ${C.border}`,
        borderRight: `1px solid ${C.border}`, whiteSpace: "nowrap", width: w, background: C.panelB,
      }}
    >
      {children}
    </th>
  );
}

export function Td({ children, mono, style }) {
  return (
    <td
      style={{
        padding: "5px 10px", fontSize: 11.5, color: C.fgMid, borderBottom: `1px solid ${C.border}`,
        borderRight: `1px solid ${C.border}`, fontFamily: mono ? "var(--font-mono)" : "inherit",
        ...style,
      }}
    >
      {children}
    </td>
  );
}

export function SplitPane({ left, right, defaultSplit = 50, direction = "horizontal" }) {
  const [split, setSplit] = useState(defaultSplit);
  const dragging = useRef(false);
  const containerRef = useRef(null);

  const onMouseDown = useCallback((e) => {
    e.preventDefault();
    dragging.current = true;
    const move = (ev) => {
      if (!dragging.current || !containerRef.current) return;
      const rect = containerRef.current.getBoundingClientRect();
      const pos = direction === "horizontal"
        ? ((ev.clientX - rect.left) / rect.width) * 100
        : ((ev.clientY - rect.top) / rect.height) * 100;
      setSplit(Math.max(20, Math.min(80, pos)));
    };
    const up = () => {
      dragging.current = false;
      window.removeEventListener("mousemove", move);
      window.removeEventListener("mouseup", up);
    };
    window.addEventListener("mousemove", move);
    window.addEventListener("mouseup", up);
  }, [direction]);

  const isH = direction === "horizontal";
  return (
    <div ref={containerRef} style={{ display: "flex", flexDirection: isH ? "row" : "column", flex: 1, overflow: "hidden", minHeight: 0 }}>
      <div style={{ [isH ? "width" : "height"]: `${split}%`, overflow: "hidden", display: "flex", flexDirection: "column", minWidth: 0, minHeight: 0 }}>
        {left}
      </div>
      <div
        onMouseDown={onMouseDown}
        style={{
          [isH ? "width" : "height"]: 4, cursor: isH ? "col-resize" : "row-resize",
          background: "transparent", flexShrink: 0,
        }}
      />
      <div style={{ flex: 1, overflow: "hidden", display: "flex", flexDirection: "column", minWidth: 0, minHeight: 0 }}>
        {right}
      </div>
    </div>
  );
}

export function PanelLabel({ children, actions }) {
  return (
    <div
      style={{
        display: "flex", alignItems: "center", justifyContent: "space-between",
        padding: "4px 10px", background: C.panelB, borderBottom: `1px solid ${C.border}`, flexShrink: 0,
      }}
    >
      <span style={{ fontSize: 10.5, fontWeight: 600, letterSpacing: "0.08em", textTransform: "uppercase", color: C.fgDim }}>
        {children}
      </span>
      {actions && <div style={{ display: "flex", gap: 4 }}>{actions}</div>}
    </div>
  );
}

export function SevBadge({ s }) {
  const v = SEV[s] ?? SEV.INFO;
  return (
    <span
      style={{
        display: "inline-block", padding: "1px 6px", borderRadius: 3, fontSize: 10,
        fontWeight: 700, letterSpacing: "0.06em", color: v.fg, background: v.bg, fontFamily: "inherit",
      }}
    >
      {v.label}
    </span>
  );
}

export function FieldRow({ label, value, mono }) {
  return (
    <div style={{ marginBottom: 10 }}>
      <div style={{ fontSize: 10, fontWeight: 600, letterSpacing: "0.08em", textTransform: "uppercase", color: C.fgDim, marginBottom: 3 }}>
        {label}
      </div>
      <div style={{ fontSize: 11.5, color: C.fgMid, fontFamily: mono ? "var(--font-mono)" : "inherit", wordBreak: "break-all" }}>
        {value}
      </div>
    </div>
  );
}

export function EmptyHint({ children }) {
  return (
    <div style={{ padding: 24, fontSize: 11.5, color: C.fgDim, textAlign: "center" }}>
      {children}
    </div>
  );
}
