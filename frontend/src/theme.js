// Design tokens + icon paths, ported directly from the Figma Make export
// (Web_App_Security_Tester Figma zip, src/App.tsx) so the running app matches
// the reference pixel-for-pixel rather than approximating it with Tailwind.

export const C = {
  bg: "#0B1014",
  panel: "#11181E",
  panelB: "#162027",
  panelC: "#1B2730",
  border: "rgba(184,205,217,0.14)",
  borderMd: "rgba(184,205,217,0.22)",
  accent: "#5BD6BD",
  accentDim: "rgba(91,214,189,0.14)",
  fg: "#D9E4E8",
  fgMid: "#91A4AE",
  fgDim: "#526773",
  critical: "#E05555",
  high: "#E07832",
  medium: "#C9981A",
  low: "#4CAF82",
  info: "#4A8CC4",
  critBg: "rgba(224,85,85,0.12)",
  highBg: "rgba(224,120,50,0.12)",
  medBg: "rgba(201,152,26,0.12)",
  lowBg: "rgba(76,175,130,0.12)",
  infoBg: "rgba(74,140,196,0.12)",
};

// Our backend's Finding.severity enum is Low/Medium/High (see docs Section 9.6),
// mapped onto the richer 5-level palette above.
export const SEV = {
  CRITICAL: { fg: C.critical, bg: C.critBg, label: "CRITICAL" },
  HIGH: { fg: C.high, bg: C.highBg, label: "HIGH" },
  MEDIUM: { fg: C.medium, bg: C.medBg, label: "MEDIUM" },
  LOW: { fg: C.low, bg: C.lowBg, label: "LOW" },
  INFO: { fg: C.info, bg: C.infoBg, label: "INFO" },
};

export function sevKeyFromSeverity(severity) {
  return (severity || "LOW").toUpperCase();
}

export const ICO = {
  play: "M3 3l10 5-10 5V3z",
  stop: "M3 3h10v10H3z",
  clear: "M2 8h12M8 2l6 6-6 6",
  copy: "M5 5V2h9v9h-3M2 5h9v9H2z",
  add: "M8 2v12M2 8h12",
  trash: "M3 5h10M6 5V3h4v2M5 5v8h6V5",
  search: "M7 13A6 6 0 107 1a6 6 0 000 12zM13 13l2 2",
  chevR: "M6 4l4 4-4 4",
  chevD: "M4 6l4 4 4-4",
  dot: "M8 8m-3 0a3 3 0 106 0 3 3 0 10-6 0",
  send: "M14 2L2 8l4 2 2 4 6-12zM6 10l3-3",
  target: "M8 1.5L2.5 4v4c0 3.2 2.4 5.7 5.5 6.8 3.1-1.1 5.5-3.6 5.5-6.8V4z",
  export: "M9 2H4a1 1 0 00-1 1v10a1 1 0 001 1h8a1 1 0 001-1V7M9 2l4 5M9 2v5h4",
  filter: "M2 4h12M5 8h6M7 12h2",
  refresh: "M1 8a7 7 0 0112.3-4.6M15 8a7 7 0 01-12.3 4.6M14 1v4h-4M2 11v4H6",
};
