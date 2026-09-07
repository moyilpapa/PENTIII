import { useEffect, useState } from "react";

export default function Splash({ duration = 2000, onDone }) {
  const [fading, setFading] = useState(false);

  // Runs exactly once on mount and is never re-armed by parent re-renders
  // (the previous version depended on `onDone`/`duration` in its effect
  // array; since the parent recreated `onDone` on every render -- including
  // its own once-a-second clock tick -- the timers kept getting cleared and
  // restarted before they could ever fire, so the splash never advanced).
  useEffect(() => {
    const fadeStart = setTimeout(() => setFading(true), Math.max(0, duration - 250));
    const done = setTimeout(() => onDone(), duration);
    return () => {
      clearTimeout(fadeStart);
      clearTimeout(done);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div
      style={{
        position: "fixed", inset: 0, zIndex: 9999, background: "#000000",
        display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center",
        opacity: fading ? 0 : 1, transition: "opacity 0.25s ease",
      }}
    >
      <img src="/logo.png" alt="PENTIII" style={{ width: 260, height: 260, objectFit: "contain" }} />
      <div style={{ marginTop: 22, fontSize: 13, letterSpacing: "0.08em", color: "#7A8A9C", fontFamily: "var(--font-mono)" }}>
        Loading...
      </div>
    </div>
  );
}
