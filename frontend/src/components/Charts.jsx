import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, ResponsiveContainer, Tooltip } from "recharts";

const GRADIENTS = {
  high: ["#f08a8a", "#e05555"],
  medium: ["#e0bb5a", "#c9981a"],
  low: ["#5fd9b3", "#00c49a"],
  blue: ["#8fbfe0", "#4a8cc4"],
};

function GradientDefs() {
  return (
    <defs>
      {Object.entries(GRADIENTS).map(([key, [from, to]]) => (
        <linearGradient key={key} id={`grad-${key}`} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={from} stopOpacity={1} />
          <stop offset="100%" stopColor={to} stopOpacity={0.9} />
        </linearGradient>
      ))}
    </defs>
  );
}

export function SeverityDonut({ counts }) {
  const data = [
    { name: "High", value: counts.High, key: "high" },
    { name: "Medium", value: counts.Medium, key: "medium" },
    { name: "Low", value: counts.Low, key: "low" },
  ].filter((d) => d.value > 0);

  const total = counts.High + counts.Medium + counts.Low;

  if (total === 0) {
    return (
      <div className="h-48 flex items-center justify-center text-sm text-ink-faint font-mono">
        no findings yet — chart appears once findings are recorded
      </div>
    );
  }

  return (
    <div className="relative h-48">
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <GradientDefs />
          <Pie
            data={data}
            dataKey="value"
            nameKey="name"
            innerRadius="62%"
            outerRadius="92%"
            paddingAngle={3}
            stroke="none"
          >
            {data.map((d) => (
              <Cell key={d.key} fill={`url(#grad-${d.key})`} />
            ))}
          </Pie>
          <Tooltip
            contentStyle={{
              background: "#101010",
              border: "1px solid rgba(255,255,255,0.08)",
              borderRadius: 6,
              fontFamily: "var(--font-mono)",
              fontSize: 12,
            }}
            itemStyle={{ color: "#d4dce8" }}
          />
        </PieChart>
      </ResponsiveContainer>
      <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
        <span className="text-2xl font-mono font-semibold text-ink">{total}</span>
        <span className="text-[10px] uppercase tracking-wider text-ink-faint font-mono">findings</span>
      </div>
    </div>
  );
}

export function ScanProgressBars({ scanCounts }) {
  const data = [
    { name: "HTTP", value: scanCounts.http || 0, key: "blue" },
    { name: "Endpoints", value: scanCounts.endpoints || 0, key: "medium" },
    { name: "JS", value: scanCounts.js || 0, key: "low" },
    { name: "SQLi", value: scanCounts.sqli || 0, key: "high" },
  ];

  return (
    <div className="h-40">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} margin={{ top: 4, right: 4, left: -20, bottom: 0 }}>
          <GradientDefs />
          <XAxis
            dataKey="name"
            tick={{ fill: "#7a8a9c", fontSize: 11, fontFamily: "var(--font-mono)" }}
            axisLine={{ stroke: "rgba(255,255,255,0.08)" }}
            tickLine={false}
          />
          <YAxis
            allowDecimals={false}
            tick={{ fill: "#3a4858", fontSize: 10, fontFamily: "var(--font-mono)" }}
            axisLine={false}
            tickLine={false}
            width={24}
          />
          <Tooltip
            cursor={{ fill: "rgba(0,196,154,0.06)" }}
            contentStyle={{
              background: "#101010",
              border: "1px solid rgba(255,255,255,0.08)",
              borderRadius: 6,
              fontFamily: "var(--font-mono)",
              fontSize: 12,
            }}
            itemStyle={{ color: "#d4dce8" }}
          />
          <Bar dataKey="value" radius={[6, 6, 0, 0]} maxBarSize={44}>
            {data.map((d) => (
              <Cell key={d.name} fill={`url(#grad-${d.key})`} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
