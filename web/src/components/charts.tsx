import { Area, AreaChart, CartesianGrid, Line, LineChart, ReferenceLine, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { clock, fmtRate } from "../lib";

// Compact axis labels: "950M", "3.8G".
function tick(v: number): string {
  const a = Math.abs(v);
  if (a >= 1e12) return +(v / 1e12).toFixed(1) + "T";
  if (a >= 1e9) return +(v / 1e9).toFixed(1) + "G";
  if (a >= 1e6) return +(v / 1e6).toFixed(1) + "M";
  if (a >= 1e3) return +(v / 1e3).toFixed(1) + "k";
  return String(Math.round(v));
}

const axis = { stroke: "var(--axis)", tick: { fill: "var(--muted)", fontSize: 11 }, tickLine: false };
const tooltipStyle = {
  contentStyle: { background: "var(--surface)", border: "1px solid var(--border)", borderRadius: 8, fontSize: 12, color: "var(--ink)" },
  labelStyle: { color: "var(--muted)" },
};

export interface SeriesDef {
  key: string;
  name: string;
  color: string;
}

/** Legend for >= 2 series (identity is never color alone: names are shown). */
export function Legend({ series }: { series: SeriesDef[] }) {
  if (series.length < 2) return null;
  return (
    <div className="chart-legend">
      {series.map((s) => (
        <span key={s.key}>
          <i style={{ background: s.color }} />
          {s.name}
        </span>
      ))}
    </div>
  );
}

/** TimeArea draws one or more series over time (t = unix seconds). */
export function TimeArea(props: { data: Record<string, number>[]; series: SeriesDef[]; unit: string; height?: number; stacked?: boolean }) {
  return (
    <div style={{ width: "100%", height: props.height ?? 240, minWidth: 0 }}>
      <ResponsiveContainer>
        <AreaChart data={props.data} margin={{ top: 8, right: 8, left: 0, bottom: 0 }}>
          <CartesianGrid stroke="var(--grid)" vertical={false} />
          <XAxis dataKey="t" tickFormatter={clock} {...axis} minTickGap={48} />
          <YAxis tickFormatter={tick} {...axis} width={44} axisLine={false} />
          <Tooltip {...tooltipStyle} labelFormatter={(t) => clock(t as number)} formatter={(v: number, n: string) => [fmtRate(v, props.unit), n]} />
          {props.series.map((s) => (
            <Area
              key={s.key}
              type="monotone"
              dataKey={s.key}
              name={s.name}
              stroke={s.color}
              strokeWidth={2}
              fill={s.color}
              fillOpacity={props.stacked ? 0.35 : 0.12}
              stackId={props.stacked ? "1" : undefined}
              isAnimationActive={false}
              dot={false}
            />
          ))}
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}

/** ThresholdLine draws one series with optional threshold / baseline references. */
export function ThresholdLine(props: { data: Record<string, number>[]; dataKey: string; unit: string; threshold?: number; baseline?: number; height?: number }) {
  return (
    <div style={{ width: "100%", height: props.height ?? 200, minWidth: 0 }}>
      <ResponsiveContainer>
        <LineChart data={props.data} margin={{ top: 8, right: 8, left: 0, bottom: 0 }}>
          <CartesianGrid stroke="var(--grid)" vertical={false} />
          <XAxis dataKey="t" tickFormatter={clock} {...axis} minTickGap={48} />
          <YAxis tickFormatter={tick} {...axis} width={44} axisLine={false} />
          <Tooltip {...tooltipStyle} labelFormatter={(t) => clock(t as number)} formatter={(v: number) => fmtRate(v, props.unit)} />
          {props.threshold ? <ReferenceLine y={props.threshold} stroke="var(--critical)" strokeDasharray="4 4" label={{ value: "eşik", fill: "var(--muted)", fontSize: 11, position: "insideTopRight" }} /> : null}
          {props.baseline ? <ReferenceLine y={props.baseline} stroke="var(--axis)" strokeDasharray="2 4" label={{ value: "normal", fill: "var(--muted)", fontSize: 11, position: "insideBottomRight" }} /> : null}
          <Line type="monotone" dataKey={props.dataKey} stroke="var(--series-1)" strokeWidth={2} dot={false} isAnimationActive={false} />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}
