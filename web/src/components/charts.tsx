import {
  Area,
  AreaChart,
  CartesianGrid,
  Legend,
  Line,
  LineChart,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { clock, fmtRate } from "../lib";

const axis = { stroke: "var(--muted)", fontSize: 11 };

// Compact axis labels: "950M", "3.8G".
function tick(_unit: string) {
  return (v: number) => {
    const a = Math.abs(v);
    if (a >= 1e12) return +(v / 1e12).toFixed(1) + "T";
    if (a >= 1e9) return +(v / 1e9).toFixed(1) + "G";
    if (a >= 1e6) return +(v / 1e6).toFixed(1) + "M";
    if (a >= 1e3) return +(v / 1e3).toFixed(1) + "k";
    return String(Math.round(v));
  };
}

export interface SeriesDef {
  key: string;
  name: string;
  color: string;
}

/** StackedArea draws a time series (t in unix seconds). */
export function StackedArea(props: { data: Record<string, number>[]; series: SeriesDef[]; unit: string; height?: number; stacked?: boolean }) {
  return (
    <div style={{ width: "100%", height: props.height ?? 240 }}>
      <ResponsiveContainer>
        <AreaChart data={props.data} margin={{ top: 8, right: 12, left: 0, bottom: 0 }}>
          <defs>
            {props.series.map((s) => (
              <linearGradient key={s.key} id={"g-" + s.key} x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor={s.color} stopOpacity={0.45} />
                <stop offset="100%" stopColor={s.color} stopOpacity={0.03} />
              </linearGradient>
            ))}
          </defs>
          <CartesianGrid stroke="var(--grid)" vertical={false} />
          <XAxis dataKey="t" tickFormatter={clock} {...axis} minTickGap={40} />
          <YAxis tickFormatter={tick(props.unit)} {...axis} width={48} />
          <Tooltip
            contentStyle={{ background: "var(--panel)", border: "1px solid var(--border)", borderRadius: 8, fontSize: 12 }}
            labelFormatter={(t) => clock(t as number)}
            formatter={(v: number, n: string) => [fmtRate(v, props.unit), n]}
          />
          <Legend wrapperStyle={{ fontSize: 12 }} />
          {props.series.map((s) => (
            <Area
              key={s.key}
              type="monotone"
              dataKey={s.key}
              name={s.name}
              stroke={s.color}
              strokeWidth={1.6}
              fill={"url(#g-" + s.key + ")"}
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

/** ThresholdLine draws a series with optional threshold/baseline reference lines. */
export function ThresholdLine(props: {
  data: Record<string, number>[];
  dataKey: string;
  unit: string;
  color?: string;
  threshold?: number;
  baseline?: number;
  height?: number;
}) {
  return (
    <div style={{ width: "100%", height: props.height ?? 220 }}>
      <ResponsiveContainer>
        <LineChart data={props.data} margin={{ top: 8, right: 12, left: 0, bottom: 0 }}>
          <CartesianGrid stroke="var(--grid)" vertical={false} />
          <XAxis dataKey="t" tickFormatter={clock} {...axis} minTickGap={40} />
          <YAxis tickFormatter={tick(props.unit)} {...axis} width={48} />
          <Tooltip
            contentStyle={{ background: "var(--panel)", border: "1px solid var(--border)", borderRadius: 8, fontSize: 12 }}
            labelFormatter={(t) => clock(t as number)}
            formatter={(v: number) => fmtRate(v, props.unit)}
          />
          {props.threshold ? (
            <ReferenceLine y={props.threshold} stroke="var(--red)" strokeDasharray="5 4" label={{ value: "eşik", fill: "var(--red)", fontSize: 11, position: "insideTopRight" }} />
          ) : null}
          {props.baseline ? (
            <ReferenceLine y={props.baseline} stroke="var(--muted)" strokeDasharray="2 4" label={{ value: "baseline", fill: "var(--muted)", fontSize: 11, position: "insideBottomRight" }} />
          ) : null}
          <Line type="monotone" dataKey={props.dataKey} stroke={props.color ?? "var(--accent)"} strokeWidth={2} dot={false} isAnimationActive={false} />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}

/** Spark is a tiny inline sparkline. */
export function Spark({ data, dataKey, color }: { data: Record<string, number>[]; dataKey: string; color?: string }) {
  return (
    <div style={{ width: 120, height: 32 }}>
      <ResponsiveContainer>
        <AreaChart data={data} margin={{ top: 2, right: 0, left: 0, bottom: 2 }}>
          <Area type="monotone" dataKey={dataKey} stroke={color ?? "var(--accent)"} fill={color ?? "var(--accent)"} fillOpacity={0.15} strokeWidth={1.4} dot={false} isAnimationActive={false} />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}
