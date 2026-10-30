import {
  Area,
  AreaChart,
  CartesianGrid,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { formatClock, formatCompact, formatCount } from "../format";
import type { AnalysisResult, Alert } from "../types";
import { SEVERITY_COLOR } from "./SeverityBadge";

interface Props {
  timeline: AnalysisResult["timeline"];
  alerts: Alert[];
}

const AXIS_TICK = { fill: "var(--muted)", fontSize: 12 };

export function TrafficChart({ timeline, alerts }: Props) {
  if (timeline.points.length === 0) {
    return <p className="empty">This capture has no packets.</p>;
  }

  return (
    <div className="chart" role="img" aria-label="Packets over time, with a marker line at each alert">
      <ResponsiveContainer width="100%" height={260}>
        <AreaChart data={timeline.points} margin={{ top: 28, right: 16, bottom: 4, left: 0 }}>
          <CartesianGrid vertical={false} stroke="var(--grid)" />
          <XAxis
            dataKey="t"
            type="number"
            domain={["dataMin", "dataMax"]}
            tickFormatter={formatClock}
            tick={AXIS_TICK}
            stroke="var(--axis)"
            tickLine={false}
            minTickGap={48}
          />
          <YAxis
            width={44}
            allowDecimals={false}
            tickFormatter={formatCompact}
            tick={AXIS_TICK}
            axisLine={false}
            tickLine={false}
          />
          <Tooltip
            cursor={{ stroke: "var(--axis)" }}
            content={({ active, payload }) => {
              const point = payload?.[0]?.payload as { t: number; packets: number } | undefined;
              if (!active || !point) return null;
              return (
                <div className="tooltip">
                  <div className="muted">{formatClock(point.t)}</div>
                  <strong>{formatCount(point.packets)}</strong> packets
                  {timeline.bucket_seconds > 1 && ` in ${timeline.bucket_seconds} s`}
                </div>
              );
            }}
          />
          {alerts.map((alert) => (
            <ReferenceLine
              key={alert.id}
              x={alert.first_time}
              stroke={SEVERITY_COLOR[alert.severity]}
              strokeWidth={2}
              label={{ value: alert.title, position: "top", fill: "var(--ink-2)", fontSize: 12 }}
            />
          ))}
          <Area
            type="linear"
            dataKey="packets"
            stroke="var(--series-1)"
            strokeWidth={2}
            fill="var(--series-1)"
            fillOpacity={0.1}
            isAnimationActive={false}
            activeDot={{ r: 4, stroke: "var(--surface)", strokeWidth: 2, fill: "var(--series-1)" }}
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}
