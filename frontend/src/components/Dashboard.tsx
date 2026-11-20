import { useState, type ReactNode } from "react";
import { formatBytes, formatClock, formatCount, formatDate, formatDuration } from "../format";
import type { AnalysisResult, Severity } from "../types";
import { AlertDetail } from "./AlertDetail";
import { AlertList } from "./AlertList";
import { DetectorList } from "./DetectorList";
import { ProtocolBars } from "./ProtocolBars";
import { TopTalkers } from "./TopTalkers";
import { TrafficChart } from "./TrafficChart";

function Panel({ title, subtitle, children }: { title: string; subtitle?: string; children: ReactNode }) {
  return (
    <section className="panel">
      <header>
        <h2>{title}</h2>
        {subtitle && <p className="muted">{subtitle}</p>}
      </header>
      {children}
    </section>
  );
}

function Tile({ label, value, note }: { label: string; value: string; note?: string }) {
  return (
    <div className="tile">
      <div className="tile-label">{label}</div>
      <div className="tile-value">{value}</div>
      {note && <div className="tile-note muted">{note}</div>}
    </div>
  );
}

function severityNote(result: AnalysisResult): string {
  const order: Severity[] = ["high", "medium", "low"];
  const parts = order
    .map((s) => [s, result.alerts.filter((a) => a.severity === s).length] as const)
    .filter(([, n]) => n > 0)
    .map(([s, n]) => `${n} ${s}`);
  return parts.length ? parts.join(" · ") : "none found";
}

interface Props {
  result: AnalysisResult;
  live?: boolean; // shows a Live badge; the live view passes a fresh snapshot every second
  highlightAlertId?: string | null;
}

/** Everything we know about one capture: an upload, a live snapshot or a saved session. */
export function Dashboard({ result, live = false, highlightAlertId = null }: Props) {
  const { summary } = result;
  const [selectedId, setSelectedId] = useState<string | null>(null);
  // Look the alert up by id so an open panel keeps updating while a live attack goes on.
  const selected = result.alerts.find((a) => a.id === selectedId) ?? null;

  return (
    <div className="dashboard">
      <div className="file-bar">
        <span className="mono file-name">{result.filename}</span>
        {live && (
          <span className="live-badge">
            <span className="dot dot-live" aria-hidden="true" /> Live
          </span>
        )}
        {summary.start !== null && summary.end !== null && (
          <span className="muted">
            {formatDate(summary.start)} · {formatClock(summary.start)} – {formatClock(summary.end)}
          </span>
        )}
      </div>

      <div className="tiles">
        <Tile label="Packets" value={formatCount(summary.packets)} />
        <Tile label="Duration" value={formatDuration(summary.duration)} />
        <Tile label="Data" value={formatBytes(summary.bytes)} />
        <Tile label="Alerts" value={formatCount(result.alerts.length)} note={severityNote(result)} />
      </div>

      <div className="grid grid-main">
        <Panel
          title="Traffic over time"
          subtitle={`Packets per ${
            result.timeline.bucket_seconds === 1 ? "second" : `${result.timeline.bucket_seconds} seconds`
          }. Colored lines mark when each alert started.`}
        >
          <TrafficChart timeline={result.timeline} alerts={result.alerts} />
        </Panel>
        <Panel title="Detectors" subtitle="One per attack from our presentation">
          <DetectorList detectors={result.detectors} />
        </Panel>
      </div>

      <Panel title={`Alerts (${result.alerts.length})`}>
        <AlertList
          alerts={result.alerts}
          detectors={result.detectors}
          captureStart={summary.start}
          onSelect={(alert) => setSelectedId(alert.id)}
          highlightId={highlightAlertId}
        />
      </Panel>

      <div className="grid grid-halves">
        <Panel title="Protocols" subtitle="Packets by highest protocol layer">
          <ProtocolBars protocols={result.protocols} total={summary.packets} />
        </Panel>
        <Panel title="Top talkers" subtitle="Sources that sent the most packets">
          <TopTalkers talkers={result.top_talkers} alerts={result.alerts} />
        </Panel>
      </div>

      {selected && <AlertDetail key={selected.id} alert={selected} onClose={() => setSelectedId(null)} />}
    </div>
  );
}
