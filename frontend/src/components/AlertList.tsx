import { formatClock, formatCount } from "../format";
import type { Alert, DetectorInfo } from "../types";
import { SeverityBadge } from "./SeverityBadge";

interface Props {
  alerts: Alert[];
  detectors: DetectorInfo[];
  captureStart: number | null;
  onSelect: (alert: Alert) => void;
  highlightId?: string | null; // briefly flashed, e.g. an alert that just arrived live
}

export function AlertList({ alerts, detectors, captureStart, onSelect, highlightId }: Props) {
  const pending = detectors.filter((d) => !d.implemented).map((d) => d.name);

  if (alerts.length === 0) {
    return (
      <div className="empty">
        <p>No attacks detected in this capture.</p>
        {pending.length > 0 && (
          <p className="muted">Not checked yet: {pending.join(", ")} (detectors still being built).</p>
        )}
      </div>
    );
  }

  return (
    <ul className="alerts">
      {alerts.map((alert) => (
        <li
          key={alert.id}
          className={`alert alert-clickable${alert.id === highlightId ? " alert-flash" : ""}`}
          onClick={(e) => {
            if (!window.getSelection()?.toString() && !(e.target as HTMLElement).closest("button")) onSelect(alert);
          }}
        >
          <div className="alert-head">
            <SeverityBadge severity={alert.severity} />
            <h3>
              <button type="button" className="link-button" onClick={() => onSelect(alert)}>
                {alert.title}
              </button>
            </h3>
            <span className="muted">
              {formatClock(alert.first_time)}
              {captureStart !== null && ` · ${(alert.first_time - captureStart).toFixed(1)} s into the capture`}
            </span>
            <span className="details-hint muted small" aria-hidden="true">
              Details →
            </span>
          </div>
          {(alert.attacker || alert.victim) && (
            <div className="who mono">
              {alert.attacker ?? "unknown"} <span aria-label="targeting">→</span> {alert.victim ?? "unknown"}
            </div>
          )}
          <p>{alert.summary}</p>
          <dl className="evidence">
            <div>
              <dt>Evidence</dt>
              <dd>
                {formatCount(alert.packet_count)} packets, starting at frame #{alert.packets[0]}
              </dd>
            </div>
            <div>
              <dt>Wireshark filter</dt>
              <dd>
                <code>{alert.wireshark_filter}</code>
              </dd>
            </div>
          </dl>
        </li>
      ))}
    </ul>
  );
}
