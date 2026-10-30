import { formatClock, formatCount } from "../format";
import type { Alert, DetectorInfo } from "../types";
import { SeverityBadge } from "./SeverityBadge";

interface Props {
  alerts: Alert[];
  detectors: DetectorInfo[];
  captureStart: number | null;
}

export function AlertList({ alerts, detectors, captureStart }: Props) {
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
        <li key={alert.id} className="alert">
          <div className="alert-head">
            <SeverityBadge severity={alert.severity} />
            <h3>{alert.title}</h3>
            <span className="muted">
              {formatClock(alert.first_time)}
              {captureStart !== null && ` · ${(alert.first_time - captureStart).toFixed(1)} s into the capture`}
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
