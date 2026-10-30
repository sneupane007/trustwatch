import type { DetectorInfo } from "../types";

export function DetectorList({ detectors }: { detectors: DetectorInfo[] }) {
  return (
    <ul className="detectors">
      {detectors.map((d) => (
        <li key={d.id}>
          <div>
            <strong>{d.name}</strong>
            <p className="muted">{d.description}</p>
          </div>
          {d.implemented ? (
            <span className="chip chip-ok">
              <span aria-hidden="true">✓</span> Active
              {d.alert_count !== undefined && ` · ${d.alert_count} alert${d.alert_count === 1 ? "" : "s"}`}
            </span>
          ) : (
            <span className="chip chip-pending">
              <span aria-hidden="true">…</span> Pending
            </span>
          )}
        </li>
      ))}
    </ul>
  );
}
