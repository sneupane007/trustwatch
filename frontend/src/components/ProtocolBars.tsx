import { formatCount } from "../format";
import type { AnalysisResult } from "../types";

export function ProtocolBars({ protocols, total }: { protocols: AnalysisResult["protocols"]; total: number }) {
  if (protocols.length === 0) return <p className="empty">No packets.</p>;
  const max = protocols[0].packets;

  return (
    <ul className="bars">
      {protocols.map((p) => (
        <li key={p.name}>
          <span className="bar-label">{p.name}</span>
          <span className="bar-track">
            <span className="bar" style={{ width: `calc((100% - 7.5rem) * ${p.packets / max})` }} />
            <span className="bar-value">
              {formatCount(p.packets)} <span className="muted">· {((p.packets / total) * 100).toFixed(1)}%</span>
            </span>
          </span>
        </li>
      ))}
    </ul>
  );
}
