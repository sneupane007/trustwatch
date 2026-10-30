import { formatBytes, formatCount } from "../format";
import type { Alert, AnalysisResult } from "../types";

interface Props {
  talkers: AnalysisResult["top_talkers"];
  alerts: Alert[];
}

export function TopTalkers({ talkers, alerts }: Props) {
  if (talkers.length === 0) return <p className="empty">No IP traffic.</p>;
  const attackers = new Set(alerts.map((a) => a.attacker));

  return (
    <table className="table">
      <thead>
        <tr>
          <th>Source</th>
          <th className="num">Packets</th>
          <th className="num">Data</th>
        </tr>
      </thead>
      <tbody>
        {talkers.map((t) => (
          <tr key={t.ip}>
            <td>
              <span className="mono">{t.ip}</span>
              {attackers.has(t.ip) && <span className="tag">attacker in an alert</span>}
            </td>
            <td className="num">{formatCount(t.packets)}</td>
            <td className="num">{formatBytes(t.bytes)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
