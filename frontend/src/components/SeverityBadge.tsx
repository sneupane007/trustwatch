import type { Severity } from "../types";

const LABEL: Record<Severity, string> = { high: "High", medium: "Medium", low: "Low" };
const ICON: Record<Severity, string> = { high: "▲", medium: "◆", low: "●" };

// Status colors from the chart palette; each always appears with an icon and a word.
export const SEVERITY_COLOR: Record<Severity, string> = {
  high: "var(--critical)",
  medium: "var(--serious)",
  low: "var(--warning)",
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span className={`badge sev-${severity}`}>
      <span aria-hidden="true">{ICON[severity]}</span>
      {LABEL[severity]}
    </span>
  );
}
