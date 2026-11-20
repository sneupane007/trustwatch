import { useEffect, useRef, useState, type ReactNode } from "react";
import { ATTACK_INFO, CLOSING_IDEA } from "../attackInfo";
import { formatClock, formatCount, formatDate } from "../format";
import type { Alert } from "../types";
import { SeverityBadge } from "./SeverityBadge";

interface Props {
  alert: Alert;
  onClose: () => void;
}

type Row = [label: string, value: ReactNode];

const REASONS: Record<string, string> = {
  conflicting_answers: "Two different answers to the same query",
  known_good_mismatch: "Answer differs from the known-good address",
};

function text(value: unknown): string {
  if (value === null || value === undefined || value === "") return "none";
  if (Array.isArray(value)) return value.length ? value.map(text).join(", ") : "none";
  if (typeof value === "number") return formatCount(value);
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

interface DnsResponse {
  frame: number;
  answers: string[];
  src_mac: string | null;
}

/** alert.details as labelled rows. Keys per detector: docs/phase2-part2-live-dashboard.md, Task 2. */
function detailRows(alert: Alert): Row[] {
  const d = alert.details;
  switch (alert.detector) {
    case "port_scan":
      return [
        ["Ports probed", text(d.ports_probed)],
        ["Open ports (SYN/ACK)", text(d.open_ports)],
        ["Window", `${d.window_seconds} s`],
        ["Threshold", `${d.port_threshold} distinct ports inside the window`],
      ];
    case "arp_spoof":
      return [
        ["IP address", <span className="mono">{text(d.ip)}</span>],
        ["Original MAC", <span className="mono">{text(d.original_mac)}</span>],
        ["First seen", `frame #${d.original_first_frame}`],
        ["New MAC", <span className="mono">{text(d.new_mac)}</span>],
        ["Forged claims", text(d.claims)],
      ];
    case "dns_spoof": {
      const responses = (d.responses as DnsResponse[] | undefined) ?? [];
      return [
        ["Name", <span className="mono">{text(d.qname)}</span>],
        ["Query ID", <span className="mono">0x{Number(d.query_id).toString(16).padStart(4, "0")}</span>],
        ["Client", <span className="mono">{text(d.client)}</span>],
        ["Reason", REASONS[String(d.reason)] ?? text(d.reason)],
        [
          "Responses",
          <ol className="plain-list">
            {responses.map((r) => (
              <li key={r.frame}>
                Frame #{r.frame}: <span className="mono">{text(r.answers)}</span>
                {r.src_mac && (
                  <span className="muted">
                    {" "}
                    from <span className="mono">{r.src_mac}</span>
                  </span>
                )}
              </li>
            ))}
          </ol>,
        ],
      ];
    }
    default:
      return Object.entries(d).map(([key, value]) => [key.replace(/_/g, " "), text(value)]);
  }
}

function Rows({ rows }: { rows: Row[] }) {
  return (
    <dl className="evidence">
      {rows.map(([label, value]) => (
        <div key={label}>
          <dt>{label}</dt>
          <dd>{value}</dd>
        </div>
      ))}
    </dl>
  );
}

function CopyFilter({ filter }: { filter: string }) {
  const [status, setStatus] = useState<"idle" | "copied" | "failed">("idle");

  async function copy() {
    try {
      await navigator.clipboard.writeText(filter);
      setStatus("copied");
    } catch {
      setStatus("failed");
    }
  }

  useEffect(() => {
    if (status === "idle") return;
    const timer = setTimeout(() => setStatus("idle"), 2500);
    return () => clearTimeout(timer);
  }, [status]);

  return (
    <div className="copy-filter">
      <code>{filter}</code>
      <button type="button" className="btn btn-primary" onClick={copy}>
        Copy Wireshark filter
      </button>
      <span role="status" className="small">
        {status === "copied" && <span className="good">✓ Copied</span>}
        {status === "failed" && <span className="muted">Couldn't copy. Select the filter and copy it by hand.</span>}
      </span>
    </div>
  );
}

/** Side panel (a full-screen sheet on phones) that explains one alert. Esc or the backdrop closes it. */
export function AlertDetail({ alert, onClose }: Props) {
  const dialog = useRef<HTMLDialogElement>(null);
  const info = ATTACK_INFO[alert.detector];

  useEffect(() => {
    const opener = document.activeElement as HTMLElement | null;
    if (!dialog.current?.open) dialog.current?.showModal(); // focus moves into the panel
    return () => opener?.focus(); // and back to the alert on close
  }, []);

  return (
    <dialog
      ref={dialog}
      className="detail"
      aria-labelledby="detail-title"
      onClose={onClose}
      onClick={(e) => {
        if (e.target === dialog.current) dialog.current.close(); // click on the backdrop
      }}
    >
      <div className="detail-body">
        <header className="detail-head">
          <div className="alert-head">
            <SeverityBadge severity={alert.severity} />
            <h2 id="detail-title">{alert.title}</h2>
            <button type="button" className="btn btn-close" onClick={() => dialog.current?.close()} autoFocus>
              <span aria-hidden="true">✕</span>
              <span className="visually-hidden">Close</span>
            </button>
          </div>
          {(alert.attacker || alert.victim) && (
            <div className="who mono">
              {alert.attacker ?? "unknown"} <span aria-label="targeting">→</span> {alert.victim ?? "unknown"}
            </div>
          )}
          <p className="muted small">
            {formatDate(alert.first_time)} · {formatClock(alert.first_time)} – {formatClock(alert.last_time)}
          </p>
          <p>{alert.summary}</p>
        </header>

        <section>
          <h3>See it in Wireshark</h3>
          <CopyFilter filter={alert.wireshark_filter} />
          <p className="muted small">
            In Wireshark, paste into the display filter bar and press Enter. Or jump straight to frame #
            {alert.packets[0]} with Go → Go to Packet (Cmd/Ctrl + G).
          </p>
        </section>

        <section>
          <h3>Evidence</h3>
          <p>
            {formatCount(alert.packet_count)} packet{alert.packet_count === 1 ? "" : "s"}
            {alert.packet_count > alert.packets.length && ` (first ${alert.packets.length} listed)`}
          </p>
          <p className="frames mono small">{alert.packets.map((n) => `#${n}`).join("  ")}</p>
        </section>

        <section>
          <h3>Details</h3>
          <Rows rows={detailRows(alert)} />
        </section>

        {info && (
          <>
            <section>
              <h3>What is this attack?</h3>
              <Rows
                rows={[
                  ["Layer", info.layer],
                  ["How it works", info.howItWorks],
                  ["Trust it abuses", info.trustAssumption],
                  ["In Wireshark", info.inWireshark],
                  ["How we detect it", info.howWeDetect],
                ]}
              />
            </section>
            <section>
              <h3>How it's fixed in the real world</h3>
              <p>{info.realWorldFix}</p>
            </section>
          </>
        )}

        <p className="closing">{CLOSING_IDEA}</p>
      </div>
    </dialog>
  );
}
