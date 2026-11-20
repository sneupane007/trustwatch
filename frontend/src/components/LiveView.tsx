import { useEffect, useRef, useState } from "react";
import { fetchInterfaces, fetchLiveStatus, liveSocketUrl, startLive, stopLive, type LiveSource } from "../api";
import { formatCount } from "../format";
import type { Alert, LiveMessage, LiveResult, LiveStatus, NetworkInterface } from "../types";
import { Dashboard } from "./Dashboard";
import { SeverityBadge } from "./SeverityBadge";

// Captures under backend/samples/ that can be replayed as if they were live.
const REPLAY_SAMPLES = [
  { file: "mixed.pcapng", label: "mixed.pcapng: all three attacks (synthetic)" },
  { file: "lab/arp_spoof.pcapng", label: "lab/arp_spoof.pcapng: ARP spoofing from our lab" },
  { file: "baseline.pcap", label: "baseline.pcap: normal traffic only" },
];
const SPEEDS = [1, 5, 20];
const TOAST_SECONDS = 6;
const HIGHLIGHT_SECONDS = 3;
const RETRY_SECONDS = 2;

type Snapshot = { session_id: string; source: string; result: LiveResult };
type Notice = { kind: "saved"; sessionId: string } | { kind: "error"; message: string };
type Toast = { key: number; alert: Alert };
type Connection = "connecting" | "open" | "retrying";

const IDLE: LiveStatus = { running: false, session_id: null, source: null, started_at: null };

function formatElapsed(seconds: number): string {
  const s = Math.max(0, Math.floor(seconds));
  const pad = (n: number) => String(n).padStart(2, "0");
  return s >= 3600
    ? `${Math.floor(s / 3600)}:${pad(Math.floor((s % 3600) / 60))}:${pad(s % 60)}`
    : `${pad(Math.floor(s / 60))}:${pad(s % 60)}`;
}

/** "mixed.pcapng (replay)" -> "Replaying mixed.pcapng"; "en0" -> "Recording on en0". */
function describeSource(source: string): string {
  return source.endsWith(" (replay)") ? `Replaying ${source.slice(0, -" (replay)".length)}` : `Recording on ${source}`;
}

interface Props {
  onOpenSession: (id: string) => void;
}

export function LiveView({ onOpenSession }: Props) {
  const [interfaces, setInterfaces] = useState<NetworkInterface[] | null>(null);
  const [interfaceError, setInterfaceError] = useState<string | null>(null);
  const [choice, setChoice] = useState(`replay:${REPLAY_SAMPLES[0].file}`);
  const [speed, setSpeed] = useState(1);

  const [status, setStatus] = useState<LiveStatus>(IDLE);
  const [busy, setBusy] = useState(false);
  const [connection, setConnection] = useState<Connection>("connecting");
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null);
  const [rate, setRate] = useState<number | null>(null);
  const [notice, setNotice] = useState<Notice | null>(null);
  const [toasts, setToasts] = useState<Toast[]>([]);
  const [highlightId, setHighlightId] = useState<string | null>(null);
  const [now, setNow] = useState(() => Date.now() / 1000);

  const lastCount = useRef<{ session: string; packets: number; at: number } | null>(null);
  const toastKey = useRef(0);

  useEffect(() => {
    fetchInterfaces()
      .then(setInterfaces)
      .catch((err) => setInterfaceError(err instanceof Error ? err.message : String(err)));
  }, []);

  function refreshStatus() {
    fetchLiveStatus()
      .then(setStatus)
      .catch(() => {}); // the socket's own retry loop reports a down backend
  }

  // One WebSocket for as long as the tab exists; reconnect every 2 s if it drops.
  useEffect(() => {
    let socket: WebSocket | null = null;
    let retry: ReturnType<typeof setTimeout> | undefined;
    let unmounted = false;

    function handle(message: LiveMessage) {
      switch (message.type) {
        case "snapshot": {
          const packets = message.result.summary.packets;
          const at = Date.now() / 1000;
          const last = lastCount.current;
          if (last && last.session === message.session_id && at > last.at) {
            setRate((packets - last.packets) / (at - last.at));
          }
          lastCount.current = { session: message.session_id, packets, at };
          setSnapshot({ session_id: message.session_id, source: message.source, result: message.result });
          break;
        }
        case "alert": {
          const key = ++toastKey.current;
          setToasts((t) => [...t, { key, alert: message.alert }]);
          setHighlightId(message.alert.id);
          setTimeout(() => setToasts((t) => t.filter((x) => x.key !== key)), TOAST_SECONDS * 1000);
          setTimeout(() => setHighlightId((id) => (id === message.alert.id ? null : id)), HIGHLIGHT_SECONDS * 1000);
          break;
        }
        case "stopped":
          setStatus(IDLE);
          setRate(null);
          setNotice((n) => (n?.kind === "error" ? n : { kind: "saved", sessionId: message.session_id }));
          break;
        case "error":
          setNotice({ kind: "error", message: message.message });
          break;
      }
    }

    function connect() {
      setConnection("connecting");
      socket = new WebSocket(liveSocketUrl());
      socket.onopen = () => {
        setConnection("open");
        refreshStatus();
      };
      socket.onmessage = (event) => handle(JSON.parse(event.data) as LiveMessage);
      socket.onclose = () => {
        if (unmounted) return;
        setConnection("retrying");
        retry = setTimeout(connect, RETRY_SECONDS * 1000);
      };
    }

    connect();
    return () => {
      unmounted = true;
      clearTimeout(retry);
      socket?.close();
    };
  }, []);

  // Tick the elapsed time while recording.
  useEffect(() => {
    if (!status.running) return;
    const timer = setInterval(() => setNow(Date.now() / 1000), 1000);
    return () => clearInterval(timer);
  }, [status.running]);

  async function start() {
    const [kind, value] = [choice.slice(0, choice.indexOf(":")), choice.slice(choice.indexOf(":") + 1)];
    const source: LiveSource = kind === "replay" ? { replay: value, speed } : { interface: value };
    setBusy(true);
    setNotice(null);
    setToasts([]);
    setSnapshot(null);
    setRate(null);
    lastCount.current = null;
    try {
      await startLive(source);
      setNow(Date.now() / 1000);
      refreshStatus();
    } catch (err) {
      setNotice({ kind: "error", message: err instanceof Error ? err.message : String(err) });
    } finally {
      setBusy(false);
    }
  }

  async function stop() {
    setBusy(true);
    try {
      const stopped = await stopLive();
      setStatus(IDLE);
      setRate(null);
      setNotice((n) => (n?.kind === "error" ? n : { kind: "saved", sessionId: stopped.session_id }));
    } catch (err) {
      setNotice({ kind: "error", message: err instanceof Error ? err.message : String(err) });
    } finally {
      setBusy(false);
    }
  }

  const isReplay = choice.startsWith("replay:");

  return (
    <div className="live">
      <section className="panel live-controls" aria-label="Live capture controls">
        <div className="control-row">
          <label className="field">
            <span className="field-label">Source</span>
            <select value={choice} onChange={(e) => setChoice(e.target.value)} disabled={status.running || busy}>
              <optgroup label="Replay a sample (no lab needed)">
                {REPLAY_SAMPLES.map((s) => (
                  <option key={s.file} value={`replay:${s.file}`}>
                    {s.label}
                  </option>
                ))}
              </optgroup>
              <optgroup label={interfaces === null && !interfaceError ? "Network interfaces (loading…)" : "Network interfaces"}>
                {(interfaces ?? []).map((i) => (
                  <option key={i.name} value={`iface:${i.name}`}>
                    {i.name}
                    {i.description && i.description !== i.name ? ` (${i.description})` : ""}
                    {i.ip ? ` · ${i.ip}` : ""}
                  </option>
                ))}
              </optgroup>
            </select>
          </label>
          {isReplay && (
            <label className="field field-narrow">
              <span className="field-label">Speed</span>
              <select value={speed} onChange={(e) => setSpeed(Number(e.target.value))} disabled={status.running || busy}>
                {SPEEDS.map((s) => (
                  <option key={s} value={s}>
                    {s}×
                  </option>
                ))}
              </select>
            </label>
          )}
          <div className="control-buttons">
            {status.running ? (
              <button type="button" className="btn btn-stop" onClick={stop} disabled={busy}>
                <span className="square" aria-hidden="true" /> Stop
              </button>
            ) : (
              <button type="button" className="btn btn-primary" onClick={start} disabled={busy}>
                <span className="dot dot-start" aria-hidden="true" /> Start
              </button>
            )}
          </div>
        </div>

        <p className="live-status" role="status">
          {status.running && status.source ? (
            <>
              <span className="dot dot-live" aria-hidden="true" /> {describeSource(status.source)}
              {status.started_at !== null && ` · ${formatElapsed(now - status.started_at)} elapsed`}
              {rate !== null && ` · ${formatCount(Math.max(0, Math.round(rate)))} packets/s`}
            </>
          ) : (
            <span className="muted">Not recording.</span>
          )}
          {connection === "retrying" && <span className="warn"> · Disconnected, retrying…</span>}
          {connection === "connecting" && <span className="muted"> · Connecting…</span>}
        </p>
        {interfaceError && (
          <p className="muted small">Couldn't list network interfaces ({interfaceError}). Replay still works.</p>
        )}
      </section>

      {notice?.kind === "error" && (
        <div className="notice notice-error" role="alert">
          <strong>Live capture problem</strong>
          <p>{notice.message}</p>
        </div>
      )}
      {notice?.kind === "saved" && (
        <div className="notice notice-ok">
          <p>
            <span className="good">✓</span> Session saved.{" "}
            <button type="button" className="link-button" onClick={() => onOpenSession(notice.sessionId)}>
              Open it in History
            </button>
          </p>
        </div>
      )}

      <div className="toasts" aria-live="polite">
        {toasts.map(({ key, alert }) => (
          <div key={key} className={`toast toast-${alert.severity}`}>
            <SeverityBadge severity={alert.severity} />
            <span>
              <strong>{alert.title}</strong>
              {(alert.attacker || alert.victim) && (
                <span className="mono">
                  {" "}
                  · {alert.attacker ?? "unknown"} → {alert.victim ?? "unknown"}
                </span>
              )}
            </span>
            <button
              type="button"
              className="btn-close btn"
              onClick={() => setToasts((t) => t.filter((x) => x.key !== key))}
            >
              <span aria-hidden="true">✕</span>
              <span className="visually-hidden">Dismiss</span>
            </button>
          </div>
        ))}
      </div>

      {snapshot ? (
        <Dashboard
          result={{ ...snapshot.result, filename: snapshot.source }}
          live={status.running && status.session_id === snapshot.session_id}
          highlightAlertId={highlightId}
        />
      ) : status.running ? (
        <div className="panel empty-state">
          <div className="spinner" aria-hidden="true" />
          <p>Waiting for the first snapshot…</p>
        </div>
      ) : (
        <div className="panel empty-state">
          <p>
            <strong>Watch traffic as it happens.</strong>
          </p>
          <p className="muted">
            Pick a network interface to capture live, or replay a sample to demo without the lab. Alerts pop up here
            the moment a detector raises them, and every session is saved to History.
          </p>
        </div>
      )}
    </div>
  );
}
