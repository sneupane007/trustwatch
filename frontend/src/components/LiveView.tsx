import { useEffect, useState } from "react";
import { fetchInterfaces, fetchLiveStatus, openLiveSocket, startLive, stopLive } from "../api";
import { formatCount, formatDuration } from "../format";
import type { Alert, AnalysisResult, LiveMessage, NetworkInterface } from "../types";
import { Dashboard } from "./Dashboard";
import { SEVERITY_COLOR, SeverityBadge } from "./SeverityBadge";

const REPLAY_SAMPLE = "mixed.pcapng";
const REPLAY = `replay:${REPLAY_SAMPLE}`; // the select value for replay; no interface is named like this
const TOAST_MS = 8000;

interface Session {
  id: string;
  running: boolean;
  startedAt: number | null; // seconds since the epoch, for the elapsed time
}

interface Toast {
  key: string;
  alert: Alert;
}

function interfaceLabel(iface: NetworkInterface): string {
  const name = iface.description.includes(iface.name) ? iface.description : `${iface.description} (${iface.name})`;
  return iface.ip ? `${name} · ${iface.ip}` : name;
}

function errorText(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/** Pick a source, press Start, and watch the dashboard update every second. */
export function LiveView() {
  const [interfaces, setInterfaces] = useState<NetworkInterface[]>([]);
  const [choice, setChoice] = useState(REPLAY);
  const [session, setSession] = useState<Session | null>(null);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [toasts, setToasts] = useState<Toast[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [disconnected, setDisconnected] = useState(false);

  useEffect(() => {
    fetchInterfaces()
      .then((list) => {
        setInterfaces([...list].sort((a, b) => Number(!a.ip) - Number(!b.ip))); // ones with an address first
        const likely = list.find((i) => i.ip && !i.ip.startsWith("127.")); // e.g. Wi-Fi, or a VM's network adapter
        if (likely) setChoice(likely.name);
      })
      .catch((err) => setError(errorText(err)));

    // A session may already be running (started earlier, or with curl): get its start time.
    fetchLiveStatus()
      .then((status) => {
        const { session_id: id, started_at: startedAt } = status;
        if (status.running && id !== null) {
          setSession((s) => (s?.id === id ? { ...s, startedAt } : { id, running: true, startedAt }));
        }
      })
      .catch(() => {}); // the interface list already shows any backend error
  }, []);

  useEffect(() => {
    const socket = openLiveSocket();
    let closedByUs = false; // leaving the Live tab, or React running effects twice in dev
    let sessionId = ""; // alert ids restart in every session, so toast keys include the session

    socket.onmessage = (event) => {
      const message: LiveMessage = JSON.parse(event.data);
      if (message.type === "snapshot") {
        sessionId = message.session_id;
        setSession((s) => (s?.id === message.session_id ? s : { id: message.session_id, running: true, startedAt: null }));
        setResult({ ...message.result, filename: message.source });
      } else if (message.type === "alert") {
        const key = `${sessionId}/${message.alert.id}`;
        setToasts((t) => [...t, { key, alert: message.alert }]);
        setTimeout(() => setToasts((t) => t.filter((toast) => toast.key !== key)), TOAST_MS);
      } else if (message.type === "error") {
        setError(message.message);
      } else {
        setSession((s) => (s?.id === message.session_id ? { ...s, running: false } : s));
      }
    };
    socket.onclose = () => {
      if (!closedByUs) setDisconnected(true);
    };
    return () => {
      closedByUs = true;
      socket.close();
    };
  }, []);

  async function act(action: () => Promise<void>) {
    setBusy(true);
    setError(null);
    try {
      await action();
    } catch (err) {
      setError(errorText(err));
    } finally {
      setBusy(false);
    }
  }

  async function start() {
    const { session_id } = await startLive(choice === REPLAY ? { replay: REPLAY_SAMPLE } : { interface: choice });
    setSession({ id: session_id, running: true, startedAt: Date.now() / 1000 });
  }

  const running = session?.running ?? false;
  const elapsed = running && session?.startedAt != null ? Math.max(0, Date.now() / 1000 - session.startedAt) : null;

  return (
    <div className="start">
      <section className="panel">
        <header>
          <h2>Live capture</h2>
          <p className="muted">
            The same detectors as upload mode, running on packets as they arrive. An alert pops up as soon as an attack
            is spotted.
          </p>
        </header>

        <div className="live-controls">
          <select
            className="select"
            aria-label="What to capture"
            value={choice}
            onChange={(e) => setChoice(e.target.value)}
            disabled={running}
          >
            {interfaces.length > 0 && (
              <optgroup label="Network interfaces">
                {interfaces.map((iface) => (
                  <option key={iface.name} value={iface.name}>
                    {interfaceLabel(iface)}
                  </option>
                ))}
              </optgroup>
            )}
            <optgroup label="Demo without the lab">
              <option value={REPLAY}>Replay {REPLAY_SAMPLE} (all three attacks, about 90 s)</option>
            </optgroup>
          </select>
          <button className="btn btn-primary" onClick={() => act(start)} disabled={busy || running}>
            Start
          </button>
          <button className="btn" onClick={() => act(stopLive)} disabled={busy || !running}>
            Stop
          </button>
        </div>

        <p className="live-status">
          {running ? (
            <>
              <span className="dot dot-live" aria-hidden="true" />
              <strong>Recording</strong>
              {result && <span className="mono">{result.filename}</span>}
              {elapsed !== null && (
                <span className="muted">· {elapsed < 60 ? `${Math.floor(elapsed)} s` : formatDuration(Math.floor(elapsed))}</span>
              )}
              {result && <span className="muted">· {formatCount(result.summary.packets)} packets</span>}
            </>
          ) : session ? (
            <span>
              Stopped. Saved to <code>backend/sessions/{session.id}/</code> (open <code>capture.pcap</code> in Wireshark).
            </span>
          ) : (
            <span className="muted">Not recording. Pick what to capture and press Start.</span>
          )}
        </p>
        <p className="muted small">
          For real attacks, run TrustWatch on the victim VM and pick its host-only adapter. Only attack your own lab VMs.
        </p>
      </section>

      {disconnected && (
        <div className="notice notice-error" role="alert">
          Lost the connection to the backend. Check that it is still running, then reload this page.
        </div>
      )}
      {error && (
        <div className="notice notice-error" role="alert">
          {error}
        </div>
      )}

      {result && <Dashboard result={result} />}

      <div className="toasts" aria-live="polite">
        {toasts.map(({ key, alert }) => (
          <div key={key} className="toast" style={{ borderLeftColor: SEVERITY_COLOR[alert.severity] }}>
            <SeverityBadge severity={alert.severity} />
            <div className="toast-body">
              <strong>{alert.title}</strong>
              <span className="mono small">
                {alert.attacker ?? "unknown"} → {alert.victim ?? "unknown"}
              </span>
            </div>
            <button
              className="toast-close"
              aria-label="Dismiss"
              onClick={() => setToasts((t) => t.filter((toast) => toast.key !== key))}
            >
              ×
            </button>
          </div>
        ))}
      </div>
    </div>
  );
}
