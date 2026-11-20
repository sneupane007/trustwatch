import { useEffect, useState } from "react";
import { fetchSession, fetchSessions, sessionPcapUrl } from "../api";
import { formatClock, formatCount, formatDate, formatDuration } from "../format";
import type { SavedSession, SessionSummary } from "../types";
import { Dashboard } from "./Dashboard";

interface Props {
  active: boolean; // refresh the list each time the tab is shown
  openId: string | null; // the session being viewed, or null for the list
  onOpen: (id: string | null) => void;
}

type Load<T> = { kind: "loading" } | { kind: "error"; message: string } | { kind: "done"; data: T };

const message = (err: unknown) => (err instanceof Error ? err.message : String(err));

function DownloadLink({ id }: { id: string }) {
  return (
    <a className="btn" href={sessionPcapUrl(id)} download>
      Download .pcap
    </a>
  );
}

function SessionView({ id, onBack }: { id: string; onBack: () => void }) {
  const [state, setState] = useState<Load<SavedSession>>({ kind: "loading" });

  useEffect(() => {
    setState({ kind: "loading" });
    fetchSession(id)
      .then((data) => setState({ kind: "done", data }))
      .catch((err) => setState({ kind: "error", message: message(err) }));
  }, [id]);

  return (
    <div className="history">
      <div className="history-bar">
        <button type="button" className="btn" onClick={onBack}>
          ← All sessions
        </button>
        <DownloadLink id={id} />
      </div>
      {state.kind === "loading" && (
        <div className="panel empty-state">
          <div className="spinner" aria-hidden="true" />
          <p>Loading session {id}…</p>
        </div>
      )}
      {state.kind === "error" && (
        <div className="notice notice-error" role="alert">
          <strong>Couldn't open this session</strong>
          <p>{state.message}</p>
        </div>
      )}
      {state.kind === "done" && <Dashboard result={{ ...state.data, filename: state.data.source }} />}
    </div>
  );
}

/** Saved live sessions, newest first. Each can be reopened or downloaded as a .pcap for Wireshark. */
export function SessionHistory({ active, openId, onOpen }: Props) {
  const [state, setState] = useState<Load<SessionSummary[]>>({ kind: "loading" });

  function load() {
    fetchSessions()
      .then((data) => setState({ kind: "done", data }))
      .catch((err) => setState({ kind: "error", message: message(err) }));
  }

  useEffect(() => {
    if (active && openId === null) load();
  }, [active, openId]);

  if (openId !== null) return <SessionView id={openId} onBack={() => onOpen(null)} />;

  return (
    <section className="panel">
      <header className="history-head">
        <div>
          <h2>Session history</h2>
          <p className="muted">Every live capture is saved with its full result and a .pcap you can open in Wireshark.</p>
        </div>
        <button type="button" className="btn" onClick={load}>
          Refresh
        </button>
      </header>

      {state.kind === "loading" && (
        <div className="empty-state">
          <div className="spinner" aria-hidden="true" />
          <p>Loading sessions…</p>
        </div>
      )}
      {state.kind === "error" && (
        <div className="notice notice-error" role="alert">
          <strong>Couldn't load sessions</strong>
          <p>{state.message}</p>
        </div>
      )}
      {state.kind === "done" && state.data.length === 0 && (
        <div className="empty">
          <p>No live sessions yet. Start one from the Live tab.</p>
        </div>
      )}
      {state.kind === "done" && state.data.length > 0 && (
        <ul className="sessions">
          {state.data.map((s) => (
            <li key={s.id} className="session">
              <div className="session-info">
                <span className="mono session-source">{s.source}</span>
                <span className="muted small">
                  {formatDate(s.started_at)} · {formatClock(s.started_at)} · {formatDuration(s.ended_at - s.started_at)}
                </span>
                <span className="small">
                  {formatCount(s.packets)} packets ·{" "}
                  <span className={s.alerts > 0 ? "has-alerts" : undefined}>
                    {s.alerts > 0 && <span aria-hidden="true">▲ </span>}
                    {formatCount(s.alerts)} alert{s.alerts === 1 ? "" : "s"}
                  </span>
                </span>
              </div>
              <div className="session-actions">
                <button type="button" className="btn btn-primary" onClick={() => onOpen(s.id)}>
                  Open
                </button>
                <DownloadLink id={s.id} />
              </div>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
