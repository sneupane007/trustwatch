import { useEffect, useState } from "react";
import { analyzeCapture, fetchDetectors } from "./api";
import { Dashboard } from "./components/Dashboard";
import { LiveView } from "./components/LiveView";
import { SessionHistory } from "./components/SessionHistory";
import { UploadZone } from "./components/UploadZone";
import type { AnalysisResult, DetectorInfo } from "./types";

type State =
  | { kind: "idle" }
  | { kind: "loading"; fileName: string }
  | { kind: "error"; message: string }
  | { kind: "done"; result: AnalysisResult };

type Tab = "upload" | "live" | "history";
const TABS: { id: Tab; label: string }[] = [
  { id: "upload", label: "Upload" },
  { id: "live", label: "Live" },
  { id: "history", label: "History" },
];

function Logo() {
  return (
    <svg viewBox="0 0 32 32" width="32" height="32" aria-hidden="true">
      <path d="M16 3 5 7v8c0 7 4.7 12 11 14 6.3-2 11-7 11-14V7L16 3Z" fill="var(--series-1)" />
      <path
        d="M9 17h4l2-5 3 9 2-4h3"
        fill="none"
        stroke="#fff"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

export default function App() {
  const [state, setState] = useState<State>({ kind: "idle" });
  const [detectors, setDetectors] = useState<DetectorInfo[] | null>(null);
  const [backendDown, setBackendDown] = useState(false);
  const [tab, setTab] = useState<Tab>("upload");
  const [openSession, setOpenSession] = useState<string | null>(null);

  useEffect(() => {
    fetchDetectors()
      .then(setDetectors)
      .catch(() => setBackendDown(true));
  }, []);

  async function handleFile(file: File) {
    setTab("upload");
    setState({ kind: "loading", fileName: file.name });
    try {
      setState({ kind: "done", result: await analyzeCapture(file) });
    } catch (err) {
      setState({ kind: "error", message: err instanceof Error ? err.message : String(err) });
    }
  }

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <Logo />
          <div>
            <h1>TrustWatch</h1>
            <p className="muted">Network attack detection lab</p>
          </div>
        </div>
        <div className="actions">
          <nav className="tabs" role="tablist" aria-label="Mode">
            {TABS.map((t) => (
              <button
                key={t.id}
                type="button"
                role="tab"
                id={`tab-${t.id}`}
                aria-selected={tab === t.id}
                aria-controls={`panel-${t.id}`}
                className="tab"
                onClick={() => setTab(t.id)}
              >
                {t.id === "live" && <span className="dot" aria-hidden="true" />}
                {t.label}
              </button>
            ))}
          </nav>
          <label className="btn btn-primary">
            Upload capture
            <input
              type="file"
              accept=".pcap,.pcapng,.cap"
              hidden
              onChange={(e) => {
                const file = e.target.files?.[0];
                if (file) handleFile(file);
                e.target.value = "";
              }}
            />
          </label>
        </div>
      </header>

      <main>
        <div role="tabpanel" id="panel-upload" aria-labelledby="tab-upload" hidden={tab !== "upload"}>
          {state.kind === "done" ? (
            <Dashboard result={state.result} />
          ) : (
            <UploadZone
              onFile={handleFile}
              loadingFile={state.kind === "loading" ? state.fileName : null}
              error={state.kind === "error" ? state.message : null}
              detectors={detectors}
              backendDown={backendDown}
            />
          )}
        </div>
        {/* Live stays mounted on other tabs so its connection and running session aren't lost. */}
        <div role="tabpanel" id="panel-live" aria-labelledby="tab-live" hidden={tab !== "live"}>
          <LiveView
            onOpenSession={(id) => {
              setOpenSession(id);
              setTab("history");
            }}
          />
        </div>
        <div role="tabpanel" id="panel-history" aria-labelledby="tab-history" hidden={tab !== "history"}>
          <SessionHistory active={tab === "history"} openId={openSession} onOpen={setOpenSession} />
        </div>
      </main>
    </div>
  );
}
