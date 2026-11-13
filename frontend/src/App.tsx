import { useEffect, useState } from "react";
import { analyzeCapture, fetchDetectors } from "./api";
import { Dashboard } from "./components/Dashboard";
import { LiveView } from "./components/LiveView";
import { UploadZone } from "./components/UploadZone";
import type { AnalysisResult, DetectorInfo } from "./types";

type State =
  | { kind: "idle" }
  | { kind: "loading"; fileName: string }
  | { kind: "error"; message: string }
  | { kind: "done"; result: AnalysisResult };

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
  const [mode, setMode] = useState<"upload" | "live">("upload");
  const [state, setState] = useState<State>({ kind: "idle" });
  const [detectors, setDetectors] = useState<DetectorInfo[] | null>(null);
  const [backendDown, setBackendDown] = useState(false);

  useEffect(() => {
    fetchDetectors()
      .then(setDetectors)
      .catch(() => setBackendDown(true));
  }, []);

  async function handleFile(file: File) {
    setMode("upload");
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
          <button
            className="btn"
            aria-pressed={mode === "live"}
            onClick={() => setMode(mode === "live" ? "upload" : "live")}
          >
            <span className="dot" aria-hidden="true" /> Live capture
          </button>
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
        {mode === "live" ? (
          <LiveView />
        ) : state.kind === "done" ? (
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
      </main>
    </div>
  );
}
