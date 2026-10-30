import { useState, type DragEvent } from "react";
import type { DetectorInfo } from "../types";
import { DetectorList } from "./DetectorList";

interface Props {
  onFile: (file: File) => void;
  loadingFile: string | null;
  error: string | null;
  detectors: DetectorInfo[] | null;
  backendDown: boolean;
}

export function UploadZone({ onFile, loadingFile, error, detectors, backendDown }: Props) {
  const [dragging, setDragging] = useState(false);

  function handleDrop(event: DragEvent) {
    event.preventDefault();
    setDragging(false);
    const file = event.dataTransfer.files[0];
    if (file) onFile(file);
  }

  return (
    <div className="start">
      {backendDown && (
        <div className="notice" role="alert">
          Can't reach the backend. Start it in another terminal:
          <code>cd backend && .venv/bin/uvicorn app.main:app --reload --port 8000</code>
        </div>
      )}

      <label
        className={`dropzone${dragging ? " dragging" : ""}`}
        onDragOver={(e) => {
          e.preventDefault();
          setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={handleDrop}
      >
        <input
          type="file"
          accept=".pcap,.pcapng,.cap"
          hidden
          disabled={loadingFile !== null}
          onChange={(e) => {
            const file = e.target.files?.[0];
            if (file) onFile(file);
            e.target.value = "";
          }}
        />
        {loadingFile ? (
          <>
            <span className="spinner" aria-hidden="true" />
            <strong>Analyzing {loadingFile}…</strong>
          </>
        ) : (
          <>
            <strong>Drop a Wireshark capture here</strong>
            <span className="muted">.pcap or .pcapng · or click to choose a file</span>
            <span className="muted small">
              Sample captures: <code>backend/samples/</code> (try <code>mixed.pcapng</code>)
            </span>
          </>
        )}
      </label>

      {error && (
        <div className="notice notice-error" role="alert">
          {error}
        </div>
      )}

      {detectors && (
        <section className="panel">
          <header>
            <h2>What we detect</h2>
            <p className="muted">Each detector looks for the packet pattern from our attack slides.</p>
          </header>
          <DetectorList detectors={detectors} />
        </section>
      )}
    </div>
  );
}
