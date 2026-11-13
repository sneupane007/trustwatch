// Mirrors the JSON the backend returns (backend/app/engine/engine.py: Engine.result).

export type Severity = "high" | "medium" | "low";

export interface Alert {
  id: string;
  detector: string;
  severity: Severity;
  title: string;
  summary: string;
  attacker: string | null;
  victim: string | null;
  first_time: number; // seconds since the epoch
  last_time: number;
  wireshark_filter: string;
  packets: number[]; // evidence frame numbers (first 50)
  packet_count: number;
  details: Record<string, unknown>;
}

export interface DetectorInfo {
  id: string;
  name: string;
  description: string;
  implemented: boolean;
  alert_count?: number; // present in analysis results
}

export interface AnalysisResult {
  filename: string;
  summary: {
    packets: number;
    bytes: number;
    start: number | null;
    end: number | null;
    duration: number;
  };
  protocols: { name: string; packets: number }[];
  top_talkers: { ip: string; packets: number; bytes: number }[];
  timeline: { bucket_seconds: number; points: { t: number; packets: number }[] };
  alerts: Alert[];
  detectors: DetectorInfo[];
}

// Live mode (backend/app/live.py)

export interface NetworkInterface {
  name: string; // what to capture on, e.g. "en0"
  description: string; // friendly name, e.g. "Wi-Fi"
  ip: string; // first IPv4 address, or ""
}

export interface LiveStatus {
  running: boolean;
  session_id: string | null;
  source: string | null;
  started_at: number | null;
}

/** What the /api/live/ws WebSocket sends. A snapshot arrives every second. */
export type LiveMessage =
  | { type: "snapshot"; session_id: string; source: string; result: Omit<AnalysisResult, "filename"> }
  | { type: "alert"; alert: Alert }
  | { type: "error"; message: string }
  | { type: "stopped"; session_id: string };
