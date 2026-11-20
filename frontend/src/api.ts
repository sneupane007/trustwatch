import type {
  AnalysisResult,
  DetectorInfo,
  LiveStatus,
  NetworkInterface,
  SavedSession,
  SessionSummary,
} from "./types";

async function errorMessage(response: Response): Promise<string> {
  const body = await response.json().catch(() => null);
  if (body?.detail) return body.detail;
  if (response.status >= 500) {
    return "The backend didn't respond. Check that it is running on port 8000 and look at its terminal for errors.";
  }
  return `Request failed (${response.status})`;
}

async function getJson<T>(url: string, init?: RequestInit): Promise<T> {
  const response = await fetch(url, init);
  if (!response.ok) throw new Error(await errorMessage(response));
  return response.json();
}

function postJson<T>(url: string, body?: unknown): Promise<T> {
  return getJson<T>(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

export const fetchDetectors = () => getJson<DetectorInfo[]>("/api/detectors");

export function analyzeCapture(file: File): Promise<AnalysisResult> {
  const body = new FormData();
  body.append("file", file);
  return getJson<AnalysisResult>("/api/analyze", { method: "POST", body });
}

// Live mode
export const fetchInterfaces = () => getJson<NetworkInterface[]>("/api/interfaces");
export const fetchLiveStatus = () => getJson<LiveStatus>("/api/live/status");
export type LiveSource = { interface: string } | { replay: string; speed: number };
export const startLive = (source: LiveSource) => postJson<{ session_id: string }>("/api/live/start", source);
export const stopLive = () => postJson<{ session_id: string; packets: number; alerts: number }>("/api/live/stop");

export function liveSocketUrl(): string {
  const scheme = location.protocol === "https:" ? "wss" : "ws";
  return `${scheme}://${location.host}/api/live/ws`;
}

// Saved sessions
export const fetchSessions = () => getJson<SessionSummary[]>("/api/sessions");
export const fetchSession = (id: string) => getJson<SavedSession>(`/api/sessions/${encodeURIComponent(id)}`);
export const sessionPcapUrl = (id: string) => `/api/sessions/${encodeURIComponent(id)}/pcap`;
