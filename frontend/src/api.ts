import type { AnalysisResult, DetectorInfo, LiveStatus, NetworkInterface } from "./types";

async function errorMessage(response: Response): Promise<string> {
  const body = await response.json().catch(() => null);
  if (body?.detail) return body.detail;
  if (response.status >= 500) {
    return "The backend didn't respond. Check that it is running on port 8000 and look at its terminal for errors.";
  }
  return `Request failed (${response.status})`;
}

export async function fetchDetectors(): Promise<DetectorInfo[]> {
  const response = await fetch("/api/detectors");
  if (!response.ok) throw new Error(await errorMessage(response));
  return response.json();
}

export async function analyzeCapture(file: File): Promise<AnalysisResult> {
  const body = new FormData();
  body.append("file", file);
  const response = await fetch("/api/analyze", { method: "POST", body });
  if (!response.ok) throw new Error(await errorMessage(response));
  return response.json();
}

export async function fetchInterfaces(): Promise<NetworkInterface[]> {
  const response = await fetch("/api/interfaces");
  if (!response.ok) throw new Error(await errorMessage(response));
  return response.json();
}

export async function fetchLiveStatus(): Promise<LiveStatus> {
  const response = await fetch("/api/live/status");
  if (!response.ok) throw new Error(await errorMessage(response));
  return response.json();
}

/** Capture on a network interface, or replay a capture from backend/samples/. */
export async function startLive(source: { interface: string } | { replay: string }): Promise<{ session_id: string }> {
  const response = await fetch("/api/live/start", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(source),
  });
  if (!response.ok) throw new Error(await errorMessage(response));
  return response.json();
}

export async function stopLive(): Promise<void> {
  const response = await fetch("/api/live/stop", { method: "POST" });
  if (!response.ok) throw new Error(await errorMessage(response));
}

export function openLiveSocket(): WebSocket {
  const scheme = location.protocol === "https:" ? "wss" : "ws";
  return new WebSocket(`${scheme}://${location.host}/api/live/ws`);
}
