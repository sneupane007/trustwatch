import type { AnalysisResult, DetectorInfo } from "./types";

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
