const number = new Intl.NumberFormat();
const compactNumber = new Intl.NumberFormat(undefined, { notation: "compact" });

export const formatCount = (n: number) => number.format(n);
export const formatCompact = (n: number) => compactNumber.format(n);

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 ** 2) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 ** 2).toFixed(1)} MB`;
}

export function formatDuration(seconds: number): string {
  if (seconds < 60) return `${seconds.toFixed(1)} s`;
  const m = Math.floor(seconds / 60);
  const s = Math.round(seconds % 60);
  return `${m} min ${s} s`;
}

/** Capture timestamp (seconds since the epoch) as local wall-clock time. */
export function formatClock(epochSeconds: number): string {
  return new Date(epochSeconds * 1000).toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

export function formatDate(epochSeconds: number): string {
  return new Date(epochSeconds * 1000).toLocaleDateString([], {
    month: "short",
    day: "numeric",
    year: "numeric",
  });
}
