/**
 * Defensive readers for the /api/stats payload, whose field names are still
 * evolving. Returns null when no candidate key holds a finite number, so the
 * UI can show "—" instead of a made-up zero.
 */
function readPath(obj: unknown, path: string): unknown {
  let cur: unknown = obj;
  for (const part of path.split(".")) {
    if (!cur || typeof cur !== "object") return undefined;
    cur = (cur as Record<string, unknown>)[part];
  }
  return cur;
}

export function pickNumber(obj: unknown, keys: string[]): number | null {
  for (const key of keys) {
    const v = readPath(obj, key);
    if (typeof v === "number" && Number.isFinite(v)) return v;
    if (typeof v === "string" && v.trim() !== "" && Number.isFinite(Number(v))) return Number(v);
  }
  return null;
}

export function formatCount(value: number | null): string {
  return value === null ? "—" : value.toLocaleString();
}

function sumOrNull(a: number | null, b: number | null): number | null {
  return a !== null && b !== null ? a + b : null;
}

/** Normalised view of the user's /api/stats payload. Missing values are null ("—"). */
export interface StatsSummary {
  total: number | null;
  scansToday: number | null;
  scansThisWeek: number | null;
  critical: number | null;
  /** HIGH + CRITICAL */
  dangerous: number | null;
  /** LOW + MEDIUM */
  suspicious: number | null;
  safe: number | null;
}

export function summarizeStats(stats: unknown): StatsSummary {
  const high = pickNumber(stats, ["by_threat_level.HIGH"]);
  const critical = pickNumber(stats, ["by_threat_level.CRITICAL", "critical_threats"]);
  const low = pickNumber(stats, ["by_threat_level.LOW"]);
  const medium = pickNumber(stats, ["by_threat_level.MEDIUM"]);
  return {
    total: pickNumber(stats, ["total_scans"]),
    scansToday: pickNumber(stats, ["scans_today"]),
    scansThisWeek: pickNumber(stats, ["scans_this_week"]),
    critical,
    dangerous: sumOrNull(high, critical) ?? pickNumber(stats, ["threats_detected"]),
    suspicious: sumOrNull(low, medium) ?? pickNumber(stats, ["suspicious_items"]),
    safe: pickNumber(stats, ["by_threat_level.SAFE", "safe_items"]),
  };
}
