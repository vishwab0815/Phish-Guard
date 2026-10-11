/**
 * Browser-local scan history (demo mode — there is no server-side history).
 *
 * - Stores the last MAX_ENTRIES normalised ScanReports in localStorage.
 * - Every storage access is wrapped in try/catch: private mode, blocked or full
 *   storage silently falls back to an in-memory list for this tab.
 * - Exposes a tiny external store so React components update live via
 *   `useLocalHistory()` (useSyncExternalStore; the server snapshot is always []).
 *
 * Only ScanReport data is stored (target strings, verdicts, findings) — never
 * file contents or full raw emails.
 */
import { useSyncExternalStore } from "react";
import type { ScanReport } from "@/components/scan/report";
import { normalizeThreatLevel, type ScanKind } from "@/components/scan/threatLevel";

export const HISTORY_STORAGE_KEY = "phishguard.history.v1";
export const MAX_ENTRIES = 50;
const MAX_TARGET_CHARS = 2048;

export interface HistoryEntry {
  id: string;
  /** ISO timestamp of when the result was saved in this browser. */
  savedAt: string;
  report: ScanReport;
}

const EMPTY: readonly HistoryEntry[] = Object.freeze([]);
const KINDS: ReadonlySet<string> = new Set<ScanKind>(["url", "email", "message", "file"]);

let cache: readonly HistoryEntry[] | null = null;
const listeners = new Set<() => void>();

// ---------- validation (data in storage is untrusted) ----------

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

function str(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}

function num(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function strings(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === "string") : [];
}

function reviveReport(raw: unknown): ScanReport | null {
  if (!isRecord(raw)) return null;
  const kind = str(raw.kind);
  if (!kind || !KINDS.has(kind)) return null;
  const target = str(raw.target);
  if (target === null) return null;

  const riskBreakdown = Array.isArray(raw.riskBreakdown)
    ? raw.riskBreakdown.flatMap((b) => {
        if (!isRecord(b) || typeof b.layer !== "string") return [];
        const contribution = num(b.riskContribution);
        if (contribution === null) return [];
        return [
          {
            layer: b.layer,
            riskContribution: contribution,
            weight: num(b.weight) ?? 0,
            details: str(b.details) ?? "",
          },
        ];
      })
    : [];

  const pairs = <K extends string>(value: unknown, a: K, b: K): Record<K, string>[] =>
    Array.isArray(value)
      ? value.flatMap((item) =>
          isRecord(item) && typeof item[a] === "string" && typeof item[b] === "string"
            ? [{ [a]: item[a], [b]: item[b] } as Record<K, string>]
            : []
        )
      : [];

  return {
    kind: kind as ScanKind,
    target: target.slice(0, MAX_TARGET_CHARS),
    level: normalizeThreatLevel(raw.level),
    riskScore: num(raw.riskScore),
    confidence: num(raw.confidence),
    indicators: strings(raw.indicators),
    recommendations: strings(raw.recommendations),
    notes: strings(raw.notes),
    riskBreakdown,
    layers: pairs(raw.layers, "name", "status"),
    durationMs: num(raw.durationMs),
    modelVersion: str(raw.modelVersion),
    scannedAt: str(raw.scannedAt),
    details: pairs(raw.details, "label", "value"),
  };
}

function reviveEntries(raw: unknown): HistoryEntry[] {
  if (!Array.isArray(raw)) return [];
  const out: HistoryEntry[] = [];
  const seen = new Set<string>();
  for (const item of raw) {
    if (!isRecord(item)) continue;
    const id = str(item.id);
    const savedAt = str(item.savedAt);
    const report = reviveReport(item.report);
    if (!id || !savedAt || !report || seen.has(id)) continue;
    seen.add(id);
    out.push({ id, savedAt, report });
    if (out.length >= MAX_ENTRIES) break;
  }
  return out;
}

// ---------- storage (every access guarded) ----------

function readStorage(): HistoryEntry[] {
  try {
    const raw = window.localStorage.getItem(HISTORY_STORAGE_KEY);
    return raw ? reviveEntries(JSON.parse(raw)) : [];
  } catch {
    return [];
  }
}

function writeStorage(entries: readonly HistoryEntry[]): void {
  try {
    if (entries.length === 0) window.localStorage.removeItem(HISTORY_STORAGE_KEY);
    else window.localStorage.setItem(HISTORY_STORAGE_KEY, JSON.stringify(entries));
  } catch {
    // Blocked or full storage: keep the in-memory copy for this tab.
  }
}

function load(): readonly HistoryEntry[] {
  if (typeof window === "undefined") return EMPTY;
  if (cache === null) cache = readStorage();
  return cache;
}

function commit(next: readonly HistoryEntry[]): void {
  cache = next;
  writeStorage(next);
  listeners.forEach((listener) => listener());
}

function onStorage(event: StorageEvent): void {
  if (event.key !== null && event.key !== HISTORY_STORAGE_KEY) return;
  cache = readStorage();
  listeners.forEach((listener) => listener());
}

function newId(): string {
  try {
    if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") return crypto.randomUUID();
  } catch {
    // fall through
  }
  return `h${Date.now().toString(36)}${Math.random().toString(36).slice(2, 10)}`;
}

// ---------- public API ----------

export const localHistory = {
  /** Newest first. Referentially stable until the next change. */
  list(): readonly HistoryEntry[] {
    return load();
  },

  add(report: ScanReport): HistoryEntry {
    const entry: HistoryEntry = {
      id: newId(),
      savedAt: new Date().toISOString(),
      report: { ...report, target: report.target.slice(0, MAX_TARGET_CHARS) },
    };
    commit([entry, ...load()].slice(0, MAX_ENTRIES));
    return entry;
  },

  remove(id: string): void {
    const current = load();
    const next = current.filter((e) => e.id !== id);
    if (next.length !== current.length) commit(next);
  },

  /** Put back a previously removed entry (e.g. "Undo"), keeping newest-first order. */
  restore(entry: HistoryEntry): void {
    const current = load();
    if (current.some((e) => e.id === entry.id)) return;
    const next = [...current, entry].sort((a, b) => b.savedAt.localeCompare(a.savedAt)).slice(0, MAX_ENTRIES);
    commit(next);
  },

  clear(): void {
    commit([]);
  },

  get(id: string): HistoryEntry | undefined {
    return load().find((e) => e.id === id);
  },

  subscribe(listener: () => void): () => void {
    listeners.add(listener);
    if (listeners.size === 1 && typeof window !== "undefined") {
      window.addEventListener("storage", onStorage);
    }
    return () => {
      listeners.delete(listener);
      if (listeners.size === 0 && typeof window !== "undefined") {
        window.removeEventListener("storage", onStorage);
      }
    };
  },
};

const getServerSnapshot = (): readonly HistoryEntry[] => EMPTY;

/** Live list of local history entries (newest first). Always [] during SSR/hydration. */
export function useLocalHistory(): readonly HistoryEntry[] {
  return useSyncExternalStore(localHistory.subscribe, localHistory.list, getServerSnapshot);
}
