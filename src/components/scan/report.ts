import type { AnalysisResponse, RiskBreakdownItem } from "@/utils/BackendService";
import { normalizeThreatLevel, type ScanKind, type ThreatLevel, THREAT_META } from "./threatLevel";

/** Normalised scan result used by the UI. Only contains data the backend actually returned. */
export interface ScanReport {
  kind: ScanKind;
  /** What the user scanned, for display. */
  target: string;
  level: ThreatLevel;
  riskScore: number | null;
  confidence: number | null;
  indicators: string[];
  recommendations: string[];
  /** Informational notes from the scanner (e.g. what couldn't be checked) — not threat findings. */
  notes: string[];
  riskBreakdown: RiskBreakdownItem[];
  layers: { name: string; status: string }[];
  durationMs: number | null;
  modelVersion: string | null;
  scannedAt: string | null;
  /** false when the backend said the result was not saved to history; null if unknown. */
  saved: boolean | null;
  /** Extra real fields returned by the backend (e.g. SPF/DKIM results, file info). */
  details: { label: string; value: string }[];
}

const LAYER_LABELS: Record<string, string> = {
  static_analysis: "Static analysis",
  domain_intelligence: "Domain intelligence",
  ssl_validation: "SSL/TLS certificate",
  ip_intelligence: "IP intelligence",
  external_scans: "External reputation services",
  document_analysis: "Document analysis",
  script_analysis: "Script analysis",
  virus_total: "VirusTotal",
};

function num(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function strArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === "string" && v.trim() !== "") : [];
}

function humanizeKey(key: string): string {
  const s = key.replace(/_/g, " ");
  return s.charAt(0).toUpperCase() + s.slice(1);
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function displayValue(value: unknown): string | null {
  if (value === null || value === undefined || value === "") return null;
  if (typeof value === "boolean") return value ? "Yes" : "No";
  if (typeof value === "number") return Number.isFinite(value) ? String(value) : null;
  if (typeof value === "string") return value;
  return null;
}

export function normalizeAnalysis(kind: ScanKind, response: AnalysisResponse, target: string): ScanReport {
  const analysis = response.analysis ?? ({} as AnalysisResponse["analysis"]);
  const result = analysis.result ?? {};

  const breakdownRaw = result.riskBreakdown ?? result.risk_breakdown;
  const riskBreakdown = Array.isArray(breakdownRaw)
    ? breakdownRaw.filter(
        (b): b is RiskBreakdownItem =>
          !!b && typeof b.layer === "string" && typeof b.riskContribution === "number"
      )
    : [];

  const layersRaw = (result.layers ?? analysis.layers) as Record<string, unknown> | undefined;
  const layers =
    layersRaw && typeof layersRaw === "object"
      ? Object.entries(layersRaw)
          .filter(([, v]) => typeof v === "string")
          .map(([k, v]) => ({ name: LAYER_LABELS[k] ?? humanizeKey(k), status: v as string }))
      : [];

  const details: { label: string; value: string }[] = [];

  // URL: domain age only if the backend actually returned a number.
  if (kind === "url") {
    const age = num(result.domain_age_days) ?? num(result.domain_age);
    details.push({ label: "Domain age", value: age !== null ? `${age} days` : "Unknown" });
  }

  // Email-specific fields (only if present).
  const emailFields: [string, string][] = [
    ["spf_result", "SPF check"],
    ["dkim_result", "DKIM check"],
    ["dmarc_result", "DMARC check"],
    ["is_spoofed", "Sender looks spoofed"],
    ["suspicious_links", "Contains suspicious links"],
    ["suspicious_attachments", "Mentions suspicious attachments"],
  ];
  for (const [key, label] of emailFields) {
    const v = displayValue(result[key]);
    if (v !== null) details.push({ label, value: v });
  }

  // File-specific fields.
  if (analysis.file) {
    if (analysis.file.name) details.push({ label: "File name", value: analysis.file.name });
    if (typeof analysis.file.size === "number") details.push({ label: "File size", value: formatBytes(analysis.file.size) });
    if (analysis.file.type) details.push({ label: "Detected file type", value: analysis.file.type });
  }
  if (analysis.summary && typeof analysis.summary === "object") {
    for (const [key, value] of Object.entries(analysis.summary)) {
      const v = displayValue(value);
      if (v !== null) details.push({ label: humanizeKey(key), value: v });
    }
  }

  return {
    kind,
    target,
    level: normalizeThreatLevel(result.threat_level),
    riskScore: num(result.risk_score),
    confidence: num(result.confidence),
    indicators: strArray(result.indicators),
    recommendations: strArray(result.recommendations),
    notes: strArray(result.notes),
    riskBreakdown,
    layers,
    durationMs: num(result.scan_duration_ms) ?? num(analysis.scan_duration_ms),
    modelVersion: typeof analysis.model_version === "string" ? analysis.model_version : null,
    scannedAt: typeof analysis.timestamp === "string" ? analysis.timestamp : null,
    saved: typeof analysis.saved === "boolean" ? analysis.saved : null,
    details,
  };
}

/** Plain-text version of the report for "Copy report". */
export function reportToText(report: ScanReport, verdict: string): string {
  const lines: string[] = [
    "PhishGuard scan report",
    `Scanned: ${report.target}`,
    `Type: ${report.kind.toUpperCase()}`,
    `Verdict: ${THREAT_META[report.level].label}`,
    verdict,
    `Risk score: ${report.riskScore ?? "Not available"}${report.riskScore !== null ? "/100" : ""}`,
    `Confidence: ${report.confidence !== null ? `${report.confidence}%` : "Not available"}`,
  ];
  if (report.scannedAt) lines.push(`Scanned at: ${new Date(report.scannedAt).toLocaleString()}`);
  if (report.recommendations.length) {
    lines.push("", "What to do:");
    report.recommendations.forEach((r) => lines.push(`- ${r}`));
  }
  if (report.indicators.length) {
    lines.push("", "Findings:");
    report.indicators.forEach((i) => lines.push(`- ${i}`));
  }
  return lines.join("\n");
}
