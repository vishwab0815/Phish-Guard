import type { ComponentType } from "react";
import { AlertTriangle, CheckCircle, HelpCircle, Shield, ShieldAlert, XOctagon } from "lucide-react";
import { cn } from "../ui/utils";

/**
 * Single source of truth for threat-level presentation.
 * IMPORTANT: unknown/unrecognised levels map to a NEUTRAL "Unknown" state —
 * never to green "Safe". A wrong "safe" is the worst possible bug.
 */
export type ThreatLevel = "safe" | "low" | "medium" | "high" | "critical" | "unknown";

export type ScanKind = "url" | "email" | "message" | "file";

const KNOWN: ReadonlySet<string> = new Set(["safe", "low", "medium", "high", "critical"]);

export function normalizeThreatLevel(value: unknown): ThreatLevel {
  if (typeof value !== "string") return "unknown";
  const v = value.trim().toLowerCase();
  return KNOWN.has(v) ? (v as ThreatLevel) : "unknown";
}

/** HIGH or CRITICAL — the levels where we tell people to stop and report. */
export function isDangerous(level: ThreatLevel): boolean {
  return level === "high" || level === "critical";
}

interface ThreatMeta {
  label: string;
  /** Tailwind classes for a solid badge. */
  badgeClass: string;
  /** Text colour for headings/numbers. */
  textClass: string;
  /** Tinted panel (border + background) for verdict boxes. */
  panelClass: string;
  Icon: ComponentType<{ className?: string }>;
  rank: number;
}

export const THREAT_META: Record<ThreatLevel, ThreatMeta> = {
  critical: {
    label: "Critical",
    badgeClass: "bg-red-700 text-white border-red-900 dark:bg-red-700 dark:text-white",
    textClass: "text-red-700 dark:text-red-400",
    panelClass: "border-red-700 bg-red-100 dark:bg-red-950/50 dark:border-red-600",
    Icon: XOctagon,
    rank: 5,
  },
  high: {
    label: "High risk",
    badgeClass: "bg-red-600 text-white border-red-700 dark:bg-red-600",
    textClass: "text-red-600 dark:text-red-400",
    panelClass: "border-red-500 bg-red-50 dark:bg-red-950/30",
    Icon: ShieldAlert,
    rank: 4,
  },
  medium: {
    label: "Medium risk",
    badgeClass: "bg-orange-500 text-white border-orange-600",
    textClass: "text-orange-600 dark:text-orange-400",
    panelClass: "border-orange-500 bg-orange-50 dark:bg-orange-950/30",
    Icon: AlertTriangle,
    rank: 3,
  },
  low: {
    label: "Low risk",
    badgeClass: "bg-yellow-400 text-yellow-950 border-yellow-500",
    textClass: "text-yellow-700 dark:text-yellow-400",
    panelClass: "border-yellow-500 bg-yellow-50 dark:bg-yellow-950/30",
    Icon: Shield,
    rank: 2,
  },
  safe: {
    label: "No threats found",
    badgeClass: "bg-green-600 text-white border-green-700",
    textClass: "text-green-700 dark:text-green-400",
    panelClass: "border-green-600 bg-green-50 dark:bg-green-950/30",
    Icon: CheckCircle,
    rank: 1,
  },
  unknown: {
    label: "Unknown",
    badgeClass: "bg-muted text-muted-foreground border-border",
    textClass: "text-muted-foreground",
    panelClass: "border-border bg-muted/40",
    Icon: HelpCircle,
    rank: 0,
  },
};

export const THREAT_FILTER_OPTIONS: { value: ThreatLevel; label: string }[] = [
  { value: "critical", label: "Critical" },
  { value: "high", label: "High risk" },
  { value: "medium", label: "Medium risk" },
  { value: "low", label: "Low risk" },
  { value: "safe", label: "No threats found" },
  { value: "unknown", label: "Unknown" },
];

const NOUN: Record<ScanKind, string> = {
  url: "link",
  email: "email",
  message: "message",
  file: "file",
};

const ACTION: Record<ScanKind, string> = {
  url: "Don't open it",
  email: "Don't click its links, open attachments or reply",
  message: "Don't reply, click links or share any details",
  file: "Don't open or run it",
};

/** One plain-language sentence describing the verdict. */
export function verdictSentence(level: ThreatLevel, kind: ScanKind): string {
  const noun = NOUN[kind];
  switch (level) {
    case "critical":
      return `This ${noun} is almost certainly a scam or malicious. ${ACTION[kind]}.`;
    case "high":
      return `This ${noun} is very likely a scam. ${ACTION[kind]}.`;
    case "medium":
      return `This ${noun} looks suspicious. Don't act on it until you've checked it through an official channel.`;
    case "low":
      return `We found minor warning signs in this ${noun}. Be careful and verify it before you trust it.`;
    case "safe":
      return `We didn't find signs of a scam in this ${noun}. That isn't a guarantee — stay alert.`;
    default:
      return `We couldn't determine a risk level for this ${noun}. Treat it with caution.`;
  }
}

/** India-specific emergency steps, shown for HIGH/CRITICAL verdicts. */
export const INDIA_EMERGENCY_STEPS: string[] = [
  "If you already entered details or paid, call 1930 (National Cyber Crime Helpline) immediately and report at cybercrime.gov.in.",
  "Call your bank using the number on your card or the bank's official website to block the card/UPI and stop further transactions.",
  "Change the password of any account you entered on that page, and turn on two-factor authentication.",
];

export function ThreatBadge({ level, className }: { level: ThreatLevel; className?: string }) {
  const meta = THREAT_META[level];
  const Icon = meta.Icon;
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-xs font-semibold whitespace-nowrap",
        meta.badgeClass,
        className
      )}
    >
      <Icon className="w-3.5 h-3.5" aria-hidden="true" />
      {meta.label}
    </span>
  );
}

export function ThreatIcon({ level, className }: { level: ThreatLevel; className?: string }) {
  const meta = THREAT_META[level];
  const Icon = meta.Icon;
  return <Icon className={cn("w-5 h-5", meta.textClass, className)} aria-hidden="true" />;
}
