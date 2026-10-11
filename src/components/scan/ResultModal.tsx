import { useState, type ComponentProps } from "react";
import { AnimatePresence, motion, useReducedMotion } from "framer-motion";
import { toast } from "sonner";
import {
  AlertTriangle,
  ClipboardCopy,
  ExternalLink,
  Info,
  ListChecks,
  Phone,
  RotateCcw,
  ScanSearch,
  Search,
  X,
} from "lucide-react";
import { Dialog, DialogContent, DialogDescription, DialogTitle } from "../ui/dialog";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "../ui/tabs";
import { Button } from "../ui/button";
import { cn } from "../ui/utils";
import { ScanProgress } from "./ScanProgress";
import { reportToText, type ScanReport } from "./report";
import {
  INDIA_EMERGENCY_STEPS,
  THREAT_META,
  ThreatBadge,
  isDangerous,
  verdictSentence,
  type ScanKind,
} from "./threatLevel";
import { KIND_META, formatDateTime, formatDuration } from "./kinds";
import type { ResultView } from "./useScanRunner";

interface ResultModalProps {
  open: boolean;
  view: ResultView | null;
  /** Close (aborts an in-flight scan). */
  onClose: () => void;
  onRetry: () => void;
  /** Close and send the user back to the scan form. */
  onScanAnother: () => void;
  onCloseAutoFocus?: ComponentProps<typeof DialogContent>["onCloseAutoFocus"];
}

const MODAL_TAB =
  "py-1.5 data-[state=active]:bg-background data-[state=active]:shadow-sm dark:data-[state=active]:bg-background dark:data-[state=active]:text-foreground";

const NOUN = { url: "link", email: "email", message: "message", file: "file" } as const;

export function ResultModal({ open, view, onClose, onRetry, onScanAnother, onCloseAutoFocus }: ResultModalProps) {
  const reduceMotion = useReducedMotion();
  const viewKey = view ? (view.status === "result" ? `result-${view.entry.id}` : view.status) : "none";

  return (
    <Dialog open={open} onOpenChange={(next) => !next && onClose()}>
      <DialogContent
        onCloseAutoFocus={onCloseAutoFocus}
        className={cn(
          "flex flex-col gap-0 overflow-hidden rounded-2xl border-border bg-card p-0 text-card-foreground shadow-2xl",
          "w-[calc(100vw-1rem)] max-w-none h-[calc(100dvh-1rem)]",
          "sm:h-auto sm:max-h-[90vh] sm:w-full sm:max-w-2xl"
        )}
      >
        <AnimatePresence mode="wait" initial={false}>
          <motion.div
            key={viewKey}
            className="flex min-h-0 flex-auto flex-col"
            initial={reduceMotion ? { opacity: 0 } : { opacity: 0, y: 8, scale: 0.99 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.2, ease: "easeOut" }}
          >
            {view?.status === "scanning" && (
              <ScanningView kind={view.kind} target={view.target} onCancel={onClose} />
            )}
            {view?.status === "error" && (
              <ErrorView
                message={view.message}
                target={view.target}
                retryable={view.retryable}
                onRetry={onRetry}
                onClose={onClose}
                onScanAnother={onScanAnother}
              />
            )}
            {view?.status === "result" && (
              <ReportView report={view.entry.report} onClose={onClose} onScanAnother={onScanAnother} />
            )}
            {!view && (
              <>
                <DialogTitle className="sr-only">Scan result</DialogTitle>
                <DialogDescription className="sr-only">No result to show.</DialogDescription>
              </>
            )}
          </motion.div>
        </AnimatePresence>
      </DialogContent>
    </Dialog>
  );
}

// ---------------------------------------------------------------------------

function TargetLine({ target, className }: { target: string; className?: string }) {
  return (
    <p
      className={cn("font-mono text-xs sm:text-sm text-muted-foreground break-all line-clamp-2", className)}
      title={target}
    >
      {target}
    </p>
  );
}

function ScanningView({ kind, target, onCancel }: { kind: ScanKind; target: string; onCancel: () => void }) {
  return (
    <>
      <div className="min-h-0 flex-auto overflow-y-auto px-5 pb-5 pt-10 sm:px-8">
        <DialogTitle className="sr-only">Scanning your {NOUN[kind]}</DialogTitle>
        <DialogDescription className="sr-only">
          PhishGuard is checking {target}. Close this window to cancel.
        </DialogDescription>
        <ScanProgress kind={kind} />
        <div className="mt-5 rounded-lg border border-border bg-muted/30 px-3 py-2">
          <p className="text-xs text-muted-foreground">Checking</p>
          <TargetLine target={target} className="text-foreground" />
        </div>
      </div>
      <div className="shrink-0 border-t border-border px-5 py-3 flex justify-end">
        <Button variant="outline" onClick={onCancel}>
          Cancel
        </Button>
      </div>
    </>
  );
}

function ErrorView({
  message,
  target,
  retryable,
  onRetry,
  onClose,
  onScanAnother,
}: {
  message: string;
  target: string;
  retryable: boolean;
  onRetry: () => void;
  onClose: () => void;
  onScanAnother: () => void;
}) {
  return (
    <>
      <div className="min-h-0 flex-auto overflow-y-auto px-5 pb-5 pt-10 sm:px-8">
        <div className="flex flex-col items-center gap-4 text-center">
          <span className="flex h-16 w-16 items-center justify-center rounded-full bg-red-100 dark:bg-red-950/60">
            <AlertTriangle className="h-8 w-8 text-red-600 dark:text-red-400" aria-hidden="true" />
          </span>
          <DialogTitle className="text-xl">The scan didn&apos;t finish</DialogTitle>
          <DialogDescription className="text-base text-foreground">{message}</DialogDescription>
          <p className="rounded-lg border border-orange-300 bg-orange-50 px-3 py-2 text-sm text-orange-900 dark:border-orange-800 dark:bg-orange-950/40 dark:text-orange-200">
            No verdict was produced, so don&apos;t treat this item as safe.
          </p>
          {target && <TargetLine target={target} className="max-w-full" />}
        </div>
      </div>
      <div className="shrink-0 border-t border-border px-5 py-3 flex flex-wrap justify-end gap-2">
        {retryable ? (
          <Button onClick={onRetry} className="text-white security-button">
            <RotateCcw className="h-4 w-4" aria-hidden="true" />
            Retry
          </Button>
        ) : (
          <Button onClick={onScanAnother} className="text-white security-button">
            <ScanSearch className="h-4 w-4" aria-hidden="true" />
            Edit and try again
          </Button>
        )}
        <Button variant="outline" onClick={onClose}>
          Close
        </Button>
      </div>
    </>
  );
}

// ---------------------------------------------------------------------------

function RiskGauge({ report }: { report: ScanReport }) {
  const reduceMotion = useReducedMotion();
  const meta = THREAT_META[report.level];
  const r = 52;
  const c = 2 * Math.PI * r;
  const score = report.riskScore === null ? null : Math.max(0, Math.min(100, report.riskScore));
  const offset = score === null ? c : c * (1 - score / 100);

  return (
    <div
      className="relative h-24 w-24 shrink-0 sm:h-28 sm:w-28"
      role="img"
      aria-label={score === null ? "Risk score not available" : `Risk score ${Math.round(score)} out of 100`}
    >
      <svg viewBox="0 0 120 120" className="h-full w-full -rotate-90" aria-hidden="true">
        <circle cx="60" cy="60" r={r} fill="none" strokeWidth="10" className="stroke-muted" />
        <motion.circle
          cx="60"
          cy="60"
          r={r}
          fill="none"
          strokeWidth="10"
          strokeLinecap="round"
          strokeDasharray={c}
          className={meta.strokeClass}
          initial={reduceMotion ? false : { strokeDashoffset: c }}
          animate={{ strokeDashoffset: offset }}
          transition={{ duration: 0.9, ease: "easeOut" }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center" aria-hidden="true">
        <span className={cn("text-2xl font-bold leading-none sm:text-3xl", meta.textClass)}>
          {score === null ? "—" : Math.round(score)}
        </span>
        <span className="mt-1 text-[10px] uppercase tracking-wide text-muted-foreground">risk / 100</span>
      </div>
    </div>
  );
}

function ReportView({
  report,
  onClose,
  onScanAnother,
}: {
  report: ScanReport;
  onClose: () => void;
  onScanAnother: () => void;
}) {
  const meta = THREAT_META[report.level];
  const verdict = verdictSentence(report.level, report.kind);
  const KindIcon = KIND_META[report.kind].Icon;

  const copyReport = async () => {
    try {
      await navigator.clipboard.writeText(reportToText(report, verdict));
      toast.success("Report copied to clipboard");
    } catch {
      toast.error("Couldn't copy — your browser blocked clipboard access");
    }
  };

  return (
    <>
      {/* HERO */}
      <section className={cn("shrink-0 border-b-2 px-5 pb-4 pt-5 pr-12 sm:px-6 sm:pt-6", meta.panelClass)}>
        <div className="flex items-center gap-4 sm:gap-5">
          <RiskGauge report={report} />
          <div className="min-w-0 flex-1 space-y-1.5">
            <div className="flex flex-wrap items-center gap-2">
              <ThreatBadge level={report.level} />
              <span className="inline-flex items-center gap-1 text-xs text-muted-foreground">
                <KindIcon className="h-3.5 w-3.5" aria-hidden="true" />
                {KIND_META[report.kind].label}
              </span>
              {report.confidence !== null && (
                <span className="text-xs text-muted-foreground">· {Math.round(report.confidence)}% confidence</span>
              )}
            </div>
            <DialogTitle className={cn("text-2xl leading-tight sm:text-3xl", meta.textClass)}>{meta.label}</DialogTitle>
            <TargetLine target={report.target} className="hidden sm:block" />
          </div>
        </div>
        <DialogDescription className="mt-3 text-sm font-medium text-foreground sm:text-base">{verdict}</DialogDescription>
        <TargetLine target={report.target} className="mt-1 sm:hidden" />
      </section>

      {/* TABS */}
      <Tabs defaultValue="todo" className="flex min-h-0 flex-auto flex-col gap-0">
        <TabsList className="mx-4 mt-3 grid h-auto w-auto shrink-0 grid-cols-3 sm:mx-6">
          <TabsTrigger value="todo" className={MODAL_TAB}>
            <ListChecks className="h-4 w-4" aria-hidden="true" />
            What to do
          </TabsTrigger>
          <TabsTrigger value="why" className={MODAL_TAB}>
            <Search className="h-4 w-4" aria-hidden="true" />
            Why
          </TabsTrigger>
          <TabsTrigger value="details" className={MODAL_TAB}>
            <Info className="h-4 w-4" aria-hidden="true" />
            Details
          </TabsTrigger>
        </TabsList>

        <TabsContent value="todo" className="min-h-0 flex-auto overflow-y-auto px-5 py-4 sm:px-6">
          <WhatToDo report={report} />
        </TabsContent>
        <TabsContent value="why" className="min-h-0 flex-auto overflow-y-auto px-5 py-4 sm:px-6">
          <Why report={report} />
        </TabsContent>
        <TabsContent value="details" className="min-h-0 flex-auto overflow-y-auto px-5 py-4 sm:px-6">
          <Details report={report} />
        </TabsContent>
      </Tabs>

      {/* FOOTER */}
      <div className="grid shrink-0 grid-cols-3 gap-2 border-t border-border px-4 py-3 sm:flex sm:justify-end sm:px-6">
        <Button variant="outline" onClick={copyReport} className="px-2 sm:px-4">
          <ClipboardCopy className="h-4 w-4" aria-hidden="true" />
          <span className="sm:hidden">Copy</span>
          <span className="hidden sm:inline">Copy report</span>
        </Button>
        <Button onClick={onScanAnother} className="px-2 text-white security-button sm:px-4">
          <ScanSearch className="h-4 w-4" aria-hidden="true" />
          <span className="sm:hidden">New scan</span>
          <span className="hidden sm:inline">Scan something else</span>
        </Button>
        <Button variant="ghost" onClick={onClose} className="px-2 sm:px-4">
          <X className="h-4 w-4 sm:hidden" aria-hidden="true" />
          Close
        </Button>
      </div>
    </>
  );
}

// ---------------------------------------------------------------------------

function WhatToDo({ report }: { report: ScanReport }) {
  const [done, setDone] = useState<ReadonlySet<number>>(() => new Set());
  const toggle = (i: number) =>
    setDone((prev) => {
      const next = new Set(prev);
      if (next.has(i)) next.delete(i);
      else next.add(i);
      return next;
    });

  return (
    <div className="space-y-5">
      {isDangerous(report.level) && (
        <section className="space-y-3 rounded-xl border-2 border-red-600 bg-red-50 p-4 dark:border-red-700 dark:bg-red-950/40">
          <h3 className="flex items-center gap-2 font-semibold text-red-700 dark:text-red-300">
            <Phone className="h-4 w-4" aria-hidden="true" />
            Already clicked, entered details or paid?
          </h3>
          <div className="flex flex-wrap gap-2">
            <a
              href="tel:1930"
              className="inline-flex items-center gap-2 rounded-lg bg-red-600 px-3 py-2 text-sm font-semibold text-white hover:bg-red-700 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-red-400"
            >
              <Phone className="h-4 w-4" aria-hidden="true" />
              Call 1930
            </a>
            <a
              href="https://cybercrime.gov.in"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-2 rounded-lg border border-red-600 bg-white px-3 py-2 text-sm font-semibold text-red-700 hover:bg-red-100 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-red-400 dark:bg-transparent dark:text-red-300 dark:hover:bg-red-950"
            >
              cybercrime.gov.in
              <ExternalLink className="h-3.5 w-3.5" aria-hidden="true" />
              <span className="sr-only">(opens in a new tab)</span>
            </a>
          </div>
          <ol className="list-decimal space-y-1 pl-5 text-sm text-foreground">
            {INDIA_EMERGENCY_STEPS.map((step) => (
              <li key={step}>{step}</li>
            ))}
          </ol>
        </section>
      )}

      <section className="space-y-2">
        <h3 className="text-sm font-semibold">Your checklist</h3>
        {report.recommendations.length > 0 ? (
          <ul className="space-y-2">
            {report.recommendations.map((rec, i) => (
              <li key={`${i}-${rec}`}>
                <label className="flex cursor-pointer items-start gap-3 rounded-lg border border-border bg-muted/30 px-3 py-2.5 text-sm transition-colors hover:bg-muted/60">
                  <input
                    type="checkbox"
                    checked={done.has(i)}
                    onChange={() => toggle(i)}
                    className="mt-0.5 h-4 w-4 shrink-0 accent-blue-600"
                  />
                  <span className={cn("break-words", done.has(i) && "text-muted-foreground line-through")}>{rec}</span>
                </label>
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-sm text-muted-foreground">The scanner didn&apos;t return specific recommendations.</p>
        )}
      </section>

      {report.notes.length > 0 && (
        <section className="space-y-2">
          <h3 className="text-sm font-semibold text-muted-foreground">Good to know</h3>
          <ul className="list-disc space-y-1 pl-5 text-sm text-muted-foreground">
            {report.notes.map((note, i) => (
              <li key={`${i}-${note}`}>{note}</li>
            ))}
          </ul>
        </section>
      )}
    </div>
  );
}

function Why({ report }: { report: ScanReport }) {
  const meta = THREAT_META[report.level];
  const positive = report.riskBreakdown.map((b) => Math.max(0, b.riskContribution));
  const total = positive.reduce((a, b) => a + b, 0);

  return (
    <div className="space-y-6">
      <section className="space-y-2">
        <h3 className="text-sm font-semibold">
          What the scanner found{" "}
          <span className="font-normal text-muted-foreground">({report.indicators.length})</span>
        </h3>
        {report.indicators.length > 0 ? (
          <ul className="space-y-2">
            {report.indicators.map((indicator, i) => (
              <li
                key={`${i}-${indicator}`}
                className="flex items-start gap-3 rounded-lg border border-border bg-muted/30 px-3 py-2 text-sm"
              >
                <span className={cn("mt-1.5 h-2 w-2 shrink-0 rounded-full", meta.fillClass)} aria-hidden="true" />
                <span className="min-w-0 break-words">{indicator}</span>
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-sm text-muted-foreground">No warning signs were reported.</p>
        )}
      </section>

      {report.riskBreakdown.length > 0 && (
        <section className="space-y-3">
          <h3 className="text-sm font-semibold">How the risk score was built</h3>
          <ul className="space-y-3">
            {report.riskBreakdown.map((item, i) => {
              const share = total > 0 ? Math.min(100, Math.round((positive[i] / total) * 100)) : 0;
              const sign = item.riskContribution >= 0 ? "+" : "−";
              return (
                <li key={`${i}-${item.layer}`} className="space-y-1.5">
                  <div className="flex items-baseline justify-between gap-3 text-sm">
                    <span className="min-w-0 font-medium break-words">{item.layer}</span>
                    <span className="shrink-0 tabular-nums text-muted-foreground">
                      {sign}
                      {Math.abs(Math.round(item.riskContribution))} pts
                    </span>
                  </div>
                  <div
                    className="h-2 overflow-hidden rounded-full bg-muted"
                    role="img"
                    aria-label={`${share}% of the total risk`}
                  >
                    <div
                      className="h-full rounded-full bg-gradient-to-r from-blue-500 to-purple-500"
                      style={{ width: `${share}%` }}
                    />
                  </div>
                  {item.details && <p className="text-xs text-muted-foreground break-words">{item.details}</p>}
                </li>
              );
            })}
          </ul>
        </section>
      )}
    </div>
  );
}

function Details({ report }: { report: ScanReport }) {
  const rows: { label: string; value: string }[] = [
    { label: "Scan type", value: KIND_META[report.kind].label },
    { label: "Scanned at", value: formatDateTime(report.scannedAt) },
    { label: "Processing time", value: report.durationMs !== null ? formatDuration(report.durationMs) : "Not available" },
    {
      label: "Confidence",
      value: report.confidence !== null ? `${Math.round(report.confidence)}%` : "Not available",
    },
    ...report.details,
    { label: "Engine version", value: report.modelVersion ?? "Not available" },
  ];

  return (
    <div className="space-y-6">
      <section className="space-y-2">
        <h3 className="text-sm font-semibold">Scanned</h3>
        <p className="rounded-lg border border-border bg-muted/30 px-3 py-2 font-mono text-xs break-all">{report.target}</p>
      </section>

      <dl className="grid grid-cols-1 gap-2 sm:grid-cols-2">
        {rows.map((d, i) => (
          <div key={`${i}-${d.label}`} className="rounded-lg border border-border bg-muted/30 px-3 py-2">
            <dt className="text-xs text-muted-foreground">{d.label}</dt>
            <dd className="font-medium break-words">{d.value}</dd>
          </div>
        ))}
      </dl>

      {report.layers.length > 0 && (
        <section className="space-y-2">
          <h3 className="text-sm font-semibold">Checks</h3>
          <ul className="flex flex-wrap gap-2">
            {report.layers.map((layer) => {
              const ran = layer.status === "completed";
              return (
                <li
                  key={layer.name}
                  className={cn(
                    "rounded-full border px-2.5 py-1 text-xs",
                    ran
                      ? "border-blue-500/40 bg-blue-50 text-blue-700 dark:bg-blue-950/40 dark:text-blue-300"
                      : "border-border text-muted-foreground"
                  )}
                >
                  {layer.name}: {ran ? "ran" : layer.status === "skipped" ? "skipped" : layer.status}
                </li>
              );
            })}
          </ul>
        </section>
      )}
    </div>
  );
}
