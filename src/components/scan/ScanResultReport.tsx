import { useId, useState } from "react";
import { Card, CardContent } from "../ui/card";
import { Button } from "../ui/button";
import { ChevronDown, ClipboardCopy, Info, ListChecks, Phone, RotateCcw } from "lucide-react";
import { toast } from "sonner";
import {
  INDIA_EMERGENCY_STEPS,
  THREAT_META,
  ThreatBadge,
  ThreatIcon,
  isDangerous,
  verdictSentence,
} from "./threatLevel";
import { reportToText, type ScanReport } from "./report";

interface ScanResultReportProps {
  report: ScanReport;
  onReset: () => void;
}

function formatDuration(ms: number) {
  return ms < 1000 ? `${Math.round(ms)} ms` : `${(ms / 1000).toFixed(1)} s`;
}

export function ScanResultReport({ report, onReset }: ScanResultReportProps) {
  const [showDetails, setShowDetails] = useState(false);
  const detailsId = useId();
  const meta = THREAT_META[report.level];
  const verdict = verdictSentence(report.level, report.kind);
  const dangerous = isDangerous(report.level);

  const copyReport = async () => {
    try {
      await navigator.clipboard.writeText(reportToText(report, verdict));
      toast.success("Report copied to clipboard");
    } catch {
      toast.error("Couldn't copy — your browser blocked clipboard access");
    }
  };

  const breakdownTotal = report.riskScore ?? 0;

  return (
    <Card className="phish-card" aria-labelledby={`${detailsId}-verdict`}>
      <CardContent className="pt-6 space-y-6">
        {/* VERDICT */}
        <section className={`rounded-xl border-2 p-5 ${meta.panelClass}`} aria-live="polite">
          <div className="flex items-start gap-4">
            <ThreatIcon level={report.level} className="w-10 h-10 shrink-0" />
            <div className="space-y-2 min-w-0">
              <div className="flex flex-wrap items-center gap-2">
                <h3 id={`${detailsId}-verdict`} className="text-sm font-medium text-muted-foreground">
                  Verdict
                </h3>
                <ThreatBadge level={report.level} className="text-sm px-3 py-1" />
              </div>
              <p className={`text-xl font-bold leading-snug ${meta.textClass}`}>{verdict}</p>
              <p className="text-sm text-muted-foreground break-all">
                Scanned: <span className="font-mono">{report.target}</span>
              </p>
              <p className="text-sm text-muted-foreground">
                Risk score:{" "}
                <span className="font-semibold text-foreground">
                  {report.riskScore !== null ? `${report.riskScore}/100` : "Not available"}
                </span>
                {" · "}
                Confidence:{" "}
                <span className="font-semibold text-foreground">
                  {report.confidence !== null ? `${report.confidence}%` : "Not available"}
                </span>
              </p>
            </div>
          </div>
        </section>

        {report.saved === false && (
          <p className="text-sm text-muted-foreground">
            Note: this result couldn&apos;t be saved to your history. Use &quot;Copy report&quot; if you want to keep it.
          </p>
        )}

        {/* EMERGENCY STEPS (India) */}
        {dangerous && (
          <section className="rounded-xl border-2 border-red-600 bg-red-50 dark:bg-red-950/40 p-4 space-y-2">
            <h3 className="font-semibold flex items-center gap-2 text-red-700 dark:text-red-300">
              <Phone className="w-4 h-4" aria-hidden="true" />
              Already clicked, entered details or paid?
            </h3>
            <ol className="list-decimal pl-5 space-y-1 text-sm">
              {INDIA_EMERGENCY_STEPS.map((step) => (
                <li key={step}>{step}</li>
              ))}
            </ol>
          </section>
        )}

        {/* WHAT TO DO NOW */}
        <section className="space-y-2">
          <h3 className="font-semibold flex items-center gap-2">
            <ListChecks className="w-4 h-4" aria-hidden="true" />
            What to do now
          </h3>
          {report.recommendations.length > 0 ? (
            <ul className="list-disc pl-5 space-y-1 text-sm">
              {report.recommendations.map((rec, i) => (
                <li key={`${i}-${rec}`}>{rec}</li>
              ))}
            </ul>
          ) : (
            <p className="text-sm text-muted-foreground">The scanner didn&apos;t return specific recommendations.</p>
          )}
        </section>

        {report.notes.length > 0 && (
          <section className="space-y-1">
            <h3 className="text-sm font-semibold text-muted-foreground">Good to know</h3>
            <ul className="list-disc pl-5 space-y-1 text-sm text-muted-foreground">
              {report.notes.map((note) => (
                <li key={note}>{note}</li>
              ))}
            </ul>
          </section>
        )}

        <div className="flex flex-wrap gap-3">
          <Button variant="outline" onClick={copyReport} className="flex items-center gap-2">
            <ClipboardCopy className="w-4 h-4" aria-hidden="true" />
            Copy report
          </Button>
          <Button variant="outline" onClick={onReset} className="flex items-center gap-2">
            <RotateCcw className="w-4 h-4" aria-hidden="true" />
            Check something else
          </Button>
        </div>

        {/* TECHNICAL DETAILS (collapsible) */}
        <section className="border-t border-border/50 pt-4">
          <button
            type="button"
            aria-expanded={showDetails}
            aria-controls={`${detailsId}-details`}
            onClick={() => setShowDetails((v) => !v)}
            className="flex w-full items-center justify-between rounded-md px-1 py-2 text-left font-semibold hover:bg-muted/50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
          >
            <span className="flex items-center gap-2">
              <Info className="w-4 h-4" aria-hidden="true" />
              Technical details ({report.indicators.length} finding{report.indicators.length === 1 ? "" : "s"})
            </span>
            <ChevronDown
              className={`w-4 h-4 transition-transform ${showDetails ? "rotate-180" : ""}`}
              aria-hidden="true"
            />
          </button>

          {showDetails && (
            <div id={`${detailsId}-details`} className="mt-4 space-y-6">
              <div className="space-y-2">
                <h4 className="text-sm font-semibold">Findings reported by the scanner</h4>
                {report.indicators.length > 0 ? (
                  <ul className="space-y-2">
                    {report.indicators.map((indicator, i) => (
                      <li
                        key={`${i}-${indicator}`}
                        className="rounded-md border border-border/60 bg-muted/30 px-3 py-2 text-sm break-words"
                      >
                        {indicator}
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="text-sm text-muted-foreground">No findings were reported.</p>
                )}
              </div>

              {report.riskBreakdown.length > 0 && (
                <div className="space-y-3">
                  <h4 className="text-sm font-semibold">How the risk score was built</h4>
                  {report.riskBreakdown.map((item) => {
                    const share =
                      breakdownTotal > 0 ? Math.min(100, Math.round((item.riskContribution / breakdownTotal) * 100)) : 0;
                    return (
                      <div key={item.layer} className="rounded-lg border border-border/60 p-3 space-y-2">
                        <div className="flex items-center justify-between gap-3 text-sm">
                          <span className="font-medium">{item.layer}</span>
                          <span className="text-muted-foreground">
                            +{item.riskContribution} points{typeof item.weight === "number" ? ` · weight ${item.weight}%` : ""}
                          </span>
                        </div>
                        <div
                          className="h-2 rounded-full bg-muted overflow-hidden"
                          role="img"
                          aria-label={`${share}% of the total risk score`}
                        >
                          <div className="h-full rounded-full bg-blue-500" style={{ width: `${share}%` }} />
                        </div>
                        {item.details && <p className="text-xs text-muted-foreground break-words">{item.details}</p>}
                      </div>
                    );
                  })}
                </div>
              )}

              {report.details.length > 0 && (
                <div className="space-y-2">
                  <h4 className="text-sm font-semibold">Details</h4>
                  <dl className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    {report.details.map((d) => (
                      <div key={d.label} className="phish-card p-3">
                        <dt className="text-xs text-muted-foreground">{d.label}</dt>
                        <dd className="font-medium break-words">{d.value}</dd>
                      </div>
                    ))}
                  </dl>
                </div>
              )}

              <div className="space-y-2">
                <h4 className="text-sm font-semibold">Scan information</h4>
                <dl className="grid grid-cols-2 md:grid-cols-4 gap-3">
                  <div className="phish-card p-3">
                    <dt className="text-xs text-muted-foreground">Scan type</dt>
                    <dd className="font-medium">{report.kind.toUpperCase()}</dd>
                  </div>
                  <div className="phish-card p-3">
                    <dt className="text-xs text-muted-foreground">Processing time</dt>
                    <dd className="font-medium">
                      {report.durationMs !== null ? formatDuration(report.durationMs) : "Not available"}
                    </dd>
                  </div>
                  <div className="phish-card p-3">
                    <dt className="text-xs text-muted-foreground">Engine version</dt>
                    <dd className="font-medium break-words">{report.modelVersion ?? "Not available"}</dd>
                  </div>
                  <div className="phish-card p-3">
                    <dt className="text-xs text-muted-foreground">Scanned at</dt>
                    <dd className="font-medium">
                      {report.scannedAt ? new Date(report.scannedAt).toLocaleString() : "Not available"}
                    </dd>
                  </div>
                </dl>
                {report.layers.length > 0 && (
                  <ul className="flex flex-wrap gap-2 pt-1">
                    {report.layers.map((layer) => (
                      <li
                        key={layer.name}
                        className={`rounded-md border px-2 py-0.5 text-xs ${
                          layer.status === "completed"
                            ? "border-green-600/40 text-green-700 dark:text-green-400"
                            : "border-border text-muted-foreground"
                        }`}
                      >
                        {layer.name}: {layer.status === "completed" ? "ran" : layer.status}
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            </div>
          )}
        </section>
      </CardContent>
    </Card>
  );
}
