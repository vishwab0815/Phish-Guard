import { useMemo, useState } from "react";
import { motion } from "framer-motion";
import { toast } from "sonner";
import { Download, HardDrive, ScanSearch, Search, Trash2 } from "lucide-react";
import { Button } from "./ui/button";
import { Input } from "./ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "./ui/select";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "./ui/dialog";
import { MAX_ENTRIES, localHistory, useLocalHistory, type HistoryEntry } from "@/lib/localHistory";
import { THREAT_FILTER_OPTIONS, THREAT_META, ThreatBadge } from "./scan/threatLevel";
import { KIND_META, SCAN_KINDS, formatRelative } from "./scan/kinds";
import { useNow } from "./scan/useNow";

interface ScanHistoryProps {
  onOpenEntry: (entry: HistoryEntry) => void;
  onStartScan: () => void;
}

function csvCell(value: string | number | null): string {
  let s = value === null ? "" : String(value);
  // Neutralise spreadsheet formula injection.
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return `"${s.replace(/"/g, '""')}"`;
}

function exportCsv(entries: readonly HistoryEntry[]) {
  const header = ["Checked at", "Type", "Scanned", "Verdict", "Risk score", "Confidence", "Findings", "Recommendations"];
  const rows = entries.map(({ savedAt, report }) => [
    report.scannedAt ?? savedAt,
    KIND_META[report.kind].label,
    report.target,
    THREAT_META[report.level].label,
    report.riskScore,
    report.confidence,
    report.indicators.join(" | "),
    report.recommendations.join(" | "),
  ]);
  const csv = [header, ...rows].map((row) => row.map(csvCell).join(",")).join("\r\n");
  const blob = new Blob(["﻿" + csv], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `phishguard-history-${new Date().toISOString().slice(0, 10)}.csv`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

export function ScanHistory({ onOpenEntry, onStartScan }: ScanHistoryProps) {
  const entries = useLocalHistory();
  const now = useNow();
  const [search, setSearch] = useState("");
  const [type, setType] = useState("all");
  const [verdict, setVerdict] = useState("all");
  const [confirmOpen, setConfirmOpen] = useState(false);

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return entries.filter(({ report }) => {
      if (type !== "all" && report.kind !== type) return false;
      if (verdict !== "all" && report.level !== verdict) return false;
      if (!q) return true;
      return (
        report.target.toLowerCase().includes(q) ||
        report.indicators.some((i) => i.toLowerCase().includes(q)) ||
        THREAT_META[report.level].label.toLowerCase().includes(q)
      );
    });
  }, [entries, search, type, verdict]);

  const remove = (entry: HistoryEntry) => {
    localHistory.remove(entry.id);
    toast("Removed from history", {
      action: { label: "Undo", onClick: () => localHistory.restore(entry) },
    });
  };

  const clearAll = () => {
    localHistory.clear();
    setConfirmOpen(false);
    toast.success("History cleared");
  };

  const filtersActive = search.trim() !== "" || type !== "all" || verdict !== "all";

  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="space-y-4"
    >
      <section className="space-y-4 rounded-2xl border border-border bg-card/80 p-4 backdrop-blur-sm sm:p-6">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <h2 className="text-xl">History</h2>
            <p className="mt-0.5 flex items-center gap-1.5 text-xs text-muted-foreground">
              <HardDrive className="h-3.5 w-3.5" aria-hidden="true" />
              Stored only in this browser · last {MAX_ENTRIES} checks
            </p>
          </div>
          <div className="flex gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => exportCsv(filtered)}
              disabled={filtered.length === 0}
            >
              <Download className="h-4 w-4" aria-hidden="true" />
              Export CSV
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => setConfirmOpen(true)}
              disabled={entries.length === 0}
              className="text-red-600 hover:text-red-700 dark:text-red-400"
            >
              <Trash2 className="h-4 w-4" aria-hidden="true" />
              Clear history
            </Button>
          </div>
        </div>

        <div className="grid gap-2 sm:grid-cols-[1fr_auto_auto]">
          <div className="relative">
            <Search
              className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground"
              aria-hidden="true"
            />
            <Input
              type="search"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search links, subjects, findings…"
              aria-label="Search history"
              className="pl-9"
            />
          </div>
          <div className="grid grid-cols-2 gap-2 sm:contents">
            <Select value={type} onValueChange={setType}>
              <SelectTrigger className="w-full sm:w-36" aria-label="Filter by type">
                <SelectValue placeholder="All types" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All types</SelectItem>
                {SCAN_KINDS.map((k) => (
                  <SelectItem key={k} value={k}>
                    {KIND_META[k].label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Select value={verdict} onValueChange={setVerdict}>
              <SelectTrigger className="w-full sm:w-44" aria-label="Filter by verdict">
                <SelectValue placeholder="All verdicts" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All verdicts</SelectItem>
                {THREAT_FILTER_OPTIONS.map((o) => (
                  <SelectItem key={o.value} value={o.value}>
                    {o.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </div>

        {entries.length === 0 ? (
          <div className="rounded-xl border border-dashed border-border px-6 py-12 text-center">
            <p className="font-medium">No checks yet</p>
            <p className="mt-1 text-sm text-muted-foreground">Results you check will appear here.</p>
            <Button onClick={onStartScan} className="mt-4 text-white security-button">
              <ScanSearch className="h-4 w-4" aria-hidden="true" />
              Run your first check
            </Button>
          </div>
        ) : filtered.length === 0 ? (
          <div className="rounded-xl border border-dashed border-border px-6 py-10 text-center text-sm text-muted-foreground">
            Nothing matches these filters.
            {filtersActive && (
              <Button
                variant="link"
                size="sm"
                onClick={() => {
                  setSearch("");
                  setType("all");
                  setVerdict("all");
                }}
              >
                Reset filters
              </Button>
            )}
          </div>
        ) : (
          <>
            <p className="text-xs text-muted-foreground" aria-live="polite">
              Showing {filtered.length} of {entries.length}
            </p>
            <ul className="divide-y divide-border overflow-hidden rounded-xl border border-border">
              {filtered.map((entry) => {
                const { report } = entry;
                const KindIcon = KIND_META[report.kind].Icon;
                return (
                  <li key={entry.id} className="flex items-stretch">
                    <button
                      type="button"
                      onClick={() => onOpenEntry(entry)}
                      className="flex min-w-0 flex-1 items-center gap-3 px-3 py-3 text-left transition-colors hover:bg-muted/60 focus-visible:bg-muted/60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-ring sm:px-4"
                    >
                      <KindIcon className="h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" />
                      <span className="min-w-0 flex-1 space-y-1">
                        <span className="block truncate font-mono text-sm" title={report.target}>
                          {report.target}
                        </span>
                        <span className="flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-muted-foreground">
                          <ThreatBadge level={report.level} className="sm:hidden" />
                          <span>{KIND_META[report.kind].label}</span>
                          {report.riskScore !== null && <span>· Risk {Math.round(report.riskScore)}/100</span>}
                          {now > 0 && (
                            <span title={new Date(entry.savedAt).toLocaleString()}>
                              · {formatRelative(entry.savedAt, now)}
                            </span>
                          )}
                        </span>
                      </span>
                      <ThreatBadge level={report.level} className="hidden shrink-0 sm:inline-flex" />
                    </button>
                    <Button
                      variant="ghost"
                      size="icon"
                      onClick={() => remove(entry)}
                      aria-label={`Delete ${report.target} from history`}
                      className="m-auto mr-1 shrink-0 text-muted-foreground hover:text-red-600 dark:hover:text-red-400"
                    >
                      <Trash2 className="h-4 w-4" aria-hidden="true" />
                    </Button>
                  </li>
                );
              })}
            </ul>
          </>
        )}
      </section>

      <Dialog open={confirmOpen} onOpenChange={setConfirmOpen}>
        <DialogContent className="bg-card">
          <DialogHeader>
            <DialogTitle>Clear all history?</DialogTitle>
            <DialogDescription>
              This removes all {entries.length} saved check{entries.length === 1 ? "" : "s"} from this browser. It
              can&apos;t be undone.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setConfirmOpen(false)}>
              Cancel
            </Button>
            <Button variant="destructive" onClick={clearAll}>
              <Trash2 className="h-4 w-4" aria-hidden="true" />
              Clear history
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </motion.div>
  );
}

export default ScanHistory;
