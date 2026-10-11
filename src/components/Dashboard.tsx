import { useMemo } from "react";
import { motion } from "framer-motion";
import { Activity, LayoutGrid, ScanSearch, ShieldAlert, ShieldCheck, TriangleAlert } from "lucide-react";
import { Button } from "./ui/button";
import { cn } from "./ui/utils";
import { useLocalHistory, type HistoryEntry } from "@/lib/localHistory";
import { THREAT_META, ThreatIcon, type ScanKind, type ThreatLevel } from "./scan/threatLevel";
import { KIND_META, SCAN_KINDS } from "./scan/kinds";
import { RecentList } from "./scan/RecentList";
import { useNow } from "./scan/useNow";

interface DashboardProps {
  onOpenEntry: (entry: HistoryEntry) => void;
  onStartScan: () => void;
  onShowHistory: () => void;
}

const LEVEL_ORDER: ThreatLevel[] = ["critical", "high", "medium", "low", "safe", "unknown"];

function summarize(entries: readonly HistoryEntry[], now: number) {
  const byLevel: Record<ThreatLevel, number> = { critical: 0, high: 0, medium: 0, low: 0, safe: 0, unknown: 0 };
  const byKind: Record<ScanKind, number> = { url: 0, email: 0, message: 0, file: 0 };
  const dayStart = now > 0 ? new Date(now).setHours(0, 0, 0, 0) : Number.POSITIVE_INFINITY;
  let today = 0;
  for (const e of entries) {
    byLevel[e.report.level] += 1;
    byKind[e.report.kind] += 1;
    if (new Date(e.savedAt).getTime() >= dayStart) today += 1;
  }
  return {
    total: entries.length,
    today,
    dangerous: byLevel.critical + byLevel.high,
    suspicious: byLevel.medium + byLevel.low,
    safe: byLevel.safe,
    byLevel,
    byKind,
  };
}

function StatTile({
  label,
  value,
  hint,
  icon: Icon,
  accent,
}: {
  label: string;
  value: number;
  hint?: string;
  icon: typeof Activity;
  accent: string;
}) {
  return (
    <div className="rounded-2xl border border-border bg-card/80 p-4 shadow-sm backdrop-blur-sm">
      <div className="flex items-center justify-between gap-2">
        <span className="text-sm text-muted-foreground">{label}</span>
        <span className={cn("flex h-8 w-8 items-center justify-center rounded-lg", accent)}>
          <Icon className="h-4 w-4" aria-hidden="true" />
        </span>
      </div>
      <p className="mt-2 text-3xl font-bold tabular-nums">{value.toLocaleString()}</p>
      {hint && <p className="mt-0.5 text-xs text-muted-foreground">{hint}</p>}
    </div>
  );
}

export function Dashboard({ onOpenEntry, onStartScan, onShowHistory }: DashboardProps) {
  const entries = useLocalHistory();
  const now = useNow();
  const s = useMemo(() => summarize(entries, now), [entries, now]);

  if (entries.length === 0) {
    return (
      <motion.div
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3 }}
        className="mx-auto max-w-xl rounded-2xl border border-dashed border-border bg-card/70 px-6 py-14 text-center backdrop-blur-sm"
      >
        <span className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl bg-gradient-to-br from-blue-500 to-purple-600 shadow-lg shadow-purple-500/30">
          <ShieldCheck className="h-7 w-7 text-white" aria-hidden="true" />
        </span>
        <h2 className="mt-5 text-xl">Your dashboard is empty</h2>
        <p className="mx-auto mt-2 max-w-sm text-sm text-muted-foreground">
          Check a link, email, message or file and your results will be summarised here. They stay in this browser.
        </p>
        <Button onClick={onStartScan} className="mt-6 h-11 px-6 text-white security-button">
          <ScanSearch className="h-4 w-4" aria-hidden="true" />
          Run your first check
        </Button>
      </motion.div>
    );
  }

  const presentLevels = LEVEL_ORDER.filter((l) => s.byLevel[l] > 0);

  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="space-y-6"
    >
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <StatTile
          label="Total checks"
          value={s.total}
          hint={`${s.today} today`}
          icon={Activity}
          accent="bg-blue-100 text-blue-700 dark:bg-blue-950/60 dark:text-blue-300"
        />
        <StatTile
          label="High-risk caught"
          value={s.dangerous}
          hint={s.byLevel.critical > 0 ? `${s.byLevel.critical} critical` : "High + critical"}
          icon={ShieldAlert}
          accent="bg-red-100 text-red-700 dark:bg-red-950/60 dark:text-red-300"
        />
        <StatTile
          label="Suspicious"
          value={s.suspicious}
          hint="Low + medium risk"
          icon={TriangleAlert}
          accent="bg-orange-100 text-orange-700 dark:bg-orange-950/60 dark:text-orange-300"
        />
        <StatTile
          label="No threats found"
          value={s.safe}
          hint="Still stay alert"
          icon={ShieldCheck}
          accent="bg-green-100 text-green-700 dark:bg-green-950/60 dark:text-green-300"
        />
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-5">
        <section className="min-w-0 space-y-5 rounded-2xl border border-border bg-card/80 p-4 backdrop-blur-sm sm:p-6 lg:col-span-2">
          <div>
            <h2 className="text-lg">Verdicts</h2>
            <p className="text-xs text-muted-foreground">
              Across your {s.total === 1 ? "only check" : `last ${s.total} checks`}
            </p>
          </div>

          {/* Stacked bar: one segment per verdict, 2px gaps, labelled in the legend below. */}
          <div className="flex h-3 w-full gap-0.5 overflow-hidden rounded-full" role="img" aria-label="Verdict breakdown">
            {presentLevels.map((level) => (
              <div
                key={level}
                className={cn("h-full first:rounded-l-full last:rounded-r-full", THREAT_META[level].fillClass)}
                style={{ width: `${(s.byLevel[level] / s.total) * 100}%` }}
                title={`${THREAT_META[level].label}: ${s.byLevel[level]}`}
              />
            ))}
          </div>

          <ul className="space-y-2">
            {LEVEL_ORDER.filter((l) => l !== "unknown" || s.byLevel.unknown > 0).map((level) => {
              const count = s.byLevel[level];
              const pct = Math.round((count / s.total) * 100);
              return (
                <li key={level} className="flex items-center gap-3 text-sm">
                  <span className={cn("h-2.5 w-2.5 shrink-0 rounded-full", THREAT_META[level].fillClass)} aria-hidden="true" />
                  <ThreatIcon level={level} className="h-4 w-4" />
                  <span className="flex-1">{THREAT_META[level].label}</span>
                  <span className="tabular-nums font-medium">{count}</span>
                  <span className="w-10 text-right tabular-nums text-xs text-muted-foreground">{pct}%</span>
                </li>
              );
            })}
          </ul>

          <div className="border-t border-border pt-4">
            <h3 className="mb-3 flex items-center gap-2 text-sm font-semibold text-muted-foreground">
              <LayoutGrid className="h-4 w-4" aria-hidden="true" />
              By type
            </h3>
            <div className="grid grid-cols-2 gap-2">
              {SCAN_KINDS.map((k) => {
                const { Icon, label } = KIND_META[k];
                return (
                  <div key={k} className="flex items-center gap-2 rounded-lg border border-border bg-muted/30 px-3 py-2">
                    <Icon className="h-4 w-4 text-muted-foreground" aria-hidden="true" />
                    <span className="flex-1 text-sm">{label}</span>
                    <span className="font-semibold tabular-nums">{s.byKind[k]}</span>
                  </div>
                );
              })}
            </div>
          </div>
        </section>

        <section className="min-w-0 space-y-3 rounded-2xl border border-border bg-card/80 p-4 backdrop-blur-sm sm:p-6 lg:col-span-3">
          <div className="flex items-center justify-between gap-2">
            <h2 className="text-lg">Recent checks</h2>
            <Button variant="ghost" size="sm" onClick={onShowHistory}>
              View all
            </Button>
          </div>
          <RecentList entries={entries.slice(0, 6)} onOpen={onOpenEntry} />
          <Button variant="outline" onClick={onStartScan} className="w-full">
            <ScanSearch className="h-4 w-4" aria-hidden="true" />
            Check something new
          </Button>
        </section>
      </div>
    </motion.div>
  );
}

export default Dashboard;
