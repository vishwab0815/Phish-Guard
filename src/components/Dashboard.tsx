import { useCallback, useEffect, useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "./ui/card";
import { Badge } from "./ui/badge";
import { Button } from "./ui/button";
import { Alert, AlertDescription } from "./ui/alert";
import { Activity, AlertTriangle, Clock, Database, RotateCcw, Shield } from "lucide-react";
import { motion, type Variants } from "framer-motion";
import {
  BackendService as DefaultBackendService,
  errorMessage,
  isAbortError,
  type BackendServiceType,
  type StatsPayload,
  type StoredScan,
} from "@/utils/BackendService";
import { normalizeThreatLevel, ThreatBadge, type ThreatLevel } from "./scan/threatLevel";
import { formatCount, summarizeStats } from "./scan/stats";

interface DashboardProps {
  backendService?: BackendServiceType;
}

interface RecentScan {
  id: string;
  type: string;
  content: string;
  level: ThreatLevel;
  timestamp: string | null;
  recommendation: string | null;
}

const containerVariants: Variants = {
  hidden: { opacity: 0 },
  visible: { opacity: 1, transition: { staggerChildren: 0.08 } },
};

const itemVariants: Variants = {
  hidden: { y: 20, opacity: 0 },
  visible: { y: 0, opacity: 1, transition: { type: "spring", stiffness: 100 } },
};

function relativeTime(timestamp: string | null): string {
  if (!timestamp) return "Time unknown";
  const then = new Date(timestamp).getTime();
  if (Number.isNaN(then)) return "Time unknown";
  const minutes = Math.floor((Date.now() - then) / 60000);
  if (minutes < 1) return "Just now";
  if (minutes < 60) return `${minutes} min ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours} hour${hours === 1 ? "" : "s"} ago`;
  const days = Math.floor(hours / 24);
  return `${days} day${days === 1 ? "" : "s"} ago`;
}

function toRecent(scan: StoredScan): RecentScan {
  return {
    id: scan.id,
    type: String(scan.type || "").toLowerCase(),
    content: scan.target,
    level: normalizeThreatLevel(scan.result?.threat_level),
    timestamp: scan.timestamp ?? null,
    recommendation: scan.result?.recommendations?.[0] ?? null,
  };
}

export function Dashboard({ backendService = DefaultBackendService }: DashboardProps) {
  const [online, setOnline] = useState<boolean | "degraded" | null>(null);
  const [enginesActive, setEnginesActive] = useState<number | null>(null);
  const [stats, setStats] = useState<StatsPayload | null>(null);
  const [statsError, setStatsError] = useState<string | null>(null);
  const [recentScans, setRecentScans] = useState<RecentScan[]>([]);
  const [scansError, setScansError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  // State is only set inside the promise callback (never synchronously in an effect).
  const load = useCallback(
    (signal?: AbortSignal) =>
      Promise.allSettled([
        backendService.getHealth(signal),
        backendService.getStats(signal),
        backendService.getScans(5, signal),
      ]).then(([healthRes, statsRes, scansRes]) => {
        if (signal?.aborted) return;

        if (healthRes.status === "fulfilled") {
          setOnline(healthRes.value.status === "degraded" ? "degraded" : true);
          const h = healthRes.value;
          setEnginesActive(
            typeof h.models_available === "number" ? h.models_available : Array.isArray(h.models) ? h.models.length : null
          );
        } else if (!isAbortError(healthRes.reason)) {
          setOnline(false);
          setEnginesActive(null);
        }

        if (statsRes.status === "fulfilled") {
          setStats(statsRes.value);
          setStatsError(null);
        } else if (!isAbortError(statsRes.reason)) {
          setStats(null);
          setStatsError(errorMessage(statsRes.reason, "Couldn't load your statistics."));
        }

        if (scansRes.status === "fulfilled") {
          setRecentScans(scansRes.value.slice(0, 5).map(toRecent));
          setScansError(null);
        } else if (!isAbortError(scansRes.reason)) {
          setScansError(errorMessage(scansRes.reason, "Couldn't load your recent scans."));
        }

        setLoading(false);
        }),
    [backendService]
  );

  useEffect(() => {
    const controller = new AbortController();
    load(controller.signal);
    const interval = setInterval(() => load(controller.signal), 60000);
    return () => {
      controller.abort();
      clearInterval(interval);
    };
  }, [load]);

  const summary = summarizeStats(stats);
  const { total, scansToday, critical, dangerous, suspicious, safe } = summary;
  const scansWeek = summary.scansThisWeek;

  const statCards = [
    { label: "Total scans", sub: "All time", value: total },
    { label: "Scans today", sub: "Since midnight, your time", value: scansToday },
    {
      label: "High-risk or critical",
      sub: critical !== null ? `${formatCount(critical)} critical` : "Results rated High or Critical",
      value: dangerous,
      danger: true,
    },
    { label: "Suspicious", sub: "Rated Low or Medium risk", value: suspicious },
  ];

  const breakdownKnown = total !== null && total > 0 && safe !== null && suspicious !== null && dangerous !== null;
  const pct = (n: number | null) => (breakdownKnown && n !== null ? (n / (total as number)) * 100 : 0);

  return (
    <motion.div variants={containerVariants} initial="hidden" animate="visible" className="space-y-6">
      {/* System status */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <motion.div variants={itemVariants}>
          <Card className="glass-card">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Scanner status</CardTitle>
              <Activity className={`h-4 w-4 ${online === true ? "status-online" : "status-warning"}`} aria-hidden="true" />
            </CardHeader>
            <CardContent>
              <div
                className={`text-2xl font-bold ${
                  online === null
                    ? "text-muted-foreground"
                    : online === "degraded"
                      ? "text-yellow-600 dark:text-yellow-400"
                      : online
                        ? "text-green-600 dark:text-green-500"
                        : "text-red-600 dark:text-red-400"
                }`}
              >
                {online === null ? "Checking…" : online === "degraded" ? "Online" : online ? "Online" : "Offline"}
              </div>
              <p className="text-xs text-muted-foreground mt-1">
                {online === false
                  ? "Scans can't run until the scanner is reachable"
                  : online === "degraded"
                    ? "Scans work, but history and stats are offline"
                    : "Ready to check links, emails, messages and files"}
              </p>
            </CardContent>
          </Card>
        </motion.div>

        <motion.div variants={itemVariants}>
          <Card className="glass-card">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Detection engines active</CardTitle>
              <Database className="h-4 w-4 text-primary" aria-hidden="true" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-gradient">{formatCount(enginesActive)}</div>
              <p className="text-xs text-muted-foreground mt-1">As reported by the server health check</p>
            </CardContent>
          </Card>
        </motion.div>

        <motion.div variants={itemVariants}>
          <Card className="glass-card">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Your scans this week</CardTitle>
              <Clock className="h-4 w-4 text-cyan-500" aria-hidden="true" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-cyan-600 dark:text-cyan-400">{formatCount(scansWeek)}</div>
              <p className="text-xs text-muted-foreground mt-1">
                {scansWeek === null ? "Not available" : "Last 7 days"}
              </p>
            </CardContent>
          </Card>
        </motion.div>
      </div>

      {statsError && (
        <Alert variant="destructive">
          <AlertTriangle className="h-4 w-4" aria-hidden="true" />
          <AlertDescription>
            <span>Your statistics are unavailable: {statsError}</span>
            <Button size="sm" variant="outline" className="mt-2 w-fit" onClick={() => load()}>
              <RotateCcw className="w-4 h-4 mr-2" aria-hidden="true" />
              Retry
            </Button>
          </AlertDescription>
        </Alert>
      )}

      {/* Your stats */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {statCards.map((stat) => (
          <motion.div key={stat.label} variants={itemVariants}>
            <Card className="glass-card">
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">{stat.label}</CardTitle>
                <Shield className="h-4 w-4 text-muted-foreground/50" aria-hidden="true" />
              </CardHeader>
              <CardContent>
                <div className={`text-3xl font-bold ${stat.danger && (stat.value ?? 0) > 0 ? "text-red-600 dark:text-red-400" : ""}`}>
                  {formatCount(stat.value)}
                </div>
                <p className="text-xs text-muted-foreground mt-1">{stat.sub}</p>
              </CardContent>
            </Card>
          </motion.div>
        ))}
      </div>

      {/* Results breakdown */}
      <motion.div variants={itemVariants}>
        <Card className="glass-card">
          <CardHeader>
            <CardTitle className="text-xl">Your results at a glance</CardTitle>
            <CardDescription>How the links, emails, messages and files you&apos;ve scanned were rated</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {breakdownKnown ? (
              <>
                <div className="flex h-3 w-full overflow-hidden rounded-full bg-muted" role="img"
                  aria-label={`${formatCount(safe)} with no threats found, ${formatCount(suspicious)} suspicious, ${formatCount(dangerous)} high-risk or critical`}>
                  <div className="bg-green-600" style={{ width: `${pct(safe)}%` }} />
                  <div className="bg-orange-500" style={{ width: `${pct(suspicious)}%` }} />
                  <div className="bg-red-600" style={{ width: `${pct(dangerous)}%` }} />
                </div>
                <ul className="flex flex-wrap gap-4 text-sm">
                  <li className="flex items-center gap-2">
                    <span className="w-3 h-3 rounded-sm bg-green-600" aria-hidden="true" />
                    No threats found: {formatCount(safe)}
                  </li>
                  <li className="flex items-center gap-2">
                    <span className="w-3 h-3 rounded-sm bg-orange-500" aria-hidden="true" />
                    Suspicious: {formatCount(suspicious)}
                  </li>
                  <li className="flex items-center gap-2">
                    <span className="w-3 h-3 rounded-sm bg-red-600" aria-hidden="true" />
                    High-risk or critical: {formatCount(dangerous)}
                  </li>
                </ul>
                <p className="text-sm text-muted-foreground">
                  {dangerous && dangerous > 0
                    ? `${formatCount(dangerous)} of your scans were rated high-risk or critical. If you entered details or paid on any of them, call 1930 and report at cybercrime.gov.in.`
                    : "None of your scans so far were rated high-risk. Keep checking anything unexpected before you act on it."}
                </p>
              </>
            ) : (
              <p className="text-sm text-muted-foreground">
                {loading
                  ? "Loading…"
                  : total === 0
                    ? "You haven't scanned anything yet. Start from the Scan tab."
                    : "A breakdown isn't available right now."}
              </p>
            )}
          </CardContent>
        </Card>
      </motion.div>

      {/* Recent scans */}
      <motion.div variants={itemVariants}>
        <Card className="glass-card">
          <CardHeader>
            <CardTitle>Recent scans</CardTitle>
            <CardDescription>Your latest results.</CardDescription>
          </CardHeader>
          <CardContent>
            {loading ? (
              <div className="text-center py-12" role="status">
                <div className="animate-spin rounded-full h-10 w-10 border-b-2 border-primary mx-auto" aria-hidden="true" />
                <p className="text-sm text-muted-foreground mt-4">Loading recent scans…</p>
              </div>
            ) : scansError ? (
              <div className="text-center py-8 space-y-3">
                <p className="text-sm text-red-600 dark:text-red-400">{scansError}</p>
                <Button size="sm" variant="outline" onClick={() => load()}>
                  <RotateCcw className="w-4 h-4 mr-2" aria-hidden="true" />
                  Retry
                </Button>
              </div>
            ) : recentScans.length === 0 ? (
              <p className="text-center py-8 text-sm text-muted-foreground">No scans yet.</p>
            ) : (
              <ul className="space-y-3">
                {recentScans.map((scan) => (
                  <li
                    key={scan.id}
                    className="flex flex-col gap-2 p-4 bg-muted/30 border border-border/50 rounded-xl sm:flex-row sm:items-start sm:justify-between"
                  >
                    <div className="min-w-0 space-y-1">
                      <p className="font-semibold truncate max-w-[60ch]" title={scan.content}>
                        {scan.content}
                      </p>
                      <div className="flex flex-wrap items-center gap-3">
                        <span className="text-xs text-muted-foreground flex items-center gap-1">
                          <Clock className="w-3 h-3" aria-hidden="true" />
                          {relativeTime(scan.timestamp)}
                        </span>
                        <Badge variant="outline" className="text-[10px] py-0 px-2 h-4 capitalize">
                          {scan.type || "unknown"}
                        </Badge>
                      </div>
                      {scan.recommendation && (
                        <p className="text-xs text-muted-foreground">{scan.recommendation}</p>
                      )}
                    </div>
                    <ThreatBadge level={scan.level} className="self-start" />
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>
      </motion.div>
    </motion.div>
  );
}
