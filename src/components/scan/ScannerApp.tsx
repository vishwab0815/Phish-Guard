"use client";

import { Suspense, useCallback, useEffect, useRef, useState, useSyncExternalStore } from "react";
import Link from "next/link";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { useTheme } from "next-themes";
import { MotionConfig } from "framer-motion";
import { Bot, History, LayoutDashboard, Moon, RotateCcw, ScanSearch, Shield, Sun } from "lucide-react";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "../ui/tabs";
import { Button } from "../ui/button";
import { cn } from "../ui/utils";
import { ApiError, BackendService, isAbortError } from "@/utils/BackendService";
import { useLocalHistory, type HistoryEntry } from "@/lib/localHistory";
import { ScanInterface, urlScanRequest } from "../ScanInterface";
import { Dashboard } from "../Dashboard";
import { ScanHistory } from "../ScanHistory";
import { AIChatbot } from "../AIChatbot";
import { ResultModal } from "./ResultModal";
import { useScanRunner } from "./useScanRunner";
import { KIND_INPUT_ID, isScanKind } from "./kinds";
import type { ScanKind } from "./threatLevel";

type AppTab = "scan" | "dashboard" | "history" | "assistant";

const TABS: { value: AppTab; label: string; Icon: typeof Shield }[] = [
  { value: "scan", label: "Scan", Icon: ScanSearch },
  { value: "dashboard", label: "Dashboard", Icon: LayoutDashboard },
  { value: "history", label: "History", Icon: History },
  { value: "assistant", label: "AI Assistant", Icon: Bot },
];

const TAB_ALIASES: Record<string, AppTab> = {
  scan: "scan",
  dashboard: "dashboard",
  history: "history",
  assistant: "assistant",
  ai: "assistant",
  "ai-assistant": "assistant",
  chat: "assistant",
};

const MAX_URL_PARAM_CHARS = 2048;

interface UrlIntent {
  tab: AppTab | null;
  type: ScanKind | null;
  url: string | null;
}

const noopSubscribe = () => () => {};

/** true after hydration on the client; false during SSR. */
function useMounted() {
  return useSyncExternalStore(noopSubscribe, () => true, () => false);
}

type Health = "checking" | "online" | "offline";

/**
 * Is the scanner reachable? Any HTTP answer from /api/health counts as online —
 * `status: 'degraded'` only means there's no database, which is expected in the demo.
 * Only a network failure/timeout is "offline".
 */
function useScannerHealth() {
  const [health, setHealth] = useState<Health>("checking");
  const check = useCallback(
    () =>
      BackendService.getHealth().then(
        () => setHealth("online"),
        (error: unknown) => {
          if (isAbortError(error)) return;
          setHealth(error instanceof ApiError && error.status > 0 ? "online" : "offline");
        }
      ),
    []
  );
  useEffect(() => {
    void check();
    const id = setInterval(() => void check(), 120_000);
    return () => clearInterval(id);
  }, [check]);
  return { health, recheck: check };
}

/**
 * Reads ?url= / ?type= / ?tab= once per distinct query string. Lives in its own
 * Suspense boundary so the rest of /scan can be prerendered. The callback runs
 * from a timer (not synchronously in the effect) so React StrictMode's
 * mount→unmount→mount cycle can't start or abort a duplicate scan.
 */
function UrlParamsHandler({ onIntent }: { onIntent: (intent: UrlIntent) => void }) {
  const searchParams = useSearchParams();
  const router = useRouter();
  const pathname = usePathname();
  const consumedRef = useRef<string | null>(null);

  useEffect(() => {
    const key = searchParams.toString();
    if (!key || consumedRef.current === key) return;
    const timer = setTimeout(() => {
      if (consumedRef.current === key) return;
      consumedRef.current = key;

      const params = new URLSearchParams(key);
      const tabRaw = params.get("tab")?.toLowerCase() ?? "";
      const typeRaw = params.get("type")?.toLowerCase() ?? "";
      const urlRaw = params.get("url");
      const type = typeRaw === "link" ? "url" : typeRaw;

      onIntent({
        tab: TAB_ALIASES[tabRaw] ?? null,
        type: isScanKind(type) ? type : null,
        url: urlRaw && urlRaw.trim() ? urlRaw.trim().slice(0, MAX_URL_PARAM_CHARS) : null,
      });

      if (urlRaw !== null) {
        // Drop ?url= so a refresh doesn't scan again.
        params.delete("url");
        const qs = params.toString();
        consumedRef.current = qs || null;
        router.replace(qs ? `${pathname}?${qs}` : pathname, { scroll: false });
      }
    }, 0);
    return () => clearTimeout(timer);
  }, [searchParams, router, pathname, onIntent]);

  return null;
}

export function ScannerApp() {
  const [tab, setTab] = useState<AppTab>("scan");
  const [kind, setKind] = useState<ScanKind>("url");
  const [urlValue, setUrlValue] = useState("");
  const { open, view, start, retry, showEntry, showError, close } = useScanRunner();
  const focusAfterCloseRef = useRef<string | null>(null);
  const history = useLocalHistory();
  const { health, recheck } = useScannerHealth();
  const { resolvedTheme, setTheme } = useTheme();
  const mounted = useMounted();

  const handleIntent = useCallback(
    ({ tab: t, type, url }: UrlIntent) => {
      if (url) {
        setTab("scan");
        setKind("url");
        setUrlValue(url);
        void start(urlScanRequest(url));
        return;
      }
      if (type) {
        setKind(type);
        setTab("scan");
      }
      if (t) setTab(t);
    },
    [start]
  );

  const scanAnother = useCallback(() => {
    const k = view ? (view.status === "result" ? view.entry.report.kind : view.kind) : kind;
    setKind(k);
    setTab("scan");
    focusAfterCloseRef.current = KIND_INPUT_ID[k];
    close();
  }, [view, kind, close]);

  const goToScan = useCallback(() => {
    setTab("scan");
    requestAnimationFrame(() => document.getElementById(KIND_INPUT_ID[kind])?.focus());
  }, [kind]);

  const openEntry = useCallback((entry: HistoryEntry) => showEntry(entry), [showEntry]);

  const busy = open && view?.status === "scanning";
  const isDark = resolvedTheme === "dark";

  return (
    <MotionConfig reducedMotion="user">
      <Tabs
        value={tab}
        onValueChange={(v) => setTab(v as AppTab)}
        className="flex min-h-screen flex-col gap-0 bg-gradient-to-br from-blue-50/70 via-transparent to-purple-50/70 dark:from-transparent dark:to-transparent"
      >
        <Suspense fallback={null}>
          <UrlParamsHandler onIntent={handleIntent} />
        </Suspense>

        {/* Header */}
        <header className="sticky top-0 z-40 border-b border-border/60 bg-card/80 shadow-sm backdrop-blur-md">
          <div className="container mx-auto flex flex-wrap items-center gap-x-4 gap-y-3 px-4 py-3">
            <Link
              href="/"
              className="mr-auto flex items-center gap-2 rounded-md focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              aria-label="PhishGuard home"
            >
              <span className="flex h-9 w-9 items-center justify-center rounded-xl bg-gradient-to-br from-blue-500 to-purple-600 shadow-md shadow-purple-500/30">
                <Shield className="h-5 w-5 text-white" aria-hidden="true" />
              </span>
              <span className="text-lg font-bold tracking-tight">PhishGuard</span>
            </Link>

            <TabsList
              aria-label="Sections"
              className="order-3 grid h-auto w-full grid-cols-4 gap-1 rounded-xl bg-muted/80 p-1 md:order-2 md:w-auto"
            >
              {TABS.map(({ value, label, Icon }) => (
                <TabsTrigger
                  key={value}
                  value={value}
                  className="group tabs-trigger-enhanced relative flex-col gap-0.5 rounded-lg px-2 py-1.5 text-[11px] data-[state=active]:text-white dark:data-[state=active]:text-white sm:flex-row sm:gap-2 sm:px-3 sm:text-sm"
                >
                  <Icon className="h-4 w-4" aria-hidden="true" />
                  <span>{label}</span>
                  {value === "history" && history.length > 0 && (
                    <span className="hidden rounded-full bg-blue-600/15 px-1.5 text-[10px] font-semibold tabular-nums text-blue-700 group-data-[state=active]:bg-white/25 group-data-[state=active]:text-white dark:text-blue-300 sm:inline">
                      {history.length}
                    </span>
                  )}
                </TabsTrigger>
              ))}
            </TabsList>

            <div className="order-2 flex items-center gap-2 md:order-3">
              {health === "offline" ? (
                <button
                  type="button"
                  onClick={() => void recheck()}
                  className="inline-flex items-center gap-1.5 rounded-full border border-red-300 bg-red-50 px-2.5 py-1 text-xs font-medium text-red-700 hover:bg-red-100 dark:border-red-800 dark:bg-red-950/40 dark:text-red-300"
                  title="Couldn't reach the scanner. Click to check again."
                >
                  <RotateCcw className="h-3 w-3" aria-hidden="true" />
                  Scanner unreachable
                </button>
              ) : (
                <span
                  className="inline-flex items-center gap-2 rounded-full border border-border bg-background/60 px-2.5 py-1 text-xs text-muted-foreground"
                  title="This is a demo: results are saved only in this browser, never on a server."
                >
                  <span
                    className={cn(
                      "h-2 w-2 rounded-full",
                      health === "online" ? "bg-green-500 shadow-[0_0_6px_rgba(34,197,94,0.7)]" : "bg-slate-400"
                    )}
                    aria-hidden="true"
                  />
                  <span className="sr-only">{health === "online" ? "Scanner online. " : "Checking scanner. "}</span>
                  <span className="font-semibold text-foreground">Demo</span>
                  <span className="hidden sm:inline">· results stay on this device</span>
                </span>
              )}

              <Button
                variant="ghost"
                size="icon"
                onClick={() => setTheme(isDark ? "light" : "dark")}
                className="hover:bg-purple-500/10"
                aria-label={mounted ? (isDark ? "Switch to light theme" : "Switch to dark theme") : "Toggle theme"}
              >
                {mounted ? (
                  isDark ? (
                    <Sun className="h-4 w-4 text-yellow-500" aria-hidden="true" />
                  ) : (
                    <Moon className="h-4 w-4 text-blue-600" aria-hidden="true" />
                  )
                ) : (
                  <span className="h-4 w-4" aria-hidden="true" />
                )}
              </Button>
            </div>
          </div>
        </header>

        {/* Main */}
        <main className="container mx-auto w-full flex-1 px-4 py-6 sm:py-8">
          {/* forceMount keeps form input and chat history when switching tabs */}
          <TabsContent value="scan" forceMount className="data-[state=inactive]:hidden">
            <ScanInterface
              kind={kind}
              onKindChange={setKind}
              urlValue={urlValue}
              onUrlChange={setUrlValue}
              busy={busy}
              onStart={(request) => void start(request)}
              onInvalid={showError}
              onOpenEntry={openEntry}
              onShowHistory={() => setTab("history")}
            />
          </TabsContent>

          <TabsContent value="dashboard">
            <Dashboard onOpenEntry={openEntry} onStartScan={goToScan} onShowHistory={() => setTab("history")} />
          </TabsContent>

          <TabsContent value="history">
            <ScanHistory onOpenEntry={openEntry} onStartScan={goToScan} />
          </TabsContent>

          <TabsContent value="assistant" forceMount className="data-[state=inactive]:hidden">
            <AIChatbot />
          </TabsContent>
        </main>

        {/* Footer */}
        <footer className="border-t border-border/60 bg-card/70 backdrop-blur-sm">
          <div className="container mx-auto px-4 py-4 text-center text-xs text-muted-foreground sm:text-sm">
            © 2026 PhishGuard · Demo — results are guidance, not a guarantee · Lost money? Call{" "}
            <a href="tel:1930" className="font-semibold text-foreground underline-offset-4 hover:underline">
              1930
            </a>{" "}
            /{" "}
            <a
              href="https://cybercrime.gov.in"
              target="_blank"
              rel="noopener noreferrer"
              className="font-semibold text-foreground underline-offset-4 hover:underline"
            >
              cybercrime.gov.in
            </a>
          </div>
        </footer>
      </Tabs>

      <ResultModal
        open={open}
        view={view}
        onClose={close}
        onRetry={retry}
        onScanAnother={scanAnother}
        onCloseAutoFocus={(event) => {
          const id = focusAfterCloseRef.current;
          if (!id) return;
          focusAfterCloseRef.current = null;
          event.preventDefault();
          const el = document.getElementById(id);
          el?.focus();
          if (el instanceof HTMLInputElement) el.select();
        }}
      />
    </MotionConfig>
  );
}

export default ScannerApp;
