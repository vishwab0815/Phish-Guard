'use client'

import { useState, useEffect, useCallback, useSyncExternalStore } from 'react'
import { useTheme } from 'next-themes'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Dashboard } from '@/components/Dashboard'
import { ScanInterface } from '@/components/ScanInterface'
import { ScanHistory } from '@/components/ScanHistory'
import { Settings } from '@/components/Settings'
import { AIChatbot } from '@/components/AIChatbot'
import { BackendService } from '@/utils/BackendService'
import { summarizeStats } from '@/components/scan/stats'
import {
  Shield,
  Scan,
  History,
  Settings as SettingsIcon,
  Bot,
  Moon,
  Sun,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Loader2,
} from 'lucide-react'

type ScannerStatus = 'checking' | 'online' | 'degraded' | 'offline'

const noopSubscribe = () => () => {}

/** true after hydration on the client; false during SSR. */
function useMounted() {
  return useSyncExternalStore(noopSubscribe, () => true, () => false)
}

export default function Home() {
  const [activeTab, setActiveTab] = useState('dashboard')
  const { resolvedTheme, setTheme } = useTheme()
  const mounted = useMounted()
  const [status, setStatus] = useState<ScannerStatus>('checking')
  const [threatCount, setThreatCount] = useState<number | null>(null)
  const [lastChecked, setLastChecked] = useState<Date | null>(null)

  // State is only set inside promise callbacks, never synchronously in an effect.
  const refreshStats = useCallback(
    () =>
      BackendService.getStats().then(
        (stats) => setThreatCount(summarizeStats(stats).dangerous),
        () => setThreatCount(null)
      ),
    []
  )

  const checkSystem = useCallback(
    () =>
      Promise.allSettled([BackendService.getHealth(), BackendService.getStats()]).then(([health, stats]) => {
        setStatus(
          health.status === 'fulfilled'
            ? health.value.status === 'degraded'
              ? 'degraded'
              : 'online'
            : 'offline'
        )
        setThreatCount(stats.status === 'fulfilled' ? summarizeStats(stats.value).dangerous : null)
        setLastChecked(new Date())
      }),
    []
  )

  useEffect(() => {
    checkSystem()
    const interval = setInterval(checkSystem, 60000)
    return () => clearInterval(interval)
  }, [checkSystem])

  const toggleDarkMode = () => {
    setTheme(resolvedTheme === 'dark' ? 'light' : 'dark')
  }

  const statusLabel =
    status === 'online'
      ? 'Scanner online'
      : status === 'degraded'
        ? 'Scanner online · history offline'
        : status === 'offline'
          ? 'Scanner offline'
          : 'Checking scanner…'

  return (
    <div className="flex min-h-screen flex-col cyber-grid bg-gradient-to-br from-slate-50 to-slate-100 dark:from-slate-950 dark:to-slate-900">
      {/* Header */}
      <header className="border-b bg-card/80 backdrop-blur-sm border-border/50 shadow-lg">
        <div className="container mx-auto px-4 py-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-3">
              <div className="flex items-center gap-2">
                <Shield className="w-8 h-8 text-blue-500 shield-glow" aria-hidden="true" />
                <h1 className="text-xl font-bold dark:neon-text">PhishGuard</h1>
              </div>
              <Badge
                variant="outline"
                className="hidden sm:flex items-center gap-1 gradient-border ai-assistant-glow"
              >
                <Bot className="w-3 h-3 text-purple-500" aria-hidden="true" />
                <span className="relative z-10">AI-assisted</span>
              </Badge>
            </div>

            <div className="flex items-center gap-2">
              <div className="flex flex-wrap items-center gap-2 mr-2">
                <div className="flex items-center gap-1 phish-card px-3 py-1" role="status">
                  {status === 'online' ? (
                    <CheckCircle className="w-4 h-4 status-online" aria-hidden="true" />
                  ) : status === 'degraded' ? (
                    <AlertTriangle className="w-4 h-4 status-warning" aria-hidden="true" />
                  ) : status === 'offline' ? (
                    <XCircle className="w-4 h-4 text-red-500" aria-hidden="true" />
                  ) : (
                    <Loader2 className="w-4 h-4 animate-spin text-muted-foreground" aria-hidden="true" />
                  )}
                  <span className="text-sm font-medium">{statusLabel}</span>
                </div>
                {/* Only shown when the count is known (history needs the database) */}
                {threatCount !== null && (
                  <div
                    className="flex items-center gap-1 phish-card px-3 py-1"
                    title="High-risk and critical results among your own scans"
                  >
                    <AlertTriangle className="w-4 h-4 status-warning" aria-hidden="true" />
                    <span className="text-sm font-medium">
                      {threatCount}{' '}
                      <span className="hidden sm:inline">high-risk in your scans</span>
                      <span className="sm:hidden">high-risk</span>
                    </span>
                  </div>
                )}
              </div>

              <Button
                variant="ghost"
                size="icon"
                onClick={toggleDarkMode}
                className="security-button hover:bg-purple-500/10"
                aria-label={
                  mounted ? (resolvedTheme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme') : 'Toggle theme'
                }
              >
                {mounted ? (
                  resolvedTheme === 'dark' ? (
                    <Sun className="w-4 h-4 text-yellow-500" aria-hidden="true" />
                  ) : (
                    <Moon className="w-4 h-4 text-blue-500" aria-hidden="true" />
                  )
                ) : (
                  <span className="w-4 h-4" aria-hidden="true" />
                )}
              </Button>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="container mx-auto w-full flex-1 px-4 py-6">
        {status === 'degraded' && (
          <Alert className="mb-6 border-yellow-300 bg-yellow-50 dark:border-yellow-800 dark:bg-yellow-950/20">
            <AlertTriangle className="h-4 w-4 text-yellow-600" aria-hidden="true" />
            <AlertDescription className="text-yellow-800 dark:text-yellow-200">
              Scanning works, but scan history, statistics and settings are unavailable right now, so results won&apos;t be saved.
            </AlertDescription>
          </Alert>
        )}

        {status === 'offline' && (
          <Alert className="mb-6 border-red-300 bg-red-50 dark:border-red-800 dark:bg-red-950/20">
            <XCircle className="h-4 w-4 text-red-600" aria-hidden="true" />
            <AlertDescription className="text-red-800 dark:text-red-200">
              <span>
                <strong>Can&apos;t reach the PhishGuard scanner.</strong> Scans won&apos;t work until it&apos;s back —
                we never show guessed results in its place.
              </span>
              <Button size="sm" variant="outline" className="mt-2 w-fit" onClick={() => checkSystem()}>
                Check again
              </Button>
            </AlertDescription>
          </Alert>
        )}

        <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
          <TabsList className="grid w-full grid-cols-5 mb-6 bg-card/80 backdrop-blur-sm p-1 rounded-xl shadow-lg h-auto">
            <TabsTrigger value="dashboard" className="tabs-trigger-enhanced flex items-center gap-2 rounded-lg">
              <Shield className="w-4 h-4" aria-hidden="true" />
              <span className="hidden sm:inline">Dashboard</span>
              <span className="sr-only sm:hidden">Dashboard</span>
            </TabsTrigger>
            <TabsTrigger value="scan" className="tabs-trigger-enhanced flex items-center gap-2 rounded-lg">
              <Scan className="w-4 h-4" aria-hidden="true" />
              <span className="hidden sm:inline">Scan</span>
              <span className="sr-only sm:hidden">Scan</span>
            </TabsTrigger>
            <TabsTrigger value="history" className="tabs-trigger-enhanced flex items-center gap-2 rounded-lg">
              <History className="w-4 h-4" aria-hidden="true" />
              <span className="hidden sm:inline">History</span>
              <span className="sr-only sm:hidden">History</span>
            </TabsTrigger>
            <TabsTrigger value="ai-assistant" className="tabs-trigger-enhanced flex items-center gap-2 rounded-lg">
              <Bot className="w-4 h-4" aria-hidden="true" />
              <span className="hidden sm:inline">AI Assistant</span>
              <span className="sr-only sm:hidden">AI Assistant</span>
            </TabsTrigger>
            <TabsTrigger value="settings" className="tabs-trigger-enhanced flex items-center gap-2 rounded-lg">
              <SettingsIcon className="w-4 h-4" aria-hidden="true" />
              <span className="hidden sm:inline">Settings</span>
              <span className="sr-only sm:hidden">Settings</span>
            </TabsTrigger>
          </TabsList>

          <TabsContent value="dashboard" className="animate-in fade-in-50 duration-500">
            <Dashboard backendService={BackendService} />
          </TabsContent>

          {/* forceMount keeps scan results and chat history when switching tabs */}
          <TabsContent value="scan" forceMount className="data-[state=inactive]:hidden">
            <ScanInterface backendService={BackendService} onScanComplete={() => void refreshStats()} />
          </TabsContent>

          <TabsContent value="history" className="animate-in fade-in-50 duration-500">
            <ScanHistory backendService={BackendService} />
          </TabsContent>

          <TabsContent value="ai-assistant" forceMount className="data-[state=inactive]:hidden">
            <AIChatbot />
          </TabsContent>

          <TabsContent value="settings" className="animate-in fade-in-50 duration-500">
            <Settings backendService={BackendService} />
          </TabsContent>
        </Tabs>
      </main>

      {/* Footer */}
      <footer className="border-t bg-card/80 backdrop-blur-sm border-border/50 mt-12 shadow-lg">
        <div className="container mx-auto px-4 py-4">
          <div className="flex flex-col sm:flex-row gap-2 items-start sm:items-center justify-between text-sm text-muted-foreground">
            <p className="flex items-center gap-2">
              <Shield className="w-4 h-4 text-blue-500" aria-hidden="true" />© {new Date().getFullYear()} PhishGuard. In
              India, report cyber fraud at cybercrime.gov.in or call 1930.
            </p>
            <div className="flex flex-wrap items-center gap-4">
              <span className="flex items-center gap-1">
                <span
                  aria-hidden="true"
                  className={`w-2 h-2 rounded-full ${
                    status === 'online'
                      ? 'bg-green-500'
                      : status === 'degraded'
                        ? 'bg-yellow-500'
                        : status === 'offline'
                          ? 'bg-red-500'
                          : 'bg-gray-400'
                  }`}
                />
                {statusLabel}
              </span>
              <span aria-hidden="true">•</span>
              <span>
                Last checked: {mounted && lastChecked ? lastChecked.toLocaleTimeString() : '—'}
              </span>
            </div>
          </div>
        </div>
      </footer>
    </div>
  )
}
