'use client'

import { useState, useEffect } from 'react'
import { useTheme } from 'next-themes'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Alert, AlertDescription } from '@/components/ui/alert'
import {
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from '@/components/ui/tabs'
import { Dashboard } from '@/components/Dashboard'
import { ScanInterface } from '@/components/ScanInterface'
import { ScanHistory } from '@/components/ScanHistory'
import { Settings } from '@/components/Settings'
import { AIChatbot } from '@/components/AIChatbot'
import { BackendService } from '@/utils/BackendService'
import {
  Shield,
  Scan,
  History,
  Settings as SettingsIcon,
  Bot,
  Bell,
  Moon,
  Sun,
  AlertTriangle,
  CheckCircle,
  Info,
} from 'lucide-react'

export default function Home() {
  const [activeTab, setActiveTab] = useState('dashboard')
  const { theme, setTheme } = useTheme()
  const [mounted, setMounted] = useState(false)
  const [systemStats, setSystemStats] = useState({
    online: false,
    activeThreats: 0,
    modelsActive: 0,
    lastUpdate: null as string | null,
  })

  const toggleDarkMode = () => {
    setTheme(theme === 'dark' ? 'light' : 'dark')
  }

  useEffect(() => {
    setMounted(true)
  }, [])

  useEffect(() => {
    // Initialize backend connection and load system stats
    const initializeSystem = async () => {
      try {
        console.log('Initializing system...')

        const healthCheck = await BackendService.getHealth()
        console.log('Health check result:', healthCheck)

        if (healthCheck.success) {
          setSystemStats((prev) => ({
            ...prev,
            online: true,
            modelsActive: healthCheck.models?.length || 4,
            lastUpdate: new Date().toISOString(),
          }))

          try {
            const stats = await BackendService.getStats()
            if (stats.success) {
              setSystemStats((prev) => ({
                ...prev,
                activeThreats: stats.stats.threats_detected || 0,
              }))
            }
          } catch (statsError) {
            console.warn('Stats loading failed, using defaults:', statsError)
          }
        } else {
          setSystemStats((prev) => ({
            ...prev,
            online: false,
            modelsActive: 4,
            activeThreats: 0,
            lastUpdate: new Date().toISOString(),
          }))
        }
      } catch (error) {
        console.error('Failed to initialize system:', error)
        setSystemStats((prev) => ({
          ...prev,
          online: false,
          modelsActive: 4,
          activeThreats: 0,
          lastUpdate: new Date().toISOString(),
        }))
      }
    }

    initializeSystem()
    const interval = setInterval(initializeSystem, 60000)
    return () => clearInterval(interval)
  }, [])

  if (!mounted) {
    return null
  }

  return (
    <div className="min-h-screen cyber-grid bg-gradient-to-br from-slate-50 to-slate-100 dark:from-slate-950 dark:to-slate-900">
      {/* Header */}
      <header className="border-b bg-card/80 backdrop-blur-sm border-border/50 shadow-lg">
        <div className="container mx-auto px-4 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="flex items-center gap-2">
                <Shield className="w-8 h-8 text-blue-500 shield-glow animate-pulse-soft" />
                <h1 className="text-xl font-bold neon-text">PhishGuard</h1>
              </div>
              <Badge
                variant="secondary"
                className="bg-gradient-to-r from-blue-500 to-purple-600 text-white animate-shimmer"
              >
                v2.1.0
              </Badge>
              <Badge
                variant="outline"
                className="flex items-center gap-1 gradient-border ai-assistant-glow"
              >
                <Bot className="w-3 h-3 text-purple-500" />
                <span className="relative z-10">AI-Powered</span>
              </Badge>
            </div>

            <div className="flex items-center gap-2">
              <div className="flex items-center gap-4 mr-4">
                <div className="flex items-center gap-1 phish-card px-3 py-1">
                  <CheckCircle
                    className={`w-4 h-4 ${
                      systemStats.online ? 'status-online' : 'text-gray-400'
                    } animate-pulse-soft`}
                  />
                  <span className="text-sm font-medium">
                    {systemStats.online ? 'Backend Online' : 'Local Mode'}
                  </span>
                </div>
                <div className="flex items-center gap-1 phish-card px-3 py-1">
                  <AlertTriangle className="w-4 h-4 status-warning animate-glow" />
                  <span className="text-sm font-medium">
                    {systemStats.activeThreats} Active Threats
                  </span>
                </div>
              </div>

              <Button
                variant="ghost"
                size="icon"
                className="security-button hover:bg-blue-500/10"
              >
                <Bell className="w-4 h-4" />
              </Button>
              <Button
                variant="ghost"
                size="icon"
                onClick={toggleDarkMode}
                className="security-button hover:bg-purple-500/10"
              >
                {theme === 'dark' ? (
                  <Sun className="w-4 h-4 text-yellow-500" />
                ) : (
                  <Moon className="w-4 h-4 text-blue-500" />
                )}
              </Button>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <div className="container mx-auto px-4 py-6">
        {!systemStats.online && (
          <Alert className="mb-6 border-yellow-200 bg-yellow-50 dark:border-yellow-800 dark:bg-yellow-950/20">
            <Info className="h-4 w-4 text-yellow-600" />
            <AlertDescription className="text-yellow-800 dark:text-yellow-200">
              <strong>Local Mode Active:</strong> Backend services are currently
              unavailable. PhishGuard is operating with local threat analysis
              engines. All scanning features remain fully functional.
            </AlertDescription>
          </Alert>
        )}

        <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
          <TabsList className="grid w-full grid-cols-5 mb-6 bg-card/80 backdrop-blur-sm p-1 rounded-xl shadow-lg">
            <TabsTrigger
              value="dashboard"
              className="tabs-trigger-enhanced flex items-center gap-2 rounded-lg"
            >
              <Shield className="w-4 h-4" />
              Dashboard
            </TabsTrigger>
            <TabsTrigger
              value="scan"
              className="tabs-trigger-enhanced flex items-center gap-2 rounded-lg"
            >
              <Scan className="w-4 h-4" />
              Scan
            </TabsTrigger>
            <TabsTrigger
              value="history"
              className="tabs-trigger-enhanced flex items-center gap-2 rounded-lg"
            >
              <History className="w-4 h-4" />
              History
            </TabsTrigger>
            <TabsTrigger
              value="ai-assistant"
              className="tabs-trigger-enhanced flex items-center gap-2 rounded-lg"
            >
              <Bot className="w-4 h-4" />
              AI Assistant
            </TabsTrigger>
            <TabsTrigger
              value="settings"
              className="tabs-trigger-enhanced flex items-center gap-2 rounded-lg"
            >
              <SettingsIcon className="w-4 h-4" />
              Settings
            </TabsTrigger>
          </TabsList>

          <TabsContent
            value="dashboard"
            className="animate-in fade-in-50 duration-500"
          >
            <Dashboard backendService={BackendService} />
          </TabsContent>

          <TabsContent value="scan" className="animate-in fade-in-50 duration-500">
            <ScanInterface backendService={BackendService} />
          </TabsContent>

          <TabsContent
            value="history"
            className="animate-in fade-in-50 duration-500"
          >
            <ScanHistory backendService={BackendService} />
          </TabsContent>

          <TabsContent
            value="ai-assistant"
            className="animate-in fade-in-50 duration-500"
          >
            <AIChatbot />
          </TabsContent>

          <TabsContent
            value="settings"
            className="animate-in fade-in-50 duration-500"
          >
            <Settings backendService={BackendService} />
          </TabsContent>
        </Tabs>
      </div>

      {/* Footer */}
      <footer className="border-t bg-card/80 backdrop-blur-sm border-border/50 mt-12 shadow-lg">
        <div className="container mx-auto px-4 py-4">
          <div className="flex items-center justify-between text-sm text-muted-foreground">
            <p className="flex items-center gap-2">
              <Shield className="w-4 h-4 text-blue-500" />© 2024 PhishGuard.
              Protecting your digital environment with AI.
            </p>
            <div className="flex items-center gap-4">
              <span className="flex items-center gap-1">
                <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
                Last Update: {systemStats.lastUpdate ? new Date(systemStats.lastUpdate).toLocaleTimeString() : 'N/A'}
              </span>
              <span>•</span>
              <span className="flex items-center gap-1">
                <div className="w-2 h-2 bg-red-500 rounded-full animate-pulse"></div>
                Active Threats: {systemStats.activeThreats}
              </span>
              <span>•</span>
              <span className="flex items-center gap-1">
                <div className={`w-2 h-2 ${systemStats.online ? 'bg-purple-500' : 'bg-gray-400'} rounded-full animate-pulse`}></div>
                AI Assistant {systemStats.online ? 'Online' : 'Offline'}
              </span>
            </div>
          </div>
        </div>
      </footer>
    </div>
  )
}
