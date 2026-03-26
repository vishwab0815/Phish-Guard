import { useState, useEffect } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "./ui/card";
import { Badge } from "./ui/badge";
import { Button } from "./ui/button";
import { CheckCircle, XCircle, AlertCircle, RefreshCw, Database, Shield, Brain, Globe } from "lucide-react";

interface ServiceStatus {
  configured: boolean;
  working: boolean;
  message: string;
}

interface APITestResults {
  summary: {
    working: number;
    total: number;
    status: string;
  };
  services: {
    virusTotal: ServiceStatus & { testUrl: string };
    googleSafeBrowsing: ServiceStatus & { testUrl: string };
    openAI: ServiceStatus & { model: string };
    database: ServiceStatus;
  };
  timestamp: string;
}

export function SystemStatus() {
  const [status, setStatus] = useState<APITestResults | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const testAPIs = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await fetch('/api/test-apis');
      const data = await response.json();

      if (data.success) {
        setStatus(data);
      } else {
        setError('Failed to test APIs');
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unknown error');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    testAPIs();
  }, []);

  const getStatusIcon = (service: ServiceStatus) => {
    if (!service.configured) {
      return <AlertCircle className="w-5 h-5 text-yellow-500" />;
    }
    return service.working ?
      <CheckCircle className="w-5 h-5 text-green-500" /> :
      <XCircle className="w-5 h-5 text-red-500" />;
  };

  const getStatusBadge = (service: ServiceStatus) => {
    if (!service.configured) {
      return <Badge variant="outline" className="bg-yellow-50">Not Configured</Badge>;
    }
    return service.working ?
      <Badge variant="outline" className="bg-green-50">Operational</Badge> :
      <Badge variant="destructive">Offline</Badge>;
  };

  const getServiceIcon = (serviceName: string) => {
    switch (serviceName) {
      case 'virusTotal':
      case 'googleSafeBrowsing':
        return <Shield className="w-8 h-8" />;
      case 'openAI':
        return <Brain className="w-8 h-8" />;
      case 'database':
        return <Database className="w-8 h-8" />;
      default:
        return <Globe className="w-8 h-8" />;
    }
  };

  const getServiceName = (key: string): string => {
    const names: Record<string, string> = {
      virusTotal: 'VirusTotal API',
      googleSafeBrowsing: 'Google Safe Browsing',
      openAI: 'OpenAI GPT-4',
      database: 'Neon PostgreSQL'
    };
    return names[key] || key;
  };

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>System Status</CardTitle>
              <CardDescription>
                Monitor external service integrations and API health
              </CardDescription>
            </div>
            <Button
              onClick={testAPIs}
              disabled={loading}
              variant="outline"
              size="sm"
            >
              <RefreshCw className={`w-4 h-4 mr-2 ${loading ? 'animate-spin' : ''}`} />
              Refresh
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          {error && (
            <div className="bg-red-50 border border-red-200 text-red-800 px-4 py-3 rounded-lg mb-4">
              <strong>Error:</strong> {error}
            </div>
          )}

          {status && (
            <div className="space-y-6">
              {/* Overall Status */}
              <div className="bg-muted/50 rounded-lg p-4">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="text-lg font-semibold">Overall Status</h3>
                    <p className="text-sm text-muted-foreground">{status.summary.status}</p>
                  </div>
                  <div className="text-right">
                    <div className="text-3xl font-bold">
                      {status.summary.working}/{status.summary.total}
                    </div>
                    <p className="text-xs text-muted-foreground">Services Online</p>
                  </div>
                </div>
              </div>

              {/* Individual Services */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {Object.entries(status.services).map(([key, service]) => (
                  <Card key={key} className="border-2">
                    <CardContent className="pt-6">
                      <div className="flex items-start gap-4">
                        <div className={`p-3 rounded-lg ${
                          !service.configured ? 'bg-yellow-100' :
                          service.working ? 'bg-green-100' : 'bg-red-100'
                        }`}>
                          {getServiceIcon(key)}
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center justify-between gap-2 mb-2">
                            <h4 className="font-semibold truncate">{getServiceName(key)}</h4>
                            {getStatusIcon(service)}
                          </div>
                          <div className="mb-2">
                            {getStatusBadge(service)}
                          </div>
                          <p className="text-sm text-muted-foreground break-words">
                            {service.message}
                          </p>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                ))}
              </div>

              {/* Configuration Instructions */}
              {Object.values(status.services).some(s => !s.configured) && (
                <Card className="border-yellow-200 bg-yellow-50">
                  <CardHeader>
                    <CardTitle className="text-sm flex items-center gap-2">
                      <AlertCircle className="w-4 h-4" />
                      Configuration Required
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <p className="text-sm text-muted-foreground mb-3">
                      Some services are not configured. Add the following to your <code className="bg-white px-2 py-1 rounded">.env.local</code> file:
                    </p>
                    <div className="bg-white p-4 rounded-lg border font-mono text-xs space-y-1">
                      {!status.services.virusTotal.configured && (
                        <div>VIRUSTOTAL_API_KEY=your_key_here</div>
                      )}
                      {!status.services.googleSafeBrowsing.configured && (
                        <div>GOOGLE_SAFE_BROWSING_API_KEY=your_key_here</div>
                      )}
                      {!status.services.openAI.configured && (
                        <div>OPENAI_API_KEY=your_key_here</div>
                      )}
                      {!status.services.database.configured && (
                        <div>DATABASE_URL=your_database_url_here</div>
                      )}
                    </div>
                    <p className="text-xs text-muted-foreground mt-3">
                      After adding keys, restart the development server with <code className="bg-white px-2 py-1 rounded">npm run dev</code>
                    </p>
                  </CardContent>
                </Card>
              )}

              <div className="text-xs text-muted-foreground text-right">
                Last checked: {new Date(status.timestamp).toLocaleString()}
              </div>
            </div>
          )}

          {loading && !status && (
            <div className="text-center py-12">
              <RefreshCw className="w-12 h-12 animate-spin mx-auto text-muted-foreground mb-4" />
              <p className="text-muted-foreground">Testing API integrations...</p>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
