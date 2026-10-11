import { useCallback, useEffect, useState, type FormEvent } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "./ui/card";
import { Badge } from "./ui/badge";
import { Button } from "./ui/button";
import { Input } from "./ui/input";
import { Label } from "./ui/label";
import { AlertCircle, Brain, CheckCircle, Database, Globe, Lock, RefreshCw, Shield, XCircle } from "lucide-react";
import {
  ApiError,
  BackendService,
  errorMessage,
  isAbortError,
  type HealthResponse,
  type IntegrationServiceStatus,
  type IntegrationTestResponse,
} from "@/utils/BackendService";

const SERVICE_INFO: Record<string, { name: string; envVar: string; kind: "shield" | "ai" | "db" }> = {
  virusTotal: { name: "VirusTotal", envVar: "VIRUSTOTAL_API_KEY", kind: "shield" },
  googleSafeBrowsing: { name: "Google Safe Browsing", envVar: "GOOGLE_SAFE_BROWSING_API_KEY", kind: "shield" },
  groq: { name: "Groq AI", envVar: "GROQ_API_KEY", kind: "ai" },
  openAI: { name: "Groq AI", envVar: "GROQ_API_KEY", kind: "ai" },
  database: { name: "PostgreSQL database", envVar: "DATABASE_URL", kind: "db" },
};

function serviceIcon(key: string) {
  const kind = SERVICE_INFO[key]?.kind;
  if (kind === "shield") return <Shield className="w-8 h-8" aria-hidden="true" />;
  if (kind === "ai") return <Brain className="w-8 h-8" aria-hidden="true" />;
  if (kind === "db") return <Database className="w-8 h-8" aria-hidden="true" />;
  return <Globe className="w-8 h-8" aria-hidden="true" />;
}

function StatusBadge({ service }: { service: IntegrationServiceStatus }) {
  if (!service.configured) {
    return (
      <Badge variant="outline" className="border-yellow-500/60 text-yellow-700 dark:text-yellow-400">
        <AlertCircle className="w-3 h-3" aria-hidden="true" />
        Not configured
      </Badge>
    );
  }
  return service.working ? (
    <Badge variant="outline" className="border-green-600/60 text-green-700 dark:text-green-400">
      <CheckCircle className="w-3 h-3" aria-hidden="true" />
      Operational
    </Badge>
  ) : (
    <Badge variant="destructive">
      <XCircle className="w-3 h-3" aria-hidden="true" />
      Failing
    </Badge>
  );
}

export function SystemStatus() {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [healthError, setHealthError] = useState<string | null>(null);
  const [healthLoading, setHealthLoading] = useState(true);

  const [adminToken, setAdminToken] = useState("");
  const [integrations, setIntegrations] = useState<IntegrationTestResponse | null>(null);
  const [integrationError, setIntegrationError] = useState<string | null>(null);
  const [integrationLoading, setIntegrationLoading] = useState(false);

  // State is only set inside promise callbacks (never synchronously in an effect).
  const loadHealth = useCallback(
    (signal?: AbortSignal) =>
      BackendService.getHealth(signal).then(
        (res) => {
          if (signal?.aborted) return;
          setHealth(res);
          setHealthError(null);
          setHealthLoading(false);
        },
        (error) => {
          if (isAbortError(error) || signal?.aborted) return;
          setHealth(null);
          setHealthError(errorMessage(error, "Couldn't reach the scanner."));
          setHealthLoading(false);
        }
      ),
    []
  );

  const refreshHealth = () => {
    setHealthLoading(true);
    loadHealth();
  };

  useEffect(() => {
    const controller = new AbortController();
    loadHealth(controller.signal);
    return () => controller.abort();
  }, [loadHealth]);

  const runIntegrationCheck = async (e: FormEvent) => {
    e.preventDefault();
    if (!adminToken.trim()) return;
    setIntegrationLoading(true);
    setIntegrationError(null);
    try {
      const res = await BackendService.testIntegrations(adminToken.trim());
      setIntegrations(res);
    } catch (error) {
      setIntegrations(null);
      if (error instanceof ApiError && error.status === 404) {
        setIntegrationError("Admin checks are disabled on this server (ADMIN_API_TOKEN is not set).");
      } else if (error instanceof ApiError && (error.status === 401 || error.status === 403)) {
        setIntegrationError("That admin token wasn't accepted.");
      } else {
        setIntegrationError(errorMessage(error, "The integration check failed."));
      }
    } finally {
      setIntegrationLoading(false);
    }
  };

  const services = integrations?.services ? Object.entries(integrations.services) : [];
  const unconfigured = services.filter(([, s]) => !s.configured);

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between gap-4">
            <div>
              <CardTitle>Scanner health</CardTitle>
              <CardDescription>Live result of the server health check</CardDescription>
            </div>
            <Button onClick={refreshHealth} disabled={healthLoading} variant="outline" size="sm">
              <RefreshCw className={`w-4 h-4 mr-2 ${healthLoading ? "animate-spin" : ""}`} aria-hidden="true" />
              Refresh
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          {healthError ? (
            <div className="rounded-lg border border-red-300 bg-red-50 px-4 py-3 text-red-800 dark:border-red-800 dark:bg-red-950/30 dark:text-red-200" role="alert">
              <strong>Scanner offline:</strong> {healthError}
            </div>
          ) : health ? (
            <dl className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              <div className="rounded-lg bg-muted/50 p-4">
                <dt className="text-xs text-muted-foreground">Status</dt>
                <dd className="text-lg font-semibold flex items-center gap-2">
                  {health.status === "degraded" ? (
                    <>
                      <AlertCircle className="w-4 h-4 text-yellow-600" aria-hidden="true" />
                      Degraded
                    </>
                  ) : (
                    <>
                      <CheckCircle className="w-4 h-4 text-green-600" aria-hidden="true" />
                      Online
                    </>
                  )}
                </dd>
              </div>
              <div className="rounded-lg bg-muted/50 p-4">
                <dt className="text-xs text-muted-foreground">Detection engines active</dt>
                <dd className="text-lg font-semibold">
                  {typeof health.models_available === "number"
                    ? health.models_available
                    : Array.isArray(health.models)
                      ? health.models.length
                      : "—"}
                </dd>
              </div>
              <div className="rounded-lg bg-muted/50 p-4">
                <dt className="text-xs text-muted-foreground">Database</dt>
                <dd className="text-lg font-semibold">
                  {health.database === "up" ? "Connected" : health.database === "down" ? "Down" : "—"}
                </dd>
              </div>
            </dl>
          ) : (
            <p className="text-sm text-muted-foreground" role="status">Checking…</p>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Lock className="w-4 h-4" aria-hidden="true" />
            External integrations (admin)
          </CardTitle>
          <CardDescription>
            Checking VirusTotal, Google Safe Browsing and Groq calls the real services and uses quota, so it needs the
            server&apos;s admin token. The token is only sent with this request and isn&apos;t stored.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          <form onSubmit={runIntegrationCheck} className="flex flex-col sm:flex-row gap-2 sm:items-end">
            <div className="flex-1 space-y-2">
              <Label htmlFor="admin-token">Admin token</Label>
              <Input
                id="admin-token"
                type="password"
                autoComplete="off"
                value={adminToken}
                onChange={(e) => setAdminToken(e.target.value)}
              />
            </div>
            <Button type="submit" variant="outline" disabled={!adminToken.trim() || integrationLoading}>
              <RefreshCw className={`w-4 h-4 mr-2 ${integrationLoading ? "animate-spin" : ""}`} aria-hidden="true" />
              Run check
            </Button>
          </form>

          {integrationError && (
            <div className="rounded-lg border border-red-300 bg-red-50 px-4 py-3 text-red-800 dark:border-red-800 dark:bg-red-950/30 dark:text-red-200" role="alert">
              {integrationError}
            </div>
          )}

          {integrations && (
            <div className="space-y-6">
              {integrations.summary && (
                <div className="bg-muted/50 rounded-lg p-4 flex items-center justify-between">
                  <div>
                    <h3 className="text-lg font-semibold">Overall</h3>
                    <p className="text-sm text-muted-foreground">{integrations.summary.status ?? "—"}</p>
                  </div>
                  <div className="text-right">
                    <div className="text-3xl font-bold">
                      {integrations.summary.working ?? "—"}/{integrations.summary.total ?? "—"}
                    </div>
                    <p className="text-xs text-muted-foreground">Services working</p>
                  </div>
                </div>
              )}

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {services.map(([key, service]) => (
                  <Card key={key} className="border-2">
                    <CardContent className="pt-6">
                      <div className="flex items-start gap-4">
                        <div
                          className={`p-3 rounded-lg ${
                            !service.configured
                              ? "bg-yellow-100 text-yellow-800 dark:bg-yellow-950/40 dark:text-yellow-300"
                              : service.working
                                ? "bg-green-100 text-green-800 dark:bg-green-950/40 dark:text-green-300"
                                : "bg-red-100 text-red-800 dark:bg-red-950/40 dark:text-red-300"
                          }`}
                        >
                          {serviceIcon(key)}
                        </div>
                        <div className="flex-1 min-w-0 space-y-2">
                          <h4 className="font-semibold truncate">{SERVICE_INFO[key]?.name ?? key}</h4>
                          <StatusBadge service={service} />
                          <p className="text-sm text-muted-foreground break-words">{service.message}</p>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                ))}
              </div>

              {unconfigured.length > 0 && (
                <div className="rounded-lg border border-yellow-300 bg-yellow-50 p-4 dark:border-yellow-800 dark:bg-yellow-950/20">
                  <p className="text-sm font-medium flex items-center gap-2 mb-2">
                    <AlertCircle className="w-4 h-4" aria-hidden="true" />
                    Configuration needed
                  </p>
                  <p className="text-sm text-muted-foreground mb-3">
                    Add these to the server&apos;s <code className="rounded bg-muted px-1.5 py-0.5">.env.local</code> and restart it:
                  </p>
                  <pre className="rounded-lg border bg-muted p-3 font-mono text-xs overflow-x-auto">
                    {Array.from(new Set(unconfigured.map(([key]) => SERVICE_INFO[key]?.envVar ?? key)))
                      .map((v) => `${v}=your_value_here`)
                      .join("\n")}
                  </pre>
                </div>
              )}

              {integrations.timestamp && (
                <p className="text-xs text-muted-foreground text-right">
                  Last checked: {new Date(integrations.timestamp).toLocaleString()}
                </p>
              )}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
