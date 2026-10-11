import { useCallback, useEffect, useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "./ui/card";
import { Button } from "./ui/button";
import { Label } from "./ui/label";
import { Switch } from "./ui/switch";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "./ui/select";
import { Slider } from "./ui/slider";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "./ui/tabs";
import { Separator } from "./ui/separator";
import { Alert, AlertDescription } from "./ui/alert";
import { AlertTriangle, Loader2, RotateCcw, Save, Shield } from "lucide-react";
import { SystemStatus } from "./SystemStatus";
import { toast } from "sonner";
import {
  BackendService as DefaultBackendService,
  errorMessage,
  isAbortError,
  type BackendServiceType,
  type UserSettings,
} from "@/utils/BackendService";

interface SettingsProps {
  backendService?: BackendServiceType;
}

const DEFAULTS: UserSettings = {
  realTimeScanning: true,
  autoQuarantine: false,
  detectionSensitivity: 50,
  defaultAction: "warn",
  emailAlerts: true,
  desktopAlerts: true,
  dailySummary: false,
  dataRetentionDays: 30,
  securityLevel: "medium",
};

const SECURITY_LEVELS = [
  { value: "low", label: "Basic" },
  { value: "medium", label: "Standard" },
  { value: "high", label: "High" },
  { value: "paranoid", label: "Maximum" },
];

const RETENTION_OPTIONS = ["30", "90", "180", "365"];

function merge(partial: Partial<UserSettings>): UserSettings {
  const s = { ...DEFAULTS };
  if (typeof partial.realTimeScanning === "boolean") s.realTimeScanning = partial.realTimeScanning;
  if (typeof partial.autoQuarantine === "boolean") s.autoQuarantine = partial.autoQuarantine;
  if (typeof partial.detectionSensitivity === "number") s.detectionSensitivity = partial.detectionSensitivity;
  if (typeof partial.defaultAction === "string") s.defaultAction = partial.defaultAction;
  if (typeof partial.emailAlerts === "boolean") s.emailAlerts = partial.emailAlerts;
  if (typeof partial.desktopAlerts === "boolean") s.desktopAlerts = partial.desktopAlerts;
  if (typeof partial.dailySummary === "boolean") s.dailySummary = partial.dailySummary;
  if (typeof partial.dataRetentionDays === "number") s.dataRetentionDays = partial.dataRetentionDays;
  if (typeof partial.securityLevel === "string") s.securityLevel = partial.securityLevel;
  return s;
}

function SettingRow({
  id,
  label,
  description,
  checked,
  onChange,
}: {
  id: string;
  label: string;
  description: string;
  checked: boolean;
  onChange: (v: boolean) => void;
}) {
  return (
    <div className="flex items-center justify-between gap-4">
      <div className="space-y-0.5">
        <Label htmlFor={id}>{label}</Label>
        <p className="text-sm text-muted-foreground">{description}</p>
      </div>
      <Switch id={id} checked={checked} onCheckedChange={onChange} />
    </div>
  );
}

export function Settings({ backendService = DefaultBackendService }: SettingsProps) {
  const [settings, setSettings] = useState<UserSettings>(DEFAULTS);
  const [loaded, setLoaded] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  const update = <K extends keyof UserSettings>(key: K, value: UserSettings[K]) =>
    setSettings((prev) => ({ ...prev, [key]: value }));

  // State is only set inside promise callbacks (never synchronously in an effect).
  const load = useCallback(
    (signal?: AbortSignal) =>
      backendService.getSettings(signal).then(
        (res) => {
          if (signal?.aborted) return;
          setSettings(merge(res.settings));
          setLoadError(null);
          setLoaded(true);
        },
        (error) => {
          if (isAbortError(error) || signal?.aborted) return;
          setLoadError(errorMessage(error, "Couldn't load your settings."));
        }
      ),
    [backendService]
  );

  useEffect(() => {
    const controller = new AbortController();
    load(controller.signal);
    return () => controller.abort();
  }, [load]);

  const handleSave = async () => {
    setSaving(true);
    try {
      const res = await backendService.saveSettings(settings);
      if (res.settings) setSettings(merge(res.settings));
      toast.success("Settings saved");
    } catch (error) {
      toast.error(errorMessage(error, "Couldn't save settings — try again."));
    } finally {
      setSaving(false);
    }
  };

  const sensitivity = settings.detectionSensitivity;

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle>Settings</CardTitle>
          <CardDescription>
            Your preferences are saved for this browser. They aren&apos;t acted on yet: every scan runs all checks,
            and alerts, auto-quarantine and data-retention clean-up aren&apos;t automated.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {loadError && (
            <Alert variant="destructive" className="mb-4">
              <AlertTriangle className="h-4 w-4" aria-hidden="true" />
              <AlertDescription>
                <span>{loadError} Saving is disabled until your current settings load, so nothing gets overwritten.</span>
                <Button size="sm" variant="outline" className="mt-2 w-fit" onClick={() => load()}>
                  <RotateCcw className="w-4 h-4 mr-2" aria-hidden="true" />
                  Retry
                </Button>
              </AlertDescription>
            </Alert>
          )}

          <Tabs defaultValue="system" className="w-full">
            <TabsList className="grid w-full grid-cols-2 sm:grid-cols-4 h-auto">
              <TabsTrigger value="system">System status</TabsTrigger>
              <TabsTrigger value="detection">Detection</TabsTrigger>
              <TabsTrigger value="notifications">Notifications</TabsTrigger>
              <TabsTrigger value="security">Data &amp; security</TabsTrigger>
            </TabsList>

            <TabsContent value="system" className="space-y-6 mt-6">
              <SystemStatus />
            </TabsContent>

            <TabsContent value="detection" className="space-y-6 mt-6">
              <fieldset disabled={!loaded} className="space-y-4 disabled:opacity-60">
                <SettingRow
                  id="setting-realtime"
                  label="Real-time scanning"
                  description="Preference for scanning content as soon as it's received"
                  checked={settings.realTimeScanning}
                  onChange={(v) => update("realTimeScanning", v)}
                />
                <Separator />
                <SettingRow
                  id="setting-quarantine"
                  label="Auto-quarantine threats"
                  description="Preference for isolating high-risk content automatically"
                  checked={settings.autoQuarantine}
                  onChange={(v) => update("autoQuarantine", v)}
                />
                <Separator />
                <div className="space-y-3">
                  <Label id="sensitivity-label">Detection sensitivity</Label>
                  <div className="px-3">
                    <Slider
                      aria-labelledby="sensitivity-label"
                      value={[sensitivity]}
                      onValueChange={(v) => update("detectionSensitivity", v[0] ?? sensitivity)}
                      max={100}
                      min={0}
                      step={5}
                      className="w-full"
                    />
                    <div className="flex justify-between text-sm text-muted-foreground mt-1" aria-hidden="true">
                      <span>Low</span>
                      <span>Medium</span>
                      <span>High</span>
                    </div>
                  </div>
                  <p className="text-sm text-muted-foreground">
                    Current sensitivity: {sensitivity}% — {sensitivity < 40 ? "Low" : sensitivity < 70 ? "Medium" : "High"}
                  </p>
                </div>
                <Separator />
                <div className="space-y-3">
                  <Label htmlFor="setting-default-action">Default action for high-risk content</Label>
                  <Select value={settings.defaultAction} onValueChange={(v) => update("defaultAction", v)} disabled={!loaded}>
                    <SelectTrigger id="setting-default-action">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="block">Block immediately</SelectItem>
                      <SelectItem value="quarantine">Quarantine for review</SelectItem>
                      <SelectItem value="warn">Warn me only</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </fieldset>
            </TabsContent>

            <TabsContent value="notifications" className="space-y-6 mt-6">
              <fieldset disabled={!loaded} className="space-y-4 disabled:opacity-60">
                <SettingRow
                  id="setting-email-alerts"
                  label="Email alerts"
                  description="Get an email when a scan is rated high-risk or critical"
                  checked={settings.emailAlerts}
                  onChange={(v) => update("emailAlerts", v)}
                />
                <Separator />
                <SettingRow
                  id="setting-desktop-alerts"
                  label="Desktop alerts"
                  description="Show a browser notification for high-risk results"
                  checked={settings.desktopAlerts}
                  onChange={(v) => update("desktopAlerts", v)}
                />
                <Separator />
                <SettingRow
                  id="setting-daily-summary"
                  label="Daily summary"
                  description="A once-a-day summary of your scans"
                  checked={settings.dailySummary}
                  onChange={(v) => update("dailySummary", v)}
                />
              </fieldset>
            </TabsContent>

            <TabsContent value="security" className="space-y-6 mt-6">
              <fieldset disabled={!loaded} className="space-y-4 disabled:opacity-60">
                <div className="space-y-3">
                  <Label htmlFor="setting-retention">Data retention period</Label>
                  <Select
                    value={String(settings.dataRetentionDays)}
                    onValueChange={(v) => update("dataRetentionDays", parseInt(v, 10))}
                    disabled={!loaded}
                  >
                    <SelectTrigger id="setting-retention">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {Array.from(new Set([...RETENTION_OPTIONS, String(settings.dataRetentionDays)])).map((d) => (
                        <SelectItem key={d} value={d}>
                          {d === "365" ? "1 year" : `${d} days`}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <p className="text-sm text-muted-foreground">How long to keep your scan history</p>
                </div>

                <Separator />

                <div className="space-y-3">
                  <Label id="security-level-label">Security level</Label>
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-2" role="group" aria-labelledby="security-level-label">
                    {SECURITY_LEVELS.map((lvl) => {
                      const active = settings.securityLevel === lvl.value;
                      return (
                        <Button
                          key={lvl.value}
                          type="button"
                          variant={active ? "default" : "outline"}
                          aria-pressed={active}
                          className="justify-start"
                          onClick={() => update("securityLevel", lvl.value)}
                        >
                          <Shield className="w-4 h-4 mr-2" aria-hidden="true" />
                          {lvl.label}
                        </Button>
                      );
                    })}
                  </div>
                </div>
              </fieldset>
            </TabsContent>
          </Tabs>

          <div className="flex justify-end pt-6">
            <Button onClick={handleSave} disabled={saving || !loaded} className="flex items-center gap-2">
              {saving ? <Loader2 className="w-4 h-4 animate-spin" aria-hidden="true" /> : <Save className="w-4 h-4" aria-hidden="true" />}
              {saving ? "Saving…" : "Save settings"}
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
