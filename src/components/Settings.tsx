import { useState, useEffect } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "./ui/card";
import { Button } from "./ui/button";
import { Input } from "./ui/input";
import { Label } from "./ui/label";
import { Switch } from "./ui/switch";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "./ui/select";
import { Slider } from "./ui/slider";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "./ui/tabs";
import { Badge } from "./ui/badge";
import { Separator } from "./ui/separator";
import { Shield, Save, Loader2 } from "lucide-react";
import { SystemStatus } from "./SystemStatus";
import { toast } from "sonner";

interface SettingsProps {
  backendService: any;
}

export function Settings({ backendService }: SettingsProps) {
  const [notifications, setNotifications] = useState(true);
  const [realTimeScanning, setRealTimeScanning] = useState(true);
  const [autoQuarantine, setAutoQuarantine] = useState(false);
  const [sensitivityLevel, setSensitivityLevel] = useState([75]);
  const [apiEndpoint, setApiEndpoint] = useState("");
  const [threatDbUpdates, setThreatDbUpdates] = useState(true);
  const [defaultAction, setDefaultAction] = useState("warn");
  const [securityLevel, setSecurityLevel] = useState("medium");
  const [dataRetention, setDataRetention] = useState("90");
  const [saving, setSaving] = useState(false);

  // Load settings on mount
  useEffect(() => {
    const loadSettings = async () => {
      try {
        const response = await backendService.getSettings();
        if (response.success && response.settings) {
          const s = response.settings;
          setRealTimeScanning(s.realTimeScanning ?? true);
          setAutoQuarantine(s.autoQuarantine ?? false);
          setSensitivityLevel([s.detectionSensitivity ?? 75]);
          setDefaultAction(s.defaultAction ?? 'warn');
          setNotifications(s.emailAlerts ?? true);
          setThreatDbUpdates(s.autoUpdate ?? true);
          setApiEndpoint(s.apiEndpoint ?? '');
          setSecurityLevel(s.securityLevel ?? 'medium');
          setDataRetention(String(s.dataRetentionDays ?? 90));
        }
      } catch (error) {
        console.error('Failed to load settings:', error);
      }
    };
    loadSettings();
  }, [backendService]);

  const handleSaveSettings = async () => {
    setSaving(true);
    try {
      const result = await backendService.saveSettings({
        realTimeScanning,
        autoQuarantine,
        detectionSensitivity: sensitivityLevel[0],
        defaultAction,
        emailAlerts: notifications,
        desktopAlerts: notifications,
        dailySummary: false,
        autoUpdate: threatDbUpdates,
        apiEndpoint,
        securityLevel,
        dataRetentionDays: parseInt(dataRetention),
      });
      if (result.success) {
        toast.success('Settings saved successfully');
      } else {
        toast.error('Failed to save settings');
      }
    } catch {
      toast.error('Failed to save settings');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle>Settings</CardTitle>
          <CardDescription>
            Configure your phishing detection preferences and system behavior
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Tabs defaultValue="system" className="w-full">
            <TabsList className="grid w-full grid-cols-5">
              <TabsTrigger value="system">System Status</TabsTrigger>
              <TabsTrigger value="detection">Detection</TabsTrigger>
              <TabsTrigger value="notifications">Notifications</TabsTrigger>
              <TabsTrigger value="api">API</TabsTrigger>
              <TabsTrigger value="security">Security</TabsTrigger>
            </TabsList>

            <TabsContent value="system" className="space-y-6 mt-6">
              <SystemStatus />
            </TabsContent>

            <TabsContent value="detection" className="space-y-6 mt-6">
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <div className="space-y-0.5">
                    <Label>Real-time Scanning</Label>
                    <p className="text-sm text-muted-foreground">
                      Automatically scan content as it's received
                    </p>
                  </div>
                  <Switch
                    checked={realTimeScanning}
                    onCheckedChange={setRealTimeScanning}
                  />
                </div>

                <Separator />

                <div className="flex items-center justify-between">
                  <div className="space-y-0.5">
                    <Label>Auto-quarantine Threats</Label>
                    <p className="text-sm text-muted-foreground">
                      Automatically isolate high-risk content
                    </p>
                  </div>
                  <Switch
                    checked={autoQuarantine}
                    onCheckedChange={setAutoQuarantine}
                  />
                </div>

                <Separator />

                <div className="space-y-3">
                  <Label>Detection Sensitivity</Label>
                  <div className="px-3">
                    <Slider
                      value={sensitivityLevel}
                      onValueChange={setSensitivityLevel}
                      max={100}
                      min={0}
                      step={5}
                      className="w-full"
                    />
                    <div className="flex justify-between text-sm text-muted-foreground mt-1">
                      <span>Low</span>
                      <span>Medium</span>
                      <span>High</span>
                    </div>
                  </div>
                  <p className="text-sm text-muted-foreground">
                    Current sensitivity: {sensitivityLevel[0]}% - {
                      sensitivityLevel[0] < 40 ? 'Low' :
                      sensitivityLevel[0] < 70 ? 'Medium' : 'High'
                    }
                  </p>
                </div>

                <Separator />

                <div className="space-y-3">
                  <Label>Default Action for High-Risk Content</Label>
                  <Select defaultValue="quarantine">
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="block">Block immediately</SelectItem>
                      <SelectItem value="quarantine">Quarantine for review</SelectItem>
                      <SelectItem value="warn">Warn user only</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>
            </TabsContent>

            <TabsContent value="notifications" className="space-y-6 mt-6">
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <div className="space-y-0.5">
                    <Label>Enable Notifications</Label>
                    <p className="text-sm text-muted-foreground">
                      Receive alerts about threats and system status
                    </p>
                  </div>
                  <Switch
                    checked={notifications}
                    onCheckedChange={setNotifications}
                  />
                </div>

                <Separator />

                <div className="space-y-3">
                  <Label>Notification Types</Label>
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-sm">High-risk threats detected</span>
                      <Switch defaultChecked />
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm">Daily security summaries</span>
                      <Switch defaultChecked />
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm">System updates available</span>
                      <Switch />
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm">Database updates completed</span>
                      <Switch />
                    </div>
                  </div>
                </div>

                <Separator />

                <div className="space-y-3">
                  <Label htmlFor="email-notifications">Notification Email</Label>
                  <Input
                    id="email-notifications"
                    type="email"
                    placeholder="admin@company.com"
                    defaultValue="admin@company.com"
                  />
                </div>
              </div>
            </TabsContent>

            <TabsContent value="api" className="space-y-6 mt-6">
              <div className="space-y-4">
                <div className="space-y-3">
                  <Label htmlFor="api-endpoint">API Endpoint</Label>
                  <Input
                    id="api-endpoint"
                    value={apiEndpoint}
                    onChange={(e) => setApiEndpoint(e.target.value)}
                  />
                  <p className="text-sm text-muted-foreground">
                    Base URL for the phishing detection API
                  </p>
                </div>

                <Separator />

                <div className="space-y-3">
                  <Label htmlFor="api-key">API Key</Label>
                  <div className="flex gap-2">
                    <Input
                      id="api-key"
                      type="password"
                      placeholder="Enter your API key"
                      defaultValue="pk_live_example_key_123"
                    />
                    <Button variant="outline">Test</Button>
                  </div>
                </div>

                <Separator />

                <div className="space-y-3">
                  <Label>API Rate Limiting</Label>
                  <Select defaultValue="standard">
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="basic">Basic (10 req/min)</SelectItem>
                      <SelectItem value="standard">Standard (60 req/min)</SelectItem>
                      <SelectItem value="premium">Premium (300 req/min)</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                <Separator />

                <div className="space-y-3">
                  <Label>Current Usage</Label>
                  <div className="grid grid-cols-2 gap-4">
                    <Card>
                      <CardContent className="pt-4">
                        <div className="text-2xl font-bold">2,847</div>
                        <p className="text-sm text-muted-foreground">Requests today</p>
                      </CardContent>
                    </Card>
                    <Card>
                      <CardContent className="pt-4">
                        <div className="text-2xl font-bold">847MB</div>
                        <p className="text-sm text-muted-foreground">Data processed</p>
                      </CardContent>
                    </Card>
                  </div>
                </div>
              </div>
            </TabsContent>

            <TabsContent value="security" className="space-y-6 mt-6">
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <div className="space-y-0.5">
                    <Label>Automatic Threat Database Updates</Label>
                    <p className="text-sm text-muted-foreground">
                      Keep threat signatures up to date
                    </p>
                  </div>
                  <Switch
                    checked={threatDbUpdates}
                    onCheckedChange={setThreatDbUpdates}
                  />
                </div>

                <Separator />

                <div className="space-y-3">
                  <Label>Data Retention Period</Label>
                  <Select defaultValue="90">
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="30">30 days</SelectItem>
                      <SelectItem value="90">90 days</SelectItem>
                      <SelectItem value="180">180 days</SelectItem>
                      <SelectItem value="365">1 year</SelectItem>
                    </SelectContent>
                  </Select>
                  <p className="text-sm text-muted-foreground">
                    How long to keep scan history and logs
                  </p>
                </div>

                <Separator />

                <div className="space-y-3">
                  <Label>Security Level</Label>
                  <div className="grid grid-cols-3 gap-2">
                    <Button variant="outline" className="justify-start">
                      <Shield className="w-4 h-4 mr-2" />
                      Basic
                    </Button>
                    <Button variant="default" className="justify-start">
                      <Shield className="w-4 h-4 mr-2" />
                      Standard
                    </Button>
                    <Button variant="outline" className="justify-start">
                      <Shield className="w-4 h-4 mr-2" />
                      Maximum
                    </Button>
                  </div>
                </div>

                <Separator />

                <div className="space-y-3">
                  <Label>Trusted Domains</Label>
                  <div className="flex flex-wrap gap-2 mb-2">
                    <Badge variant="secondary">company.com</Badge>
                    <Badge variant="secondary">secure-partner.com</Badge>
                    <Badge variant="secondary">trusted-vendor.org</Badge>
                  </div>
                  <div className="flex gap-2">
                    <Input placeholder="Add trusted domain..." />
                    <Button variant="outline">Add</Button>
                  </div>
                </div>
              </div>
            </TabsContent>
          </Tabs>

          <div className="flex justify-end pt-6">
            <Button onClick={handleSaveSettings} disabled={saving} className="flex items-center gap-2">
              {saving ? <Loader2 className="w-4 h-4 animate-spin" /> : <Save className="w-4 h-4" />}
              {saving ? 'Saving...' : 'Save Settings'}
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}