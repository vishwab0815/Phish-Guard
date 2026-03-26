import { useState, useEffect } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "./ui/card";
import { Badge } from "./ui/badge";
import { Progress } from "./ui/progress";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "./ui/tooltip";
import { Shield, AlertTriangle, CheckCircle, Clock, Info, ExternalLink, Activity, Database } from "lucide-react";

interface ThreatStat {
  label: string;
  value: number;
  change: string;
  type: 'safe' | 'warning' | 'danger';
}

interface RecentScan {
  id: string;
  type: 'url' | 'email' | 'file' | 'message';
  content: string;
  threat_level: 'low' | 'medium' | 'high' | 'safe';
  timestamp: string;
  confidence: number;
  indicators: string[];
  recommendation: string;
  source?: string;
  detectedAt?: string;
}

interface DashboardProps {
  backendService: any;
}

export function Dashboard({ backendService }: DashboardProps) {
  const [threatStats, setThreatStats] = useState<ThreatStat[]>([
    { label: "Total Scans Today", value: 0, change: "+0%", type: 'safe' },
    { label: "Threats Detected", value: 0, change: "+0%", type: 'warning' },
    { label: "High Risk Items", value: 0, change: "+0%", type: 'danger' },
    { label: "Protection Score", value: 0, change: "+0%", type: 'safe' }
  ]);

  const [recentScans, setRecentScans] = useState<RecentScan[]>([]);
  const [models, setModels] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [systemHealth, setSystemHealth] = useState({ online: false, modelsActive: 0 });

  useEffect(() => {
    const loadDashboardData = async () => {
      try {
        setLoading(true);
        const userId = backendService.generateUserId();

        // Load system statistics
        const statsResponse = await backendService.getStats(userId);
        if (statsResponse.success) {
          const stats = statsResponse.stats;
          setThreatStats([
            { 
              label: "Total Scans Today", 
              value: stats.total_scans || 0, 
              change: stats.recent_activity > 0 && stats.total_scans > 0 ? `+${Math.round((stats.recent_activity / stats.total_scans) * 100)}%` : "+0%", 
              type: 'safe' 
            },
            { 
              label: "Threats Detected", 
              value: stats.threats_detected || 0, 
              change: stats.threats_detected > 0 ? "+5%" : "+0%", 
              type: 'warning' 
            },
            { 
              label: "High Risk Items", 
              value: stats.suspicious_items || 0, 
              change: "-2%", 
              type: 'danger' 
            },
            { 
              label: "Protection Score", 
              value: Math.round(((stats.safe_items || 0) / Math.max(stats.total_scans || 1, 1)) * 100), 
              change: "+1%", 
              type: 'safe' 
            }
          ]);
        }

        // Load recent scans
        const scansResponse = await backendService.getScans(userId);
        if (scansResponse.success) {
          const transformedScans = scansResponse.scans.slice(0, 4).map((scan: any) => ({
            id: scan.id,
            type: scan.type,
            content: scan.target,
            threat_level: scan.result.threat_level.toLowerCase(),
            timestamp: getRelativeTime(scan.timestamp),
            confidence: scan.result.confidence,
            indicators: scan.result.indicators || [],
            recommendation: scan.result.recommendations?.[0] || 'No specific recommendation available.',
            source: `${scan.type} analysis`,
            detectedAt: new Date(scan.timestamp).toLocaleTimeString()
          }));
          setRecentScans(transformedScans);
        }

        // Load model information
        const modelsResponse = await backendService.getModels();
        if (modelsResponse.success) {
          setModels(modelsResponse.models);
          setSystemHealth({
            online: true,
            modelsActive: modelsResponse.models.filter((m: any) => m.config.state === 'active').length
          });
        }

        // Health check
        const healthResponse = await backendService.getHealth();
        setSystemHealth(prev => ({ 
          ...prev, 
          online: healthResponse.success 
        }));

      } catch (error) {
        console.error('Failed to load dashboard data:', error);
      } finally {
        setLoading(false);
      }
    };

    loadDashboardData();
    
    // Refresh data every 30 seconds
    const interval = setInterval(loadDashboardData, 30000);
    return () => clearInterval(interval);
  }, [backendService]);

  const getRelativeTime = (timestamp: string) => {
    const now = new Date();
    const past = new Date(timestamp);
    const diffInMinutes = Math.floor((now.getTime() - past.getTime()) / (1000 * 60));
    
    if (diffInMinutes < 1) return 'Just now';
    if (diffInMinutes < 60) return `${diffInMinutes} min ago`;
    if (diffInMinutes < 1440) return `${Math.floor(diffInMinutes / 60)} hour${Math.floor(diffInMinutes / 60) === 1 ? '' : 's'} ago`;
    return `${Math.floor(diffInMinutes / 1440)} day${Math.floor(diffInMinutes / 1440) === 1 ? '' : 's'} ago`;
  };

  // Fallback data for empty state
  const fallbackScans: RecentScan[] = [
    { 
      id: "1", 
      type: "url", 
      content: "suspicious-bank-login.com", 
      threat_level: "high", 
      timestamp: "2 min ago",
      confidence: 95,
      indicators: ["Suspicious domain", "Phishing keywords", "No HTTPS certificate", "Recently registered domain"],
      recommendation: "Block immediately. This appears to be a banking phishing site designed to steal credentials.",
      source: "Email link",
      detectedAt: "14:30:22"
    },
    { 
      id: "2", 
      type: "email", 
      content: "Prize notification from unknown sender", 
      threat_level: "medium", 
      timestamp: "5 min ago",
      confidence: 78,
      indicators: ["Prize scam pattern", "Urgency language", "External links", "Generic greeting"],
      recommendation: "Likely spam/scam. Delete without opening attachments or clicking links.",
      source: "Inbox scan",
      detectedAt: "14:27:15"
    },
    { 
      id: "3", 
      type: "file", 
      content: "invoice_2024.pdf", 
      threat_level: "safe", 
      timestamp: "12 min ago",
      confidence: 98,
      indicators: ["Clean content", "Valid PDF structure", "No embedded scripts"],
      recommendation: "File appears safe. Standard PDF document with no suspicious elements.",
      source: "File upload",
      detectedAt: "14:20:33"
    },
    { 
      id: "4", 
      type: "message", 
      content: "Click here to verify your account", 
      threat_level: "high", 
      timestamp: "18 min ago",
      confidence: 91,
      indicators: ["Account verification scam", "Urgency language", "Suspicious link", "Social engineering"],
      recommendation: "High risk phishing attempt. Do not click any links. Report to security team.",
      source: "SMS/Message",
      detectedAt: "14:14:47"
    }
  ];

  const getThreatBadgeVariant = (level: string) => {
    switch (level) {
      case 'high': return 'destructive';
      case 'medium': return 'secondary';
      case 'low': return 'outline';
      default: return 'default';
    }
  };

  const getThreatIcon = (level: string) => {
    switch (level) {
      case 'high': return <AlertTriangle className="w-4 h-4" />;
      case 'medium': return <Clock className="w-4 h-4" />;
      case 'low': return <Shield className="w-4 h-4" />;
      default: return <CheckCircle className="w-4 h-4" />;
    }
  };

  const getThreatColor = (level: string) => {
    switch (level) {
      case 'high': return 'text-destructive';
      case 'medium': return 'text-orange-500';
      case 'low': return 'text-yellow-600';
      default: return 'text-green-600';
    }
  };

  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'url': return <ExternalLink className="w-3 h-3" />;
      case 'email': return <span className="text-xs">@</span>;
      case 'file': return <span className="text-xs">📄</span>;
      case 'message': return <span className="text-xs">💬</span>;
      default: return <Info className="w-3 h-3" />;
    }
  };

  return (
    <TooltipProvider>
      <div className="space-y-6">
        {/* System Status */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Backend Status</CardTitle>
              <Activity className={`h-4 w-4 ${systemHealth.online ? 'text-green-500' : 'text-red-500'}`} />
            </CardHeader>
            <CardContent>
              <div className={`text-lg font-bold ${systemHealth.online ? 'text-green-500' : 'text-yellow-500'}`}>
                {systemHealth.online ? 'Online' : 'Local Mode'}
              </div>
              <p className="text-xs text-muted-foreground">
                {systemHealth.online ? 'Real-time threat analysis available' : 'Using local analysis engines'}
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">AI Models Active</CardTitle>
              <Database className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-lg font-bold text-blue-500">
                {systemHealth.modelsActive}/4
              </div>
              <p className="text-xs text-muted-foreground">
                Detection engines running
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Data Processing</CardTitle>
              <Shield className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-lg font-bold text-purple-500">
                {systemHealth.online ? 'Real-time' : 'Local'}
              </div>
              <p className="text-xs text-muted-foreground">
                {systemHealth.online ? 'Live threat intelligence' : 'Local threat analysis'}
              </p>
            </CardContent>
          </Card>
        </div>

        {/* Threat Statistics */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {threatStats.map((stat, index) => (
            <Card key={index}>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">{stat.label}</CardTitle>
                <Shield className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{stat.value}{stat.label.includes('Score') ? '%' : ''}</div>
                <p className="text-xs text-muted-foreground">
                  <span className={stat.type === 'danger' ? 'text-destructive' : stat.type === 'warning' ? 'text-orange-500' : 'text-green-500'}>
                    {stat.change}
                  </span>
                  {' '}from yesterday
                </p>
              </CardContent>
            </Card>
          ))}
        </div>

        {/* Protection Score */}
        <Card>
          <CardHeader>
            <CardTitle>Overall Protection Score</CardTitle>
            <CardDescription>
              Your current security posture based on recent scans and threat patterns
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              <div className="flex justify-between">
                <span>Protection Level</span>
                <span className="font-medium">{threatStats[3]?.value || 0}/100</span>
              </div>
              <Progress value={threatStats[3]?.value || 0} className="w-full" />
              <p className="text-sm text-muted-foreground">
                Excellent protection. Continue regular scanning to maintain security.
              </p>
            </div>
          </CardContent>
        </Card>

        {/* Recent Scans */}
        <Card>
          <CardHeader>
            <CardTitle>Recent Scans</CardTitle>
            <CardDescription>
              Latest phishing detection results across all monitored applications
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {loading ? (
                <div className="text-center py-8">
                  <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary mx-auto"></div>
                  <p className="text-sm text-muted-foreground mt-2">Loading recent scans...</p>
                </div>
              ) : recentScans.length === 0 ? (
                <div className="text-center py-8">
                  <Shield className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
                  <p className="text-muted-foreground">No recent scans available</p>
                  <p className="text-sm text-muted-foreground">Start scanning URLs, emails, or files to see results here</p>
                </div>
              ) : (
                (recentScans.length > 0 ? recentScans : fallbackScans).slice(0, 4).map((scan) => (
                <Tooltip key={scan.id}>
                  <TooltipTrigger asChild>
                    <div className="flex items-center justify-between p-3 border rounded-lg hover:bg-muted/50 transition-colors cursor-pointer">
                      <div className="flex items-center space-x-3">
                        <div className="flex items-center space-x-2">
                          {getThreatIcon(scan.threat_level)}
                          <Badge variant="outline" className="capitalize flex items-center gap-1">
                            {getTypeIcon(scan.type)}
                            {scan.type}
                          </Badge>
                        </div>
                        <div>
                          <p className="font-medium truncate max-w-[300px]">{scan.content}</p>
                          <p className="text-sm text-muted-foreground">{scan.timestamp}</p>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <Badge variant={getThreatBadgeVariant(scan.threat_level)} className="capitalize">
                          {scan.threat_level === 'safe' ? 'Safe' : `${scan.threat_level} Risk`}
                        </Badge>
                        <Info className="w-4 h-4 text-muted-foreground" />
                      </div>
                    </div>
                  </TooltipTrigger>
                  <TooltipContent className="max-w-sm p-4">
                    <div className="space-y-3">
                      <div className="border-b pb-2">
                        <div className="flex items-center gap-2 mb-1">
                          {getThreatIcon(scan.threat_level)}
                          <span className={`font-semibold capitalize ${getThreatColor(scan.threat_level)}`}>
                            {scan.threat_level === 'safe' ? 'Safe Content' : `${scan.threat_level} Risk Detected`}
                          </span>
                        </div>
                        <p className="text-sm text-muted-foreground">
                          Confidence: {scan.confidence}% • {scan.source} • {scan.detectedAt}
                        </p>
                      </div>
                      
                      <div>
                        <h4 className="font-medium text-sm mb-1">Threat Indicators</h4>
                        <div className="flex flex-wrap gap-1">
                          {scan.indicators.slice(0, 3).map((indicator, index) => (
                            <Badge key={index} variant="outline" className="text-xs">
                              {indicator}
                            </Badge>
                          ))}
                          {scan.indicators.length > 3 && (
                            <Badge variant="outline" className="text-xs">
                              +{scan.indicators.length - 3} more
                            </Badge>
                          )}
                        </div>
                      </div>

                      <div>
                        <h4 className="font-medium text-sm mb-1">Recommendation</h4>
                        <p className="text-xs text-muted-foreground leading-relaxed">
                          {scan.recommendation}
                        </p>
                      </div>
                    </div>
                  </TooltipContent>
                </Tooltip>
              )))}
            </div>
          </CardContent>
        </Card>

        {/* Model Status */}
        {models.length > 0 && (
          <Card>
            <CardHeader>
              <CardTitle>AI Model Status</CardTitle>
              <CardDescription>
                Real-time status of threat detection models
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {models.map((model) => (
                  <div key={model.id} className="flex items-center justify-between p-3 border rounded-lg">
                    <div>
                      <p className="font-medium capitalize">{model.id.replace(/_/g, ' ')}</p>
                      <p className="text-sm text-muted-foreground">v{model.config.version}</p>
                    </div>
                    <Badge variant={model.config.state === 'active' ? 'default' : 'secondary'}>
                      {model.config.state}
                    </Badge>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        )}
      </div>
    </TooltipProvider>
  );
}