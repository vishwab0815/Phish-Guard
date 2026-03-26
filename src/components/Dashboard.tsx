import { useState, useEffect } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "./ui/card";
import { Badge } from "./ui/badge";
import { Progress } from "./ui/progress";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "./ui/tooltip";
import { Shield, AlertTriangle, CheckCircle, Clock, Info, ExternalLink, Activity, Database } from "lucide-react";
import { motion, AnimatePresence, Variants } from "framer-motion";

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

const containerVariants: Variants = {
  hidden: { opacity: 0 },
  visible: {
    opacity: 1,
    transition: {
      staggerChildren: 0.1
    }
  }
};

const itemVariants: Variants = {
  hidden: { y: 20, opacity: 0 },
  visible: {
    y: 0,
    opacity: 1,
    transition: {
      type: "spring",
      stiffness: 100
    }
  }
};

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
      <motion.div 
        variants={containerVariants}
        initial="hidden"
        animate="visible"
        className="space-y-6"
      >
        {/* System Status */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
          <motion.div variants={itemVariants}>
            <Card className="glass-card">
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Backend Status</CardTitle>
                <Activity className={`h-4 w-4 ${systemHealth.online ? 'status-online' : 'status-warning'}`} />
              </CardHeader>
              <CardContent>
                <div className={`text-2xl font-bold ${systemHealth.online ? 'text-green-500' : 'text-yellow-500'}`}>
                  {systemHealth.online ? 'Online' : 'Local Mode'}
                </div>
                <p className="text-xs text-muted-foreground mt-1">
                  {systemHealth.online ? 'Real-time threat analysis available' : 'Using local analysis engines'}
                </p>
              </CardContent>
            </Card>
          </motion.div>

          <motion.div variants={itemVariants}>
            <Card className="glass-card">
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">AI Models Active</CardTitle>
                <Database className="h-4 w-4 text-primary" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold text-gradient">
                  {systemHealth.modelsActive}/4
                </div>
                <p className="text-xs text-muted-foreground mt-1">
                  Detection engines running
                </p>
              </CardContent>
            </Card>
          </motion.div>

          <motion.div variants={itemVariants}>
            <Card className="glass-card">
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Data Processing</CardTitle>
                <Shield className="h-4 w-4 text-cyan-400" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold text-cyan-400">
                  {systemHealth.online ? 'Real-time' : 'Local'}
                </div>
                <p className="text-xs text-muted-foreground mt-1">
                  {systemHealth.online ? 'Live threat intelligence' : 'Local threat analysis'}
                </p>
              </CardContent>
            </Card>
          </motion.div>
        </div>

        {/* Threat Statistics */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {threatStats.map((stat, index) => (
            <motion.div key={index} variants={itemVariants}>
              <Card className="glass-card hover:translate-y-[-4px] transition-transform duration-300">
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                  <CardTitle className="text-sm font-medium">{stat.label}</CardTitle>
                  <Shield className="h-4 w-4 text-muted-foreground/50" />
                </CardHeader>
                <CardContent>
                  <div className="text-3xl font-bold">{stat.value}{stat.label.includes('Score') ? '%' : ''}</div>
                  <p className="text-xs mt-1">
                    <span className={stat.type === 'danger' ? 'text-destructive' : stat.type === 'warning' ? 'text-orange-500' : 'text-green-500'}>
                      {stat.change}
                    </span>
                    <span className="text-muted-foreground ml-1">from yesterday</span>
                  </p>
                </CardContent>
              </Card>
            </motion.div>
          ))}
        </div>

        {/* Protection Score */}
        <motion.div variants={itemVariants}>
          <Card className="glass-card overflow-hidden relative">
            <div className="absolute top-0 right-0 p-8 opacity-10">
              <Shield className="w-32 h-32" />
            </div>
            <CardHeader>
              <CardTitle className="text-xl">Overall Protection Score</CardTitle>
              <CardDescription>
                Your current security posture based on recent scans and threat patterns
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <div className="flex justify-between items-end">
                  <span className="text-sm font-medium text-muted-foreground">Protection Level</span>
                  <span className="text-4xl font-bold text-gradient">{threatStats[3]?.value || 0}%</span>
                </div>
                <Progress value={threatStats[3]?.value || 0} className="h-3 w-full bg-white/5" />
                <div className="flex items-center gap-2 text-sm text-muted-foreground">
                  <CheckCircle className="w-4 h-4 text-green-500" />
                  <span>Excellent protection. Continue regular scanning to maintain security.</span>
                </div>
              </div>
            </CardContent>
          </Card>
        </motion.div>

        {/* Recent Scans */}
        <motion.div variants={itemVariants}>
          <Card className="glass-card">
            <CardHeader>
              <CardTitle>Recent Scans</CardTitle>
              <CardDescription>
                Latest phishing detection results across all monitored applications
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                {loading ? (
                  <div className="text-center py-12">
                    <div className="animate-spin rounded-full h-10 w-10 border-b-2 border-primary mx-auto"></div>
                    <p className="text-sm text-muted-foreground mt-4">Analyzing recent threats...</p>
                  </div>
                ) : (recentScans.length > 0 ? recentScans : []).map((scan) => (
                  <Tooltip key={scan.id}>
                    <TooltipTrigger asChild>
                      <motion.div 
                        whileHover={{ scale: 1.01 }}
                        className="flex items-center justify-between p-4 bg-white/5 border border-white/5 rounded-xl hover:bg-white/10 transition-all cursor-pointer group"
                      >
                        <div className="flex items-center space-x-4">
                          <div className={`p-2 rounded-lg bg-opacity-20 ${scan.threat_level === 'high' ? 'bg-red-500' : 'bg-green-500'}`}>
                            {getThreatIcon(scan.threat_level)}
                          </div>
                          <div>
                            <p className="font-semibold truncate max-w-[350px] group-hover:text-primary transition-colors">{scan.content}</p>
                            <div className="flex items-center gap-3 mt-1">
                              <span className="text-xs text-muted-foreground flex items-center gap-1">
                                <Clock className="w-3 h-3" />
                                {scan.timestamp}
                              </span>
                              <Badge variant="outline" className="text-[10px] py-0 px-2 h-4 capitalize border-white/10">
                                {scan.type}
                              </Badge>
                            </div>
                          </div>
                        </div>
                        <div className="flex items-center gap-4">
                          <div className="text-right hidden sm:block">
                            <p className="text-xs text-muted-foreground mb-1">Confidence</p>
                            <p className="text-sm font-mono font-bold">{scan.confidence}%</p>
                          </div>
                          <Badge variant={getThreatBadgeVariant(scan.threat_level)} className="h-7 px-3 capitalize">
                            {scan.threat_level === 'safe' ? 'Safe' : `${scan.threat_level}`}
                          </Badge>
                        </div>
                      </motion.div>
                    </TooltipTrigger>
                    <TooltipContent className="max-w-sm p-0 glass-card border-white/10 overflow-hidden" side="left">
                      <div className="p-4 space-y-4">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            {getThreatIcon(scan.threat_level)}
                            <span className={`font-bold capitalize ${getThreatColor(scan.threat_level)}`}>
                              {scan.threat_level === 'safe' ? 'Safe Content' : `${scan.threat_level} Risk`}
                            </span>
                          </div>
                          <span className="text-[10px] text-muted-foreground uppercase tracking-wider">{scan.detectedAt}</span>
                        </div>
                        
                        <div className="space-y-2">
                          <h4 className="text-xs font-bold text-muted-foreground uppercase tracking-widest">Analysis Indicators</h4>
                          <div className="flex flex-wrap gap-1">
                            {scan.indicators.slice(0, 4).map((indicator, index) => (
                              <Badge key={index} variant="secondary" className="text-[10px] py-0 px-2 bg-white/5">
                                {indicator}
                              </Badge>
                            ))}
                          </div>
                        </div>

                        <div className="p-3 bg-black/20 rounded-lg border border-white/5">
                          <h4 className="text-xs font-bold text-primary mb-1 uppercase tracking-widest">AI Recommendation</h4>
                          <p className="text-xs text-muted-foreground leading-relaxed">
                            {scan.recommendation}
                          </p>
                        </div>
                      </div>
                    </TooltipContent>
                  </Tooltip>
                ))}
              </div>
            </CardContent>
          </Card>
        </motion.div>
      </motion.div>
    </TooltipProvider>
  );
}