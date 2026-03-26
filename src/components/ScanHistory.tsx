import { useState, useEffect } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "./ui/card";
import { Button } from "./ui/button";
import { Badge } from "./ui/badge";
import { Input } from "./ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "./ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "./ui/table";
import { Search, Download, Eye, Trash2 } from "lucide-react";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from "./ui/dialog";
import { toast } from "sonner";

interface HistoryItem {
  id: string;
  type: 'url' | 'email' | 'file' | 'message';
  content: string;
  threat_level: 'safe' | 'low' | 'medium' | 'high';
  confidence: number;
  timestamp: string;
  indicators: string[];
  status: 'completed' | 'quarantined' | 'blocked';
}

interface ScanHistoryProps {
  backendService: any;
}

export function ScanHistory({ backendService }: ScanHistoryProps) {
  const [searchTerm, setSearchTerm] = useState("");
  const [filterType, setFilterType] = useState("all");
  const [filterThreat, setFilterThreat] = useState("all");
  const [historyData, setHistoryData] = useState<HistoryItem[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const loadScanHistory = async () => {
      try {
        setLoading(true);
        const userId = backendService.generateUserId();
        const response = await backendService.getScans(userId);
        
        if (response.success) {
          const transformedHistory = response.scans.map((scan: any) => ({
            id: scan.id,
            type: scan.type,
            content: scan.target,
            threat_level: scan.result.threat_level.toLowerCase(),
            confidence: scan.result.confidence,
            timestamp: new Date(scan.timestamp).toLocaleString(),
            indicators: scan.result.indicators || [],
            status: scan.result.threat_level === 'HIGH' || scan.result.threat_level === 'CRITICAL' ? 'blocked' :
                    scan.result.threat_level === 'MEDIUM' ? 'quarantined' : 'completed'
          }));
          setHistoryData(transformedHistory);
        }
      } catch (error) {
        console.error('Failed to load scan history:', error);
        // Keep fallback data if backend fails
        setHistoryData(fallbackHistoryData);
      } finally {
        setLoading(false);
      }
    };

    loadScanHistory();
  }, [backendService]);

  const fallbackHistoryData: HistoryItem[] = [
    {
      id: "1",
      type: "url",
      content: "https://suspicious-bank-login.com/verify",
      threat_level: "high",
      confidence: 95,
      timestamp: "2024-08-12 14:30:22",
      indicators: ["Suspicious domain", "Phishing keywords", "No HTTPS certificate"],
      status: "blocked"
    },
    {
      id: "2",
      type: "email",
      content: "Congratulations! You've won $1,000,000...",
      threat_level: "high",
      confidence: 89,
      timestamp: "2024-08-12 13:45:18",
      indicators: ["Prize scam pattern", "Urgency language", "External links"],
      status: "quarantined"
    },
    {
      id: "3",
      type: "file",
      content: "invoice_2024_final.pdf",
      threat_level: "medium",
      confidence: 72,
      timestamp: "2024-08-12 12:15:44",
      indicators: ["Embedded JavaScript", "Generic filename"],
      status: "quarantined"
    },
    {
      id: "4",
      type: "message",
      content: "Your account will be suspended unless you verify...",
      threat_level: "high",
      confidence: 91,
      timestamp: "2024-08-12 11:20:33",
      indicators: ["Account threat", "Urgency language", "Verification request"],
      status: "blocked"
    },
    {
      id: "5",
      type: "url",
      content: "https://legitimate-company.com/newsletter",
      threat_level: "safe",
      confidence: 98,
      timestamp: "2024-08-12 10:05:12",
      indicators: ["Clean content", "Valid certificate", "Established domain"],
      status: "completed"
    },
    {
      id: "6",
      type: "email",
      content: "Meeting reminder for tomorrow at 2 PM",
      threat_level: "safe",
      confidence: 99,
      timestamp: "2024-08-12 09:30:15",
      indicators: ["Internal sender", "Clean content"],
      status: "completed"
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

  const getStatusBadgeVariant = (status: string) => {
    switch (status) {
      case 'blocked': return 'destructive';
      case 'quarantined': return 'secondary';
      default: return 'default';
    }
  };

  const filteredHistory = historyData.filter(item => {
    const matchesSearch = item.content.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesType = filterType === "all" || item.type === filterType;
    const matchesThreat = filterThreat === "all" || item.threat_level === filterThreat;
    return matchesSearch && matchesType && matchesThreat;
  });

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle>Scan History</CardTitle>
          <CardDescription>
            View and manage all previous phishing detection scans
          </CardDescription>
        </CardHeader>
        <CardContent>
          {/* Filters */}
          <div className="flex flex-col sm:flex-row gap-4 mb-6">
            <div className="flex-1">
              <div className="relative">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-muted-foreground w-4 h-4" />
                <Input
                  placeholder="Search scans..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="pl-10"
                />
              </div>
            </div>
            <Select value={filterType} onValueChange={setFilterType}>
              <SelectTrigger className="w-[120px]">
                <SelectValue placeholder="Type" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Types</SelectItem>
                <SelectItem value="url">URL</SelectItem>
                <SelectItem value="email">Email</SelectItem>
                <SelectItem value="file">File</SelectItem>
                <SelectItem value="message">Message</SelectItem>
              </SelectContent>
            </Select>
            <Select value={filterThreat} onValueChange={setFilterThreat}>
              <SelectTrigger className="w-[140px]">
                <SelectValue placeholder="Threat Level" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Levels</SelectItem>
                <SelectItem value="safe">Safe</SelectItem>
                <SelectItem value="low">Low Risk</SelectItem>
                <SelectItem value="medium">Medium Risk</SelectItem>
                <SelectItem value="high">High Risk</SelectItem>
              </SelectContent>
            </Select>
            <Button variant="outline" size="icon">
              <Download className="w-4 h-4" />
            </Button>
          </div>

          {/* History Table */}
          <div className="border rounded-lg">
            {loading ? (
              <div className="text-center py-8">
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary mx-auto"></div>
                <p className="text-sm text-muted-foreground mt-2">Loading scan history...</p>
              </div>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Type</TableHead>
                    <TableHead>Content</TableHead>
                    <TableHead>Threat Level</TableHead>
                    <TableHead>Confidence</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Timestamp</TableHead>
                    <TableHead>Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredHistory.map((item) => (
                    <TableRow key={item.id}>
                      <TableCell>
                        <Badge variant="outline" className="capitalize">
                          {item.type}
                        </Badge>
                      </TableCell>
                      <TableCell className="max-w-[300px]">
                        <div className="truncate">{item.content}</div>
                      </TableCell>
                      <TableCell>
                        <Badge variant={getThreatBadgeVariant(item.threat_level)} className="capitalize">
                          {item.threat_level === 'safe' ? 'Safe' : `${item.threat_level} Risk`}
                        </Badge>
                      </TableCell>
                      <TableCell>{item.confidence}%</TableCell>
                      <TableCell>
                        <Badge variant={getStatusBadgeVariant(item.status)} className="capitalize">
                          {item.status}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-sm text-muted-foreground">
                        {item.timestamp}
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center gap-2">
                          <Dialog>
                            <DialogTrigger asChild>
                              <Button variant="ghost" size="icon">
                                <Eye className="w-4 h-4" />
                              </Button>
                            </DialogTrigger>
                            <DialogContent className="max-w-2xl">
                              <DialogHeader>
                                <DialogTitle>Scan Details</DialogTitle>
                                <DialogDescription>
                                  Detailed analysis results for this scan
                                </DialogDescription>
                              </DialogHeader>
                              <div className="space-y-4">
                                <div>
                                  <h4 className="font-medium mb-2">Content</h4>
                                  <p className="text-sm bg-muted p-3 rounded-lg break-all">
                                    {item.content}
                                  </p>
                                </div>
                                <div>
                                  <h4 className="font-medium mb-2">Threat Indicators</h4>
                                  <div className="flex flex-wrap gap-2">
                                    {item.indicators.map((indicator, index) => (
                                      <Badge key={index} variant="outline">
                                        {indicator}
                                      </Badge>
                                    ))}
                                  </div>
                                </div>
                                <div className="grid grid-cols-2 gap-4">
                                  <div>
                                    <h4 className="font-medium">Threat Level</h4>
                                    <Badge variant={getThreatBadgeVariant(item.threat_level)} className="capitalize">
                                      {item.threat_level === 'safe' ? 'Safe' : `${item.threat_level} Risk`}
                                    </Badge>
                                  </div>
                                  <div>
                                    <h4 className="font-medium">Confidence</h4>
                                    <p>{item.confidence}%</p>
                                  </div>
                                </div>
                              </div>
                            </DialogContent>
                          </Dialog>
                          <Button
                            variant="ghost"
                            size="icon"
                            onClick={async () => {
                              if (!confirm('Are you sure you want to delete this scan?')) return;
                              const result = await backendService.deleteScan(item.id);
                              if (result.success) {
                                setHistoryData(prev => prev.filter(h => h.id !== item.id));
                                toast.success('Scan deleted');
                              } else {
                                toast.error('Failed to delete scan');
                              }
                            }}
                          >
                            <Trash2 className="w-4 h-4" />
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </div>

          {!loading && filteredHistory.length === 0 && (
            <div className="text-center py-8 text-muted-foreground">
              No scan results found matching your criteria.
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}