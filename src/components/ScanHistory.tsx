import { useCallback, useEffect, useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "./ui/card";
import { Button } from "./ui/button";
import { Badge } from "./ui/badge";
import { Input } from "./ui/input";
import { Alert, AlertDescription } from "./ui/alert";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "./ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "./ui/table";
import { AlertTriangle, Download, Eye, RotateCcw, Search, Trash2 } from "lucide-react";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from "./ui/dialog";
import { toast } from "sonner";
import {
  BackendService as DefaultBackendService,
  errorMessage,
  isAbortError,
  type BackendServiceType,
  type StoredScan,
} from "@/utils/BackendService";
import { normalizeThreatLevel, THREAT_FILTER_OPTIONS, THREAT_META, ThreatBadge, type ThreatLevel } from "./scan/threatLevel";

interface HistoryItem {
  id: string;
  type: string;
  content: string;
  level: ThreatLevel;
  confidence: number | null;
  riskScore: number | null;
  timestamp: string | null;
  indicators: string[];
  recommendations: string[];
}

interface ScanHistoryProps {
  backendService?: BackendServiceType;
}

function toHistoryItem(scan: StoredScan): HistoryItem {
  const r = scan.result ?? {};
  return {
    id: scan.id,
    type: String(scan.type || "").toLowerCase(),
    content: scan.target ?? "",
    level: normalizeThreatLevel(r.threat_level),
    confidence: typeof r.confidence === "number" ? r.confidence : null,
    riskScore: typeof r.risk_score === "number" ? r.risk_score : null,
    timestamp: scan.timestamp ?? null,
    indicators: Array.isArray(r.indicators) ? r.indicators : [],
    recommendations: Array.isArray(r.recommendations) ? r.recommendations : [],
  };
}

function formatTimestamp(ts: string | null) {
  if (!ts) return "—";
  const d = new Date(ts);
  return Number.isNaN(d.getTime()) ? "—" : d.toLocaleString();
}

function csvCell(value: string | number | null): string {
  let s = value === null ? "" : String(value);
  // Neutralise spreadsheet formula injection.
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return `"${s.replace(/"/g, '""')}"`;
}

function exportCsv(items: HistoryItem[]) {
  const header = ["Scanned at", "Type", "Content", "Threat level", "Risk score", "Confidence", "Findings", "Recommendations"];
  const rows = items.map((i) => [
    i.timestamp ?? "",
    i.type,
    i.content,
    THREAT_META[i.level].label,
    i.riskScore,
    i.confidence,
    i.indicators.join(" | "),
    i.recommendations.join(" | "),
  ]);
  const csv = [header, ...rows].map((row) => row.map((c) => csvCell(c as string | number | null)).join(",")).join("\r\n");
  const blob = new Blob(["﻿" + csv], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `phishguard-scan-history-${new Date().toISOString().slice(0, 10)}.csv`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

export function ScanHistory({ backendService = DefaultBackendService }: ScanHistoryProps) {
  const [searchTerm, setSearchTerm] = useState("");
  const [filterType, setFilterType] = useState("all");
  const [filterThreat, setFilterThreat] = useState("all");
  const [historyData, setHistoryData] = useState<HistoryItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [deletingId, setDeletingId] = useState<string | null>(null);

  // State is only set inside promise callbacks (never synchronously in an effect).
  const load = useCallback(
    (signal?: AbortSignal) =>
      backendService.getScans(100, signal).then(
        (scans) => {
          if (signal?.aborted) return;
          setHistoryData(scans.map(toHistoryItem));
          setLoadError(null);
          setLoading(false);
        },
        (error) => {
          if (isAbortError(error) || signal?.aborted) return;
          setLoadError(errorMessage(error, "Couldn't load your scan history."));
          setLoading(false);
        }
      ),
    [backendService]
  );

  const retry = () => {
    setLoading(true);
    setLoadError(null);
    load();
  };

  useEffect(() => {
    const controller = new AbortController();
    load(controller.signal);
    return () => controller.abort();
  }, [load]);

  const handleDelete = async (item: HistoryItem) => {
    if (!window.confirm("Delete this scan from your history?")) return;
    setDeletingId(item.id);
    try {
      await backendService.deleteScan(item.id);
      setHistoryData((prev) => prev.filter((h) => h.id !== item.id));
      toast.success("Scan deleted");
    } catch (error) {
      toast.error(errorMessage(error, "Couldn't delete the scan — try again."));
    } finally {
      setDeletingId(null);
    }
  };

  const filteredHistory = historyData.filter((item) => {
    const matchesSearch = item.content.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesType = filterType === "all" || item.type === filterType;
    const matchesThreat = filterThreat === "all" || item.level === filterThreat;
    return matchesSearch && matchesType && matchesThreat;
  });

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle>Scan history</CardTitle>
          <CardDescription>
            Your last 100 scans, newest first.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {/* Filters */}
          <div className="flex flex-col sm:flex-row gap-4 mb-6">
            <div className="flex-1">
              <div className="relative">
                <Search
                  className="absolute left-3 top-1/2 transform -translate-y-1/2 text-muted-foreground w-4 h-4"
                  aria-hidden="true"
                />
                <Input
                  placeholder="Search scans..."
                  aria-label="Search scans"
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="pl-10"
                />
              </div>
            </div>
            <Select value={filterType} onValueChange={setFilterType}>
              <SelectTrigger className="w-[140px]" aria-label="Filter by type">
                <SelectValue placeholder="Type" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All types</SelectItem>
                <SelectItem value="url">Link</SelectItem>
                <SelectItem value="email">Email</SelectItem>
                <SelectItem value="file">File</SelectItem>
                <SelectItem value="message">Message</SelectItem>
              </SelectContent>
            </Select>
            <Select value={filterThreat} onValueChange={setFilterThreat}>
              <SelectTrigger className="w-[170px]" aria-label="Filter by threat level">
                <SelectValue placeholder="Threat level" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All levels</SelectItem>
                {THREAT_FILTER_OPTIONS.map((opt) => (
                  <SelectItem key={opt.value} value={opt.value}>
                    {opt.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Button
              variant="outline"
              size="icon"
              aria-label="Download shown scans as CSV"
              title="Download shown scans as CSV"
              disabled={filteredHistory.length === 0}
              onClick={() => exportCsv(filteredHistory)}
            >
              <Download className="w-4 h-4" aria-hidden="true" />
            </Button>
          </div>

          {loadError && (
            <Alert variant="destructive" className="mb-4">
              <AlertTriangle className="h-4 w-4" aria-hidden="true" />
              <AlertDescription>
                <span>{loadError}</span>
                <Button size="sm" variant="outline" className="mt-2 w-fit" onClick={retry}>
                  <RotateCcw className="w-4 h-4 mr-2" aria-hidden="true" />
                  Retry
                </Button>
              </AlertDescription>
            </Alert>
          )}

          {/* History Table */}
          <div className="border rounded-lg">
            {loading ? (
              <div className="text-center py-8" role="status">
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary mx-auto" aria-hidden="true" />
                <p className="text-sm text-muted-foreground mt-2">Loading scan history…</p>
              </div>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Type</TableHead>
                    <TableHead>Content</TableHead>
                    <TableHead>Threat level</TableHead>
                    <TableHead>Confidence</TableHead>
                    <TableHead>Scanned at</TableHead>
                    <TableHead>Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredHistory.map((item) => (
                    <TableRow key={item.id}>
                      <TableCell>
                        <Badge variant="outline" className="capitalize">
                          {item.type || "unknown"}
                        </Badge>
                      </TableCell>
                      <TableCell className="max-w-[300px]">
                        <div className="truncate" title={item.content}>
                          {item.content}
                        </div>
                      </TableCell>
                      <TableCell>
                        <ThreatBadge level={item.level} />
                      </TableCell>
                      <TableCell>{item.confidence !== null ? `${item.confidence}%` : "—"}</TableCell>
                      <TableCell className="text-sm text-muted-foreground">{formatTimestamp(item.timestamp)}</TableCell>
                      <TableCell>
                        <div className="flex items-center gap-2">
                          <Dialog>
                            <DialogTrigger asChild>
                              <Button variant="ghost" size="icon" aria-label="View scan details">
                                <Eye className="w-4 h-4" aria-hidden="true" />
                              </Button>
                            </DialogTrigger>
                            <DialogContent className="max-w-2xl">
                              <DialogHeader>
                                <DialogTitle>Scan details</DialogTitle>
                                <DialogDescription>Results saved for this scan</DialogDescription>
                              </DialogHeader>
                              <div className="space-y-4">
                                <div>
                                  <h4 className="font-medium mb-2">Content</h4>
                                  <p className="text-sm bg-muted p-3 rounded-lg break-all">{item.content}</p>
                                </div>
                                <div className="grid grid-cols-3 gap-4">
                                  <div>
                                    <h4 className="font-medium">Threat level</h4>
                                    <ThreatBadge level={item.level} />
                                  </div>
                                  <div>
                                    <h4 className="font-medium">Risk score</h4>
                                    <p>{item.riskScore !== null ? `${item.riskScore}/100` : "Not available"}</p>
                                  </div>
                                  <div>
                                    <h4 className="font-medium">Confidence</h4>
                                    <p>{item.confidence !== null ? `${item.confidence}%` : "Not available"}</p>
                                  </div>
                                </div>
                                <div>
                                  <h4 className="font-medium mb-2">Findings</h4>
                                  {item.indicators.length > 0 ? (
                                    <ul className="list-disc pl-5 space-y-1 text-sm">
                                      {item.indicators.map((indicator, i) => (
                                        <li key={`${i}-${indicator}`}>{indicator}</li>
                                      ))}
                                    </ul>
                                  ) : (
                                    <p className="text-sm text-muted-foreground">None recorded.</p>
                                  )}
                                </div>
                                {item.recommendations.length > 0 && (
                                  <div>
                                    <h4 className="font-medium mb-2">What to do</h4>
                                    <ul className="list-disc pl-5 space-y-1 text-sm">
                                      {item.recommendations.map((rec, i) => (
                                        <li key={`${i}-${rec}`}>{rec}</li>
                                      ))}
                                    </ul>
                                  </div>
                                )}
                              </div>
                            </DialogContent>
                          </Dialog>
                          <Button
                            variant="ghost"
                            size="icon"
                            aria-label="Delete scan"
                            disabled={deletingId === item.id}
                            onClick={() => handleDelete(item)}
                          >
                            <Trash2 className="w-4 h-4" aria-hidden="true" />
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </div>

          {!loading && !loadError && filteredHistory.length === 0 && (
            <div className="text-center py-8 text-muted-foreground">
              {historyData.length === 0 ? "You haven't scanned anything yet." : "No scans match your filters."}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
