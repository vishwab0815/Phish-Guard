import { useCallback, useEffect, useRef, useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "./ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "./ui/tabs";
import { Alert, AlertDescription, AlertTitle } from "./ui/alert";
import { Button } from "./ui/button";
import { AlertTriangle, Brain, Link, Mail, MessageSquare, RotateCcw, Upload } from "lucide-react";
import { motion } from "framer-motion";
import {
  BackendService as DefaultBackendService,
  errorMessage,
  isAbortError,
  type AnalysisResponse,
  type BackendServiceType,
} from "@/utils/BackendService";
import type { ScanKind } from "./scan/threatLevel";
import { normalizeAnalysis, type ScanReport } from "./scan/report";
import { UrlScanForm } from "./scan/UrlScanForm";
import { EmailScanForm } from "./scan/EmailScanForm";
import { MessageScanForm } from "./scan/MessageScanForm";
import { FileScanForm } from "./scan/FileScanForm";
import { ScanProgress } from "./scan/ScanProgress";
import { ScanResultReport } from "./scan/ScanResultReport";

interface ScanInterfaceProps {
  backendService?: BackendServiceType;
  /** Called after a scan completes successfully (e.g. to refresh header stats). */
  onScanComplete?: () => void;
}

const MAX_EMAIL_BYTES = 200 * 1024;

interface ScanError {
  kind: ScanKind;
  message: string;
}

function emailTarget(raw: string): string {
  const subject = raw.match(/^subject:\s*(.+)$/im)?.[1]?.trim();
  if (subject) return `Email: ${subject.slice(0, 120)}`;
  const firstLine = raw.trim().split(/\r?\n/)[0] ?? "";
  return `Email: ${firstLine.slice(0, 80)}${firstLine.length > 80 ? "…" : ""}`;
}

function textTarget(text: string): string {
  const t = text.trim().replace(/\s+/g, " ");
  return t.length > 120 ? `${t.slice(0, 120)}…` : t;
}

export function ScanInterface({ backendService = DefaultBackendService, onScanComplete }: ScanInterfaceProps) {
  const [activeTab, setActiveTab] = useState<ScanKind>("url");
  const [urlInput, setUrlInput] = useState("");
  const [emailRaw, setEmailRaw] = useState("");
  const [messageContent, setMessageContent] = useState("");
  const [selectedFile, setSelectedFile] = useState<File | null>(null);

  const [scanningKind, setScanningKind] = useState<ScanKind | null>(null);
  const [report, setReport] = useState<ScanReport | null>(null);
  const [error, setError] = useState<ScanError | null>(null);

  const abortRef = useRef<AbortController | null>(null);
  const onScanCompleteRef = useRef(onScanComplete);
  useEffect(() => {
    onScanCompleteRef.current = onScanComplete;
  }, [onScanComplete]);

  // Abort any in-flight scan on unmount.
  useEffect(() => () => abortRef.current?.abort(), []);

  const runScan = useCallback(
    async (kind: ScanKind) => {
      let target = "";
      let call: (signal: AbortSignal) => Promise<AnalysisResponse>;

      switch (kind) {
        case "url": {
          const url = urlInput.trim();
          if (!url) return;
          target = url;
          call = (signal) => backendService.analyzeUrl(url, signal);
          break;
        }
        case "email": {
          const raw = emailRaw;
          if (!raw.trim()) return;
          if (new Blob([raw]).size > MAX_EMAIL_BYTES) {
            setReport(null);
            setError({ kind, message: "This email is larger than 200 KB. Remove long attachments or quoted replies and try again." });
            return;
          }
          target = emailTarget(raw);
          call = (signal) => backendService.analyzeEmail(raw, signal);
          break;
        }
        case "message": {
          const msg = messageContent.trim();
          if (!msg) return;
          target = textTarget(msg);
          call = (signal) => backendService.analyzeMessage(msg, signal);
          break;
        }
        case "file": {
          const file = selectedFile;
          if (!file) return;
          target = file.name;
          call = (signal) => backendService.analyzeFile(file, signal);
          break;
        }
      }

      abortRef.current?.abort();
      const controller = new AbortController();
      abortRef.current = controller;

      setScanningKind(kind);
      setReport(null);
      setError(null);

      try {
        const response = await call(controller.signal);
        if (controller.signal.aborted) return;
        if (!response?.analysis?.result) {
          throw new Error("The scanner returned an incomplete result — try again.");
        }
        setReport(normalizeAnalysis(kind, response, target));
        onScanCompleteRef.current?.();
      } catch (err) {
        if (isAbortError(err) || controller.signal.aborted) return;
        setError({ kind, message: errorMessage(err, "Couldn't reach the scanner — try again.") });
      } finally {
        if (abortRef.current === controller) {
          abortRef.current = null;
          setScanningKind(null);
        }
      }
    },
    [backendService, urlInput, emailRaw, messageContent, selectedFile]
  );

  const cancelScan = () => {
    abortRef.current?.abort();
    abortRef.current = null;
    setScanningKind(null);
  };

  const reset = () => {
    setReport(null);
    setError(null);
  };

  const isScanning = scanningKind !== null;

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4, ease: "easeOut" }}
      className="space-y-6"
    >
      <Card className="phish-card">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Brain className="w-5 h-5 text-purple-500" aria-hidden="true" />
            Check something suspicious
          </CardTitle>
          <CardDescription>
            Paste a link, email or message, or upload a file. You&apos;ll get a plain-language verdict and what to do next.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Tabs value={activeTab} onValueChange={(v) => setActiveTab(v as ScanKind)} className="w-full">
            <TabsList className="grid w-full grid-cols-2 sm:grid-cols-4 h-auto bg-card/50 backdrop-blur-sm">
              <TabsTrigger value="url" className="tabs-trigger-enhanced flex items-center gap-2">
                <Link className="w-4 h-4" aria-hidden="true" />
                Link
              </TabsTrigger>
              <TabsTrigger value="email" className="tabs-trigger-enhanced flex items-center gap-2">
                <Mail className="w-4 h-4" aria-hidden="true" />
                Email
              </TabsTrigger>
              <TabsTrigger value="message" className="tabs-trigger-enhanced flex items-center gap-2">
                <MessageSquare className="w-4 h-4" aria-hidden="true" />
                Message
              </TabsTrigger>
              <TabsTrigger value="file" className="tabs-trigger-enhanced flex items-center gap-2">
                <Upload className="w-4 h-4" aria-hidden="true" />
                File
              </TabsTrigger>
            </TabsList>

            <TabsContent value="url" className="pt-4">
              <UrlScanForm value={urlInput} onChange={setUrlInput} onSubmit={() => runScan("url")} disabled={isScanning} />
            </TabsContent>
            <TabsContent value="email" className="pt-4">
              <EmailScanForm value={emailRaw} onChange={setEmailRaw} onSubmit={() => runScan("email")} disabled={isScanning} />
            </TabsContent>
            <TabsContent value="message" className="pt-4">
              <MessageScanForm
                value={messageContent}
                onChange={setMessageContent}
                onSubmit={() => runScan("message")}
                disabled={isScanning}
              />
            </TabsContent>
            <TabsContent value="file" className="pt-4">
              <FileScanForm
                file={selectedFile}
                onFileChange={setSelectedFile}
                onSubmit={() => runScan("file")}
                disabled={isScanning}
              />
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>

      {scanningKind && <ScanProgress kind={scanningKind} onCancel={cancelScan} />}

      {error && !isScanning && (
        <Alert variant="destructive" className="border-red-500/60">
          <AlertTriangle className="h-4 w-4" aria-hidden="true" />
          <AlertTitle>The scan didn&apos;t finish</AlertTitle>
          <AlertDescription>
            <p>{error.message}</p>
            <p className="text-muted-foreground">
              No verdict was produced, so don&apos;t treat this item as safe.
            </p>
            <div className="flex gap-2 pt-2">
              <Button size="sm" variant="outline" onClick={() => runScan(error.kind)} className="flex items-center gap-2">
                <RotateCcw className="w-4 h-4" aria-hidden="true" />
                Retry
              </Button>
              <Button size="sm" variant="ghost" onClick={() => setError(null)}>
                Dismiss
              </Button>
            </div>
          </AlertDescription>
        </Alert>
      )}

      {report && !isScanning && <ScanResultReport report={report} onReset={reset} />}
    </motion.div>
  );
}

export default ScanInterface;
