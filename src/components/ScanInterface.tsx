import { useState } from "react";
import { motion } from "framer-motion";
import { History, ShieldCheck } from "lucide-react";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "./ui/tabs";
import { BackendService } from "@/utils/BackendService";
import { useLocalHistory, type HistoryEntry } from "@/lib/localHistory";
import type { ScanKind } from "./scan/threatLevel";
import type { ScanRequest } from "./scan/useScanRunner";
import { KIND_META, SCAN_KINDS } from "./scan/kinds";
import { UrlScanForm } from "./scan/UrlScanForm";
import { EmailScanForm } from "./scan/EmailScanForm";
import { MessageScanForm } from "./scan/MessageScanForm";
import { FileScanForm } from "./scan/FileScanForm";
import { RecentList } from "./scan/RecentList";

const MAX_EMAIL_BYTES = 200 * 1024;

interface ScanInterfaceProps {
  kind: ScanKind;
  onKindChange: (kind: ScanKind) => void;
  /** The link field is controlled by the page so `?url=` can prefill it. */
  urlValue: string;
  onUrlChange: (value: string) => void;
  busy: boolean;
  onStart: (request: ScanRequest) => void;
  /** Show a problem with the input (no server call). */
  onInvalid: (kind: ScanKind, target: string, message: string) => void;
  onOpenEntry: (entry: HistoryEntry) => void;
  onShowHistory: () => void;
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

/** Build a scan request for a link (also used by `?url=` auto-scan). */
export function urlScanRequest(url: string): ScanRequest {
  const target = url.trim();
  return { kind: "url", target, run: (signal) => BackendService.analyzeUrl(target, signal) };
}

export function ScanInterface({
  kind,
  onKindChange,
  urlValue,
  onUrlChange,
  busy,
  onStart,
  onInvalid,
  onOpenEntry,
  onShowHistory,
}: ScanInterfaceProps) {
  const [emailRaw, setEmailRaw] = useState("");
  const [messageContent, setMessageContent] = useState("");
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const history = useLocalHistory();
  const recent = history.slice(0, 4);

  const submit = (k: ScanKind) => {
    switch (k) {
      case "url": {
        if (!urlValue.trim()) return;
        onStart(urlScanRequest(urlValue));
        return;
      }
      case "email": {
        const raw = emailRaw;
        if (!raw.trim()) return;
        const target = emailTarget(raw);
        if (new Blob([raw]).size > MAX_EMAIL_BYTES) {
          onInvalid(
            "email",
            target,
            "This email is larger than 200 KB. Remove long attachments or quoted replies and try again."
          );
          return;
        }
        onStart({ kind: "email", target, run: (signal) => BackendService.analyzeEmail(raw, signal) });
        return;
      }
      case "message": {
        const msg = messageContent.trim();
        if (!msg) return;
        onStart({ kind: "message", target: textTarget(msg), run: (signal) => BackendService.analyzeMessage(msg, signal) });
        return;
      }
      case "file": {
        const file = selectedFile;
        if (!file) return;
        onStart({ kind: "file", target: file.name, run: (signal) => BackendService.analyzeFile(file, signal) });
        return;
      }
    }
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3, ease: "easeOut" }}
      className="mx-auto w-full max-w-3xl space-y-6"
    >
      <section className="rounded-2xl border border-border bg-card/80 p-4 shadow-xl shadow-blue-500/5 backdrop-blur-sm sm:p-6">
        <div className="mb-5 space-y-1">
          <h2 className="flex items-center gap-2 text-xl sm:text-2xl">
            <ShieldCheck className="h-6 w-6 text-purple-500" aria-hidden="true" />
            Check something suspicious
          </h2>
          <p className="text-sm text-muted-foreground">
            Paste a link, email or message, or upload a file. You&apos;ll get a plain-language verdict and what to do next.
          </p>
        </div>

        <Tabs value={kind} onValueChange={(v) => onKindChange(v as ScanKind)} className="w-full gap-4">
          <TabsList
            aria-label="What do you want to check?"
            className="grid h-auto w-full grid-cols-4 gap-1 rounded-xl bg-muted p-1"
          >
            {SCAN_KINDS.map((k) => {
              const { Icon, label } = KIND_META[k];
              return (
                <TabsTrigger
                  key={k}
                  value={k}
                  className="flex-col gap-1 rounded-lg py-2 text-xs data-[state=active]:shadow-sm sm:flex-row sm:gap-2 sm:text-sm tabs-trigger-enhanced data-[state=active]:text-white dark:data-[state=active]:text-white"
                >
                  <Icon className="h-4 w-4" aria-hidden="true" />
                  {label}
                </TabsTrigger>
              );
            })}
          </TabsList>

          <TabsContent value="url">
            <UrlScanForm value={urlValue} onChange={onUrlChange} onSubmit={() => submit("url")} disabled={busy} />
          </TabsContent>
          <TabsContent value="email">
            <EmailScanForm value={emailRaw} onChange={setEmailRaw} onSubmit={() => submit("email")} disabled={busy} />
          </TabsContent>
          <TabsContent value="message">
            <MessageScanForm
              value={messageContent}
              onChange={setMessageContent}
              onSubmit={() => submit("message")}
              disabled={busy}
            />
          </TabsContent>
          <TabsContent value="file">
            <FileScanForm
              file={selectedFile}
              onFileChange={setSelectedFile}
              onSubmit={() => submit("file")}
              disabled={busy}
            />
          </TabsContent>
        </Tabs>
      </section>

      {recent.length > 0 && (
        <section className="space-y-2" aria-labelledby="recent-checks-heading">
          <div className="flex items-center justify-between gap-2 px-1">
            <h3 id="recent-checks-heading" className="text-sm font-semibold text-muted-foreground">
              Recent checks
            </h3>
            <button
              type="button"
              onClick={onShowHistory}
              className="inline-flex items-center gap-1 rounded text-xs font-medium text-blue-600 hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring dark:text-blue-400"
            >
              <History className="h-3.5 w-3.5" aria-hidden="true" />
              View all ({history.length})
            </button>
          </div>
          <RecentList entries={recent} onOpen={onOpenEntry} />
        </section>
      )}
    </motion.div>
  );
}

export default ScanInterface;
