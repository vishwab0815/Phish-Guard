import { useEffect, useState } from "react";
import { Card, CardContent } from "../ui/card";
import { Loader2 } from "lucide-react";
import type { ScanKind } from "./threatLevel";

/**
 * Shown only while a scan request is in flight. It does NOT claim per-step
 * progress (the backend runs checks in parallel and doesn't stream progress);
 * it just describes what the scanner is checking. Timers live in this
 * component and are cleared on unmount, so nothing fires after completion.
 */
const STAGES: Record<ScanKind, string[]> = {
  url: [
    "Checking the link's structure and wording",
    "Looking up the domain",
    "Checking the security certificate",
    "Asking external reputation services (if configured)",
  ],
  email: [
    "Reading the sender and headers",
    "Checking the wording for pressure and scam tactics",
    "Checking links and attachments mentioned",
  ],
  message: [
    "Checking the wording for pressure and scam tactics",
    "Checking any links or payment requests",
  ],
  file: [
    "Uploading the file securely",
    "Checking file type and signatures",
    "Looking for embedded scripts or macros",
    "Asking external malware scanners (if configured)",
  ],
};

export function ScanProgress({ kind, onCancel }: { kind: ScanKind; onCancel?: () => void }) {
  const stages = STAGES[kind];
  const [index, setIndex] = useState(0);

  useEffect(() => {
    const id = setInterval(() => {
      setIndex((i) => (i < stages.length - 1 ? i + 1 : i));
    }, 1500);
    return () => clearInterval(id);
  }, [stages.length]);

  return (
    <Card className="phish-card border-blue-500/50 shadow-lg shadow-blue-500/20">
      <CardContent className="pt-6">
        <div className="space-y-4" role="status" aria-live="polite">
          <div className="flex items-center justify-between gap-4">
            <span className="font-medium flex items-center gap-2">
              <Loader2 className="w-5 h-5 text-blue-500 animate-spin" aria-hidden="true" />
              Scanning… this usually takes a few seconds
            </span>
            {onCancel && (
              <button
                type="button"
                onClick={onCancel}
                className="text-sm text-muted-foreground underline underline-offset-4 hover:text-foreground"
              >
                Cancel
              </button>
            )}
          </div>
          <div className="relative h-2 rounded-full bg-blue-100 dark:bg-blue-950 overflow-hidden" aria-hidden="true">
            <div className="absolute inset-y-0 w-1/3 rounded-full bg-blue-500 animate-[scan-indeterminate_1.4s_ease-in-out_infinite]" />
          </div>
          <ul className="space-y-1 text-sm">
            {stages.map((stage, i) => (
              <li
                key={stage}
                className={i === index ? "text-foreground font-medium" : "text-muted-foreground"}
              >
                {i === index ? "› " : "  "}
                {stage}
              </li>
            ))}
          </ul>
          <style>{`@keyframes scan-indeterminate{0%{left:-33%}100%{left:100%}}`}</style>
        </div>
      </CardContent>
    </Card>
  );
}
