import { useEffect, useState } from "react";
import { motion, useReducedMotion } from "framer-motion";
import { Loader2, ShieldCheck } from "lucide-react";
import type { ScanKind } from "./threatLevel";

/**
 * Shown inside the result modal while a scan request is in flight.
 * Honest by design: the backend runs its checks in parallel and doesn't stream
 * progress, so we list what is being checked, show an indeterminate bar and a
 * real elapsed-time counter — no fake percentages. The timer is cleared on unmount.
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

export function ScanProgress({ kind }: { kind: ScanKind }) {
  const stages = STAGES[kind];
  const reduceMotion = useReducedMotion();
  const [elapsed, setElapsed] = useState(0);

  useEffect(() => {
    const started = Date.now();
    const id = setInterval(() => setElapsed(Math.floor((Date.now() - started) / 1000)), 1000);
    return () => clearInterval(id);
  }, []);

  return (
    <div className="space-y-6" role="status" aria-live="polite">
      <div className="flex flex-col items-center gap-4 text-center">
        <div className="relative flex h-20 w-20 items-center justify-center">
          {!reduceMotion && (
            <motion.span
              aria-hidden="true"
              className="absolute inset-0 rounded-full bg-blue-500/20 dark:bg-blue-400/20"
              animate={{ scale: [1, 1.35, 1], opacity: [0.6, 0, 0.6] }}
              transition={{ duration: 2, repeat: Infinity, ease: "easeInOut" }}
            />
          )}
          <span className="relative flex h-16 w-16 items-center justify-center rounded-full bg-gradient-to-br from-blue-500 to-purple-600 shadow-lg shadow-purple-500/30">
            <ShieldCheck className="h-8 w-8 text-white" aria-hidden="true" />
          </span>
        </div>
        <div className="space-y-1">
          <p className="text-lg font-semibold">Checking it now…</p>
          <p className="text-sm text-muted-foreground">
            This usually takes a few seconds{elapsed >= 2 ? ` · ${elapsed}s` : ""}
          </p>
        </div>
      </div>

      <div className="relative h-1.5 overflow-hidden rounded-full bg-blue-100 dark:bg-blue-950" aria-hidden="true">
        {reduceMotion ? (
          <div className="absolute inset-0 rounded-full bg-gradient-to-r from-blue-500 to-purple-500 opacity-70" />
        ) : (
          <motion.div
            className="absolute inset-y-0 w-1/3 rounded-full bg-gradient-to-r from-blue-500 to-purple-500"
            initial={{ x: "-100%" }}
            animate={{ x: "300%" }}
            transition={{ duration: 1.4, repeat: Infinity, ease: "easeInOut" }}
          />
        )}
      </div>

      <div className="space-y-2">
        <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Running these checks</p>
        <ul className="space-y-2">
          {stages.map((stage, i) => (
            <motion.li
              key={stage}
              initial={reduceMotion ? false : { opacity: 0, y: 6 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.12, duration: 0.25 }}
              className="flex items-center gap-3 rounded-lg border border-border bg-muted/40 px-3 py-2 text-sm"
            >
              <Loader2 className="h-4 w-4 shrink-0 animate-spin text-blue-500" aria-hidden="true" />
              <span>{stage}</span>
            </motion.li>
          ))}
        </ul>
      </div>
    </div>
  );
}
