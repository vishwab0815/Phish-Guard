import { useCallback, useEffect, useRef, useState } from "react";
import { errorMessage, isAbortError, type AnalysisResponse } from "@/utils/BackendService";
import { localHistory, type HistoryEntry } from "@/lib/localHistory";
import { normalizeAnalysis } from "./report";
import type { ScanKind } from "./threatLevel";

export interface ScanRequest {
  kind: ScanKind;
  /** What the user scanned, for display (never a file's contents). */
  target: string;
  run: (signal: AbortSignal) => Promise<AnalysisResponse>;
}

export type ResultView =
  | { status: "scanning"; kind: ScanKind; target: string }
  | { status: "result"; entry: HistoryEntry }
  | { status: "error"; kind: ScanKind; target: string; message: string; retryable: boolean };

/**
 * Owns the result modal's state machine: scanning → result | error.
 * - Closing the modal while scanning aborts the request.
 * - Successful results are saved to browser-local history.
 * - Never invents a result: failures become an error view with Retry.
 */
export function useScanRunner() {
  const [open, setOpen] = useState(false);
  const [view, setView] = useState<ResultView | null>(null);
  const abortRef = useRef<AbortController | null>(null);
  const lastRequestRef = useRef<ScanRequest | null>(null);

  useEffect(() => () => abortRef.current?.abort(), []);

  const start = useCallback(async (request: ScanRequest) => {
    abortRef.current?.abort();
    const controller = new AbortController();
    abortRef.current = controller;
    lastRequestRef.current = request;

    setView({ status: "scanning", kind: request.kind, target: request.target });
    setOpen(true);

    try {
      const response = await request.run(controller.signal);
      if (controller.signal.aborted) return;
      if (!response?.analysis?.result) {
        throw new Error("The scanner returned an incomplete result — try again.");
      }
      const entry = localHistory.add(normalizeAnalysis(request.kind, response, request.target));
      setView({ status: "result", entry });
    } catch (err) {
      if (isAbortError(err) || controller.signal.aborted) return;
      setView({
        status: "error",
        kind: request.kind,
        target: request.target,
        message: errorMessage(err, "Couldn't reach the scanner — try again."),
        retryable: true,
      });
    } finally {
      if (abortRef.current === controller) abortRef.current = null;
    }
  }, []);

  const retry = useCallback(() => {
    const request = lastRequestRef.current;
    if (request) void start(request);
  }, [start]);

  const showEntry = useCallback((entry: HistoryEntry) => {
    abortRef.current?.abort();
    abortRef.current = null;
    setView({ status: "result", entry });
    setOpen(true);
  }, []);

  /** Show a validation problem (e.g. input too large) without calling the server. */
  const showError = useCallback((kind: ScanKind, target: string, message: string) => {
    abortRef.current?.abort();
    abortRef.current = null;
    lastRequestRef.current = null;
    setView({ status: "error", kind, target, message, retryable: false });
    setOpen(true);
  }, []);

  const close = useCallback(() => {
    abortRef.current?.abort();
    abortRef.current = null;
    setOpen(false);
  }, []);

  return { open, view, start, retry, showEntry, showError, close };
}
