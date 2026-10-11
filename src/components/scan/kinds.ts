import type { ComponentType } from "react";
import { FileText, Link2, Mail, MessageSquare } from "lucide-react";
import type { ScanKind } from "./threatLevel";

export const SCAN_KINDS: readonly ScanKind[] = ["url", "email", "message", "file"];

export const KIND_META: Record<ScanKind, { label: string; Icon: ComponentType<{ className?: string }> }> = {
  url: { label: "Link", Icon: Link2 },
  email: { label: "Email", Icon: Mail },
  message: { label: "Message", Icon: MessageSquare },
  file: { label: "File", Icon: FileText },
};

/** id of the primary input for each scan type (used to restore focus). */
export const KIND_INPUT_ID: Record<ScanKind, string> = {
  url: "url-input",
  email: "email-raw",
  message: "message-content",
  file: "file-choose",
};

export function isScanKind(value: unknown): value is ScanKind {
  return typeof value === "string" && (SCAN_KINDS as readonly string[]).includes(value);
}

export function formatDuration(ms: number): string {
  return ms < 1000 ? `${Math.round(ms)} ms` : `${(ms / 1000).toFixed(1)} s`;
}

export function formatDateTime(iso: string | null): string {
  if (!iso) return "Not available";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "Not available" : d.toLocaleString();
}

/** Short relative time ("just now", "5 min ago", "yesterday"). Client-only (uses the current clock). */
export function formatRelative(iso: string, now: number = Date.now()): string {
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return "";
  const diff = Math.max(0, now - t);
  const min = Math.floor(diff / 60000);
  if (min < 1) return "just now";
  if (min < 60) return `${min} min ago`;
  const h = Math.floor(min / 60);
  if (h < 24) return `${h} h ago`;
  const d = Math.floor(h / 24);
  if (d === 1) return "yesterday";
  if (d < 7) return `${d} days ago`;
  return new Date(t).toLocaleDateString();
}
