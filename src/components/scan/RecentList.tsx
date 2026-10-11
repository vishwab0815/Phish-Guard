import { ChevronRight } from "lucide-react";
import type { HistoryEntry } from "@/lib/localHistory";
import { cn } from "../ui/utils";
import { ThreatBadge } from "./threatLevel";
import { KIND_META, formatRelative } from "./kinds";
import { useNow } from "./useNow";

interface RecentListProps {
  entries: readonly HistoryEntry[];
  onOpen: (entry: HistoryEntry) => void;
  className?: string;
}

/** Compact clickable list of saved checks (verdict + target + time). */
export function RecentList({ entries, onOpen, className }: RecentListProps) {
  const now = useNow();
  return (
    <ul className={cn("divide-y divide-border overflow-hidden rounded-xl border border-border bg-card/60", className)}>
      {entries.map((entry) => {
        const { report } = entry;
        const KindIcon = KIND_META[report.kind].Icon;
        return (
          <li key={entry.id}>
            <button
              type="button"
              onClick={() => onOpen(entry)}
              className="group flex w-full items-center gap-3 px-3 py-2.5 text-left transition-colors hover:bg-muted/60 focus-visible:bg-muted/60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-ring"
            >
              <KindIcon className="h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" />
              <span className="min-w-0 flex-1">
                <span className="block truncate font-mono text-sm" title={report.target}>
                  {report.target}
                </span>
                <span className="block text-xs text-muted-foreground">
                  {KIND_META[report.kind].label}
                  {now > 0 ? ` · ${formatRelative(entry.savedAt, now)}` : ""}
                </span>
              </span>
              <ThreatBadge level={report.level} className="shrink-0" />
              <ChevronRight
                className="hidden h-4 w-4 shrink-0 text-muted-foreground transition-transform group-hover:translate-x-0.5 sm:block"
                aria-hidden="true"
              />
            </button>
          </li>
        );
      })}
    </ul>
  );
}
