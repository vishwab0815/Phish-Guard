import type { ReactNode } from "react";

/**
 * Tiny, dependency-free markdown renderer for chat messages.
 * Supports headings, bullet/numbered lists, **bold**, *italic* / _italic_, `code`, fenced code
 * blocks and line breaks. Everything is rendered as React text nodes (no
 * dangerouslySetInnerHTML), so HTML in the input is always escaped.
 * Links are intentionally NOT made clickable.
 */

function renderInline(text: string, keyPrefix: string): ReactNode[] {
  // Italic markers must sit at word boundaries, so snake_case and URLs aren't affected.
  const parts = text.split(/(\*\*[^*]+\*\*|`[^`]+`|(?<![\w*])\*[^*\s][^*]*?\*(?![\w*])|(?<!\w)_[^_\s][^_]*?_(?!\w))/g);
  return parts
    .filter((p) => p !== "")
    .map((part, i) => {
      const key = `${keyPrefix}-${i}`;
      if (part.startsWith("**") && part.endsWith("**") && part.length > 4) {
        return <strong key={key}>{part.slice(2, -2)}</strong>;
      }
      if (part.length > 2 && ((part.startsWith("*") && part.endsWith("*")) || (part.startsWith("_") && part.endsWith("_")))) {
        return <em key={key}>{part.slice(1, -1)}</em>;
      }
      if (part.startsWith("`") && part.endsWith("`") && part.length > 2) {
        return (
          <code key={key} className="rounded bg-black/10 dark:bg-white/10 px-1 py-0.5 font-mono text-[0.85em]">
            {part.slice(1, -1)}
          </code>
        );
      }
      return <span key={key}>{part}</span>;
    });
}

type Block =
  | { type: "p"; lines: string[] }
  | { type: "h"; text: string }
  | { type: "ul"; items: string[] }
  | { type: "ol"; items: string[] }
  | { type: "code"; lines: string[] };

function parse(markdown: string): Block[] {
  const blocks: Block[] = [];
  const lines = markdown.replace(/\r\n/g, "\n").split("\n");
  let i = 0;

  while (i < lines.length) {
    const line = lines[i];
    const trimmed = line.trim();

    if (trimmed.startsWith("```")) {
      const code: string[] = [];
      i++;
      while (i < lines.length && !lines[i].trim().startsWith("```")) {
        code.push(lines[i]);
        i++;
      }
      i++; // closing fence
      blocks.push({ type: "code", lines: code });
      continue;
    }

    if (trimmed === "") {
      i++;
      continue;
    }

    const heading = trimmed.match(/^#{1,6}\s+(.*)$/);
    if (heading) {
      blocks.push({ type: "h", text: heading[1] });
      i++;
      continue;
    }

    if (/^([-*•])\s+/.test(trimmed)) {
      const items: string[] = [];
      while (i < lines.length && /^([-*•])\s+/.test(lines[i].trim())) {
        items.push(lines[i].trim().replace(/^([-*•])\s+/, ""));
        i++;
      }
      blocks.push({ type: "ul", items });
      continue;
    }

    if (/^\d+[.)]\s+/.test(trimmed)) {
      const items: string[] = [];
      while (i < lines.length && /^\d+[.)]\s+/.test(lines[i].trim())) {
        items.push(lines[i].trim().replace(/^\d+[.)]\s+/, ""));
        i++;
      }
      blocks.push({ type: "ol", items });
      continue;
    }

    const para: string[] = [];
    while (
      i < lines.length &&
      lines[i].trim() !== "" &&
      !/^(#{1,6}\s|[-*•]\s|\d+[.)]\s|```)/.test(lines[i].trim())
    ) {
      para.push(lines[i].trim());
      i++;
    }
    blocks.push({ type: "p", lines: para });
  }
  return blocks;
}

export function SimpleMarkdown({ text, className }: { text: string; className?: string }) {
  const blocks = parse(text);
  return (
    <div className={`space-y-2 break-words ${className ?? ""}`}>
      {blocks.map((block, bi) => {
        const key = `b${bi}`;
        switch (block.type) {
          case "h":
            return (
              <p key={key} className="font-semibold">
                {renderInline(block.text, key)}
              </p>
            );
          case "ul":
            return (
              <ul key={key} className="list-disc pl-5 space-y-1">
                {block.items.map((item, ii) => (
                  <li key={`${key}-${ii}`}>{renderInline(item, `${key}-${ii}`)}</li>
                ))}
              </ul>
            );
          case "ol":
            return (
              <ol key={key} className="list-decimal pl-5 space-y-1">
                {block.items.map((item, ii) => (
                  <li key={`${key}-${ii}`}>{renderInline(item, `${key}-${ii}`)}</li>
                ))}
              </ol>
            );
          case "code":
            return (
              <pre key={key} className="rounded bg-black/10 dark:bg-white/10 p-2 font-mono text-xs overflow-x-auto whitespace-pre">
                {block.lines.join("\n")}
              </pre>
            );
          default:
            return (
              <p key={key}>
                {block.lines.map((l, li) => (
                  <span key={`${key}-${li}`}>
                    {li > 0 && <br />}
                    {renderInline(l, `${key}-${li}`)}
                  </span>
                ))}
              </p>
            );
        }
      })}
    </div>
  );
}
