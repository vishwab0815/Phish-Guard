import type { FormEvent } from "react";
import { Button } from "../ui/button";
import { Input } from "../ui/input";
import { Label } from "../ui/label";
import { Globe, Zap } from "lucide-react";

interface UrlScanFormProps {
  value: string;
  onChange: (value: string) => void;
  onSubmit: () => void;
  disabled: boolean;
}

export function UrlScanForm({ value, onChange, onSubmit, disabled }: UrlScanFormProps) {
  const handleSubmit = (e: FormEvent) => {
    e.preventDefault();
    if (!value.trim() || disabled) return;
    onSubmit();
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div className="space-y-2">
        <Label htmlFor="url-input" className="flex items-center gap-2">
          <Globe className="w-4 h-4" aria-hidden="true" />
          Website link or domain
        </Label>
        <Input
          id="url-input"
          type="text"
          inputMode="url"
          autoComplete="off"
          spellCheck={false}
          placeholder="https://example.com or suspicious-site.com"
          value={value}
          onChange={(e) => onChange(e.target.value)}
          className="h-11 bg-background/70 dark:bg-background/40"
          aria-describedby="url-help"
        />
        <p id="url-help" className="text-xs text-muted-foreground">
          Paste the link exactly as you received it. We check the link itself — we don&apos;t open it in your browser.
        </p>
      </div>
      <Button type="submit" disabled={!value.trim() || disabled} className="w-full h-11 text-base text-white security-button">
        <Zap className="w-4 h-4 mr-2" aria-hidden="true" />
        {disabled ? "Checking link…" : "Check this link"}
      </Button>
    </form>
  );
}
