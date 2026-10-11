import type { FormEvent } from "react";
import { Button } from "../ui/button";
import { Textarea } from "../ui/textarea";
import { Label } from "../ui/label";
import { Eye, Mail } from "lucide-react";

interface EmailScanFormProps {
  value: string;
  onChange: (value: string) => void;
  onSubmit: () => void;
  disabled: boolean;
}

export function EmailScanForm({ value, onChange, onSubmit, disabled }: EmailScanFormProps) {
  const handleSubmit = (e: FormEvent) => {
    e.preventDefault();
    if (!value.trim() || disabled) return;
    onSubmit();
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div className="space-y-2">
        <Label htmlFor="email-raw" className="flex items-center gap-2">
          <Mail className="w-4 h-4" aria-hidden="true" />
          Full email
        </Label>
        <Textarea
          id="email-raw"
          placeholder={"Paste the whole email here.\n\nFor the best result include the headers (From, To, Subject…). In Gmail use ⋮ → \"Show original\"; in Outlook use File → Properties → Internet headers."}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          rows={10}
          className="bg-background/70 dark:bg-background/40 font-mono text-sm"
          aria-describedby="email-help"
        />
        <p id="email-help" className="text-xs text-muted-foreground">
          Headers are optional but help us check whether the sender is genuine (SPF/DKIM/DMARC).
        </p>
      </div>
      <Button type="submit" disabled={!value.trim() || disabled} className="w-full h-11 text-base text-white security-button">
        <Eye className="w-4 h-4 mr-2" aria-hidden="true" />
        {disabled ? "Checking email…" : "Check this email"}
      </Button>
    </form>
  );
}
