import type { FormEvent } from "react";
import { Button } from "../ui/button";
import { Textarea } from "../ui/textarea";
import { Label } from "../ui/label";
import { MessageSquare, Shield } from "lucide-react";

interface MessageScanFormProps {
  value: string;
  onChange: (value: string) => void;
  onSubmit: () => void;
  disabled: boolean;
}

export function MessageScanForm({ value, onChange, onSubmit, disabled }: MessageScanFormProps) {
  const handleSubmit = (e: FormEvent) => {
    e.preventDefault();
    if (!value.trim() || disabled) return;
    onSubmit();
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div className="space-y-2">
        <Label htmlFor="message-content" className="flex items-center gap-2">
          <MessageSquare className="w-4 h-4" aria-hidden="true" />
          SMS, WhatsApp or chat message
        </Label>
        <Textarea
          id="message-content"
          placeholder="Paste the message you received…"
          value={value}
          onChange={(e) => onChange(e.target.value)}
          rows={6}
          className="bg-background/70 dark:bg-background/40"
          aria-describedby="message-help"
        />
        <p id="message-help" className="text-xs text-muted-foreground">
          We look for pressure tactics, fake prizes, KYC/OTP requests and suspicious payment asks.
        </p>
      </div>
      <Button type="submit" disabled={!value.trim() || disabled} className="w-full h-11 text-base text-white security-button">
        <Shield className="w-4 h-4 mr-2" aria-hidden="true" />
        {disabled ? "Checking message…" : "Check this message"}
      </Button>
    </form>
  );
}
