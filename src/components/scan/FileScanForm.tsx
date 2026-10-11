import { useRef, useState, type DragEvent } from "react";
import { Button } from "../ui/button";
import { FileText, Shield, Upload } from "lucide-react";

const MAX_FILE_BYTES = 100 * 1024 * 1024;

interface FileScanFormProps {
  file: File | null;
  onFileChange: (file: File | null) => void;
  onSubmit: () => void;
  disabled: boolean;
}

function formatSize(bytes: number) {
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export function FileScanForm({ file, onFileChange, onSubmit, disabled }: FileScanFormProps) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [isDragging, setIsDragging] = useState(false);
  const tooLarge = !!file && file.size > MAX_FILE_BYTES;
  const empty = !!file && file.size === 0;

  const handleDrop = (event: DragEvent) => {
    event.preventDefault();
    setIsDragging(false);
    const dropped = event.dataTransfer.files?.[0];
    if (dropped) onFileChange(dropped);
  };

  return (
    <div
      className={`border-2 border-dashed rounded-lg p-8 text-center glass-effect transition-all ${
        isDragging ? "border-blue-500 bg-blue-50 dark:bg-blue-950/20" : "border-border/50"
      }`}
      onDragOver={(e) => {
        e.preventDefault();
        setIsDragging(true);
      }}
      onDragLeave={() => setIsDragging(false)}
      onDrop={handleDrop}
    >
      <input
        ref={inputRef}
        type="file"
        id="file-upload"
        className="sr-only"
        onChange={(e) => {
          onFileChange(e.target.files?.[0] ?? null);
          e.target.value = "";
        }}
        disabled={disabled}
      />

      {file ? (
        <div className="space-y-3">
          <div className="bg-card/50 backdrop-blur-sm rounded-lg p-4 max-w-md mx-auto">
            <div className="flex items-start gap-3">
              <FileText className="w-5 h-5 text-blue-500 mt-1" aria-hidden="true" />
              <div className="flex-1 text-left">
                <p className="font-medium break-all">{file.name}</p>
                <p className="text-sm text-muted-foreground">Size: {formatSize(file.size)}</p>
                <p className="text-sm text-muted-foreground">Type: {file.type || "Unknown"}</p>
              </div>
            </div>
          </div>
          {tooLarge && (
            <p className="text-sm text-red-600 dark:text-red-400" role="alert">
              This file is larger than 100 MB and can&apos;t be scanned.
            </p>
          )}
          {empty && (
            <p className="text-sm text-red-600 dark:text-red-400" role="alert">
              This file is empty.
            </p>
          )}
          <div className="flex gap-2 justify-center">
            <Button onClick={onSubmit} disabled={disabled || tooLarge || empty} className="security-button">
              <Shield className="w-4 h-4 mr-2" aria-hidden="true" />
              {disabled ? "Checking file…" : "Check this file"}
            </Button>
            <Button variant="outline" onClick={() => onFileChange(null)} disabled={disabled}>
              Clear
            </Button>
          </div>
        </div>
      ) : (
        <>
          <Upload
            className={`w-12 h-12 mx-auto mb-4 ${isDragging ? "text-blue-500 animate-bounce" : "text-muted-foreground"}`}
            aria-hidden="true"
          />
          <p className="text-lg font-medium mb-2">Check a file</p>
          <p className="text-sm text-muted-foreground mb-4">
            Drop a file here or choose one (max 100 MB).
          </p>
          <Button
            variant="outline"
            className="security-button"
            onClick={() => inputRef.current?.click()}
            disabled={disabled}
          >
            <Upload className="w-4 h-4 mr-2" aria-hidden="true" />
            Choose a file
          </Button>
          <p className="text-xs text-muted-foreground mt-3">
            The file is uploaded to PhishGuard for analysis. Don&apos;t upload documents containing private information.
          </p>
        </>
      )}
    </div>
  );
}
