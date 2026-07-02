"use client";

import { useCallback, useState } from "react";
import { UploadCloud, AlertTriangle } from "lucide-react";
import { cn } from "@/lib/utils";

interface Props {
  onFile: (file: File, provider: string | undefined) => void;
  loading: boolean;
}

const PROVIDERS = [
  { value: "", label: "Auto-detect" },
  { value: "chatgpt", label: "ChatGPT" },
  { value: "claude", label: "Claude" },
  { value: "cursor", label: "Cursor" },
  { value: "generic", label: "Generic JSON" },
];

export function Upload({ onFile, loading }: Props) {
  const [dragOver, setDragOver] = useState(false);
  const [selected, setSelected] = useState<File | null>(null);
  const [provider, setProvider] = useState<string>("");

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setDragOver(false);
      const f = e.dataTransfer.files?.[0];
      if (f) setSelected(f);
    },
    []
  );

  const handleSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0];
    if (f) setSelected(f);
  };

  const submit = () => {
    if (selected) onFile(selected, provider || undefined);
  };

  return (
    <div className="space-y-4">
      <label
        onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
        onDragLeave={() => setDragOver(false)}
        onDrop={handleDrop}
        className={cn(
          "flex flex-col items-center justify-center gap-3 rounded-lg2 p-12 cursor-pointer transition-colors border-2 border-dashed",
          dragOver ? "border-text-mute bg-card-soft" : "border-border hover:border-text-mute hover:bg-card-soft"
        )}
      >
        <UploadCloud className="w-8 h-8 text-text-faint" strokeWidth={1.5} />
        <div className="text-center">
          <div className="text-sm font-medium text-text">
            {selected ? selected.name : "Drop your LLM export here"}
          </div>
          <div className="text-xs text-text-faint mt-1">
            {selected
              ? `${(selected.size / 1024).toFixed(1)} KB — ready to scan`
              : "ChatGPT conversations.json · Claude HTML/JSON · Cursor JSON · or a pre-built didileak_report.json"}
          </div>
        </div>
        <input type="file" className="hidden" onChange={handleSelect} accept=".json,.html,.htm" />
      </label>

      <div className="flex flex-wrap gap-3 items-end">
        <div className="flex-1 min-w-[200px]">
          <label className="block text-[10px] uppercase tracking-wider text-text-faint mb-1.5 font-semibold">Provider</label>
          <select
            value={provider}
            onChange={(e) => setProvider(e.target.value)}
            className="w-full bg-card-soft border border-border rounded-sm2 px-3 py-2 text-sm focus:outline-none focus:border-text-mute"
          >
            {PROVIDERS.map((p) => (
              <option key={p.value} value={p.value}>{p.label}</option>
            ))}
          </select>
        </div>
        <button
          onClick={submit}
          disabled={!selected || loading}
          className={cn(
            "px-5 py-2 rounded-sm2 text-sm font-semibold transition-colors",
            !selected || loading
              ? "bg-card-soft text-text-faint cursor-not-allowed border border-border"
              : "bg-text text-card hover:bg-text-dim"
          )}
        >
          {loading ? "Scanning…" : "Scan for leaks"}
        </button>
      </div>

      <div className="flex items-start gap-2 text-xs text-text-faint bg-card-soft rounded-md2 p-3">
        <AlertTriangle className="w-3.5 h-3.5 flex-shrink-0 mt-0.5 text-text-faint" strokeWidth={1.5} />
        <div>
          <span className="text-text-dim font-medium">Privacy.</span> The file is processed locally by the
          didileak Python CLI on this server. No data leaves your deployment. For paranoid use,
          run <code className="font-mono text-text-dim">didileak scan</code> in a sandboxed VM and
          upload only the resulting <code className="font-mono text-text-dim">didileak_report.json</code>{" "}
          to this dashboard.
        </div>
      </div>
    </div>
  );
}
