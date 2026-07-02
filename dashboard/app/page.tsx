"use client";

import { useState } from "react";
import { Upload } from "@/components/upload";
import { Stats } from "@/components/stats";
import { FindingsTable } from "@/components/findings-table";
import { FindingDetail } from "@/components/finding-detail";
import type { Finding, ScanResult } from "@/lib/types";
import { AlertTriangle, ShieldCheck, Github, BookOpen } from "lucide-react";

export default function Home() {
  const [result, setResult] = useState<ScanResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<Finding | null>(null);

  const onFile = async (file: File, provider: string | undefined) => {
    setLoading(true);
    setError(null);
    try {
      const isPrebuilt =
        file.name.includes("didileak_report") && file.name.endsWith(".json");
      let data: ScanResult;
      if (isPrebuilt) {
        const text = await file.text();
        data = JSON.parse(text);
      } else {
        const form = new FormData();
        form.append("file", file);
        if (provider) form.append("provider", provider);
        const res = await fetch("/api/scan", { method: "POST", body: form });
        if (!res.ok) {
          const e = await res.json().catch(() => ({ error: "scan failed" }));
          throw new Error(e.error || `scan failed (${res.status})`);
        }
        data = (await res.json()) as ScanResult;
      }
      setResult(data);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  };

  return (
    <main className="min-h-screen flex flex-col">
      {/* Header — just the app name on terracotta */}
      <header className="border-b border-on-bg/15">
        <div className="max-w-5xl mx-auto px-6 py-5 flex items-center justify-between">
          <h1 className="text-xl font-bold tracking-tight text-on-bg">DidILeak</h1>
          <div className="flex items-center gap-4 text-xs">
            <a href="https://github.com/frangelbarrera/DidILeak" target="_blank" rel="noreferrer"
              className="flex items-center gap-1.5 text-on-bg-faint hover:text-on-bg transition-colors">
              <Github className="w-3.5 h-3.5" strokeWidth={1.5} /> GitHub
            </a>
            <a href="https://github.com/frangelbarrera/OSINT-BIBLE" target="_blank" rel="noreferrer"
              className="flex items-center gap-1.5 text-on-bg-faint hover:text-on-bg transition-colors">
              <BookOpen className="w-3.5 h-3.5" strokeWidth={1.5} /> OSINT-BIBLE
            </a>
          </div>
        </div>
      </header>

      <div className="flex-1 max-w-5xl mx-auto w-full px-6 py-10 space-y-8">
        {!result && (
          <section>
            <h2 className="text-2xl font-bold tracking-tight text-on-bg mb-2">
              What did you paste into ChatGPT?
            </h2>
            <p className="text-on-bg-dim text-sm max-w-2xl leading-relaxed">
              Drop your ChatGPT, Claude, or Cursor export.{" "}
              <span className="text-on-bg font-medium">DidILeak</span> scans every message for API
              keys, tokens, passwords, and PII you may have leaked — and tells you exactly how to
              rotate them.
            </p>
            <p className="text-on-bg-faint text-xs mt-3 italic">
              OSINT-BIBLE taught you to investigate others. DidILeak teaches you to investigate yourself.
            </p>
          </section>
        )}

        {!result && (
          <section className="bg-card rounded-lg2 p-6 shadow-soft-md">
            <Upload onFile={onFile} loading={loading} />
            {error && (
              <div className="mt-4 flex items-start gap-2 bg-card-soft rounded-md2 p-3 text-xs">
                <AlertTriangle className="w-3.5 h-3.5 flex-shrink-0 mt-0.5 text-sev-critical" strokeWidth={1.5} />
                <div>
                  <span className="text-text font-medium">Scan failed.</span>{" "}
                  <span className="text-text-dim">{error}</span>
                </div>
              </div>
            )}
          </section>
        )}

        {result && (
          <>
            <Stats result={result} />

            {result.total_findings === 0 ? (
              <div className="bg-card rounded-lg2 p-12 text-center shadow-soft-md">
                <ShieldCheck className="w-9 h-9 mx-auto mb-3 text-ok" strokeWidth={1.5} />
                <div className="text-base font-semibold text-ok mb-1">Clean.</div>
                <p className="text-text-dim text-sm">
                  No secrets or PII detected in this export. Stay vigilant.
                </p>
              </div>
            ) : (
              <FindingsTable findings={result.findings} onSelect={setSelected} />
            )}

            <div className="flex gap-2">
              <button
                onClick={() => { setResult(null); setError(null); }}
                className="px-4 py-2 rounded-sm2 bg-card text-text-dim text-xs font-medium hover:bg-card-soft transition-colors shadow-soft-sm"
              >
                Scan another file
              </button>
              {result.total_findings > 0 && (
                <button
                  onClick={() => downloadJson(result)}
                  className="px-4 py-2 rounded-sm2 bg-card text-text-dim text-xs font-medium hover:bg-card-soft transition-colors shadow-soft-sm"
                >
                  Download JSON report
                </button>
              )}
            </div>

            {result.parser_warnings.length > 0 && (
              <details className="bg-card rounded-md2 p-3 text-xs shadow-soft-sm">
                <summary className="cursor-pointer text-text-dim font-medium">
                  {result.parser_warnings.length} parser warning(s)
                </summary>
                <ul className="mt-2 text-text-faint space-y-1">
                  {result.parser_warnings.map((w, i) => <li key={i}>· {w}</li>)}
                </ul>
              </details>
            )}
          </>
        )}
      </div>

      <footer className="mt-auto border-t border-on-bg/15">
        <div className="max-w-5xl mx-auto px-6 py-4 text-center text-[11px] text-on-bg-faint">
          Generated by{" "}
          <a href="https://github.com/frangelbarrera/DidILeak" className="text-on-bg-dim hover:text-on-bg">
            DidILeak
          </a>{" "}
          · OSINT-BIBLE taught you to investigate others. DidILeak teaches you to investigate yourself.
        </div>
      </footer>

      <FindingDetail finding={selected} onClose={() => setSelected(null)} />
    </main>
  );
}

function downloadJson(result: ScanResult) {
  const blob = new Blob([JSON.stringify(result, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "didileak_report.json";
  a.click();
  URL.revokeObjectURL(url);
}
