"use client";

import type { ScanResult } from "@/lib/types";
import { riskScore, riskLabel } from "@/lib/utils";
import { Severity, SEV_COLOR } from "@/lib/types";

export function Stats({ result }: { result: ScanResult }) {
  const score = riskScore(result.by_severity);
  const { label, color } = riskLabel(score);
  const severities: Severity[] = ["critical", "high", "medium", "low", "info"];

  return (
    <div className="space-y-4">
      {/* Risk badge — small, floats on terracotta */}
      <div>
        <div
          className="inline-flex items-center gap-2.5 px-3.5 py-2 rounded-md2 bg-card shadow-soft-md"
        >
          <span
            className="w-2 h-2 rounded-pixel"
            style={{ background: color }}
          />
          <span
            className="text-[11px] font-semibold uppercase tracking-wider"
            style={{ color }}
          >
            {label}
          </span>
          <span className="text-[11px] font-mono text-text-dim pl-2.5 border-l border-border">
            risk {score}
          </span>
        </div>
      </div>

      {/* Stats grid — cream cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <Stat label="Findings" value={result.total_findings} />
        <Stat label="Messages" value={result.messages_scanned} />
        <Stat label="Conversations" value={result.conversations_scanned} />
        <Stat label="Risk score" value={score} />
      </div>

      {/* Severity pills — pixel squares + label + count */}
      <div className="flex flex-wrap items-center gap-2">
        {severities.map((s) => {
          const n = result.by_severity[s] ?? 0;
          if (n === 0) return null;
          return (
            <span
              key={s}
              className="inline-flex items-center gap-2 px-3 py-1.5 rounded-sm2 bg-card shadow-soft-sm"
            >
              <span
                className="w-2 h-2 rounded-pixel"
                style={{ background: SEV_COLOR[s] }}
              />
              <span className="text-xs text-text font-medium">{s}</span>
              <span className="text-[11px] font-mono font-bold text-text pl-1">{n}</span>
            </span>
          );
        })}
      </div>
    </div>
  );
}

function Stat({ label, value }: { label: string; value: number }) {
  return (
    <div className="bg-card rounded-lg2 p-4 shadow-soft-md">
      <div className="font-sans text-2xl font-bold tracking-tight text-text leading-none">
        {value}
      </div>
      <div className="text-[10px] uppercase tracking-wider text-text-faint mt-1.5 font-medium">
        {label}
      </div>
    </div>
  );
}
