"use client";

import { useMemo, useState } from "react";
import { ChevronUp, ChevronDown, Search } from "lucide-react";
import type { Finding, Severity } from "@/lib/types";
import { SEV_COLOR, SEV_WEIGHT } from "@/lib/types";
import { cn, fmtTs } from "@/lib/utils";

interface Props {
  findings: Finding[];
  onSelect: (f: Finding) => void;
}

type SortKey = "severity" | "rule_name" | "masked_value" | "conversation_title" | "timestamp";

export function FindingsTable({ findings, onSelect }: Props) {
  const [query, setQuery] = useState("");
  const [sevFilter, setSevFilter] = useState<Severity | "">("");
  const [catFilter, setCatFilter] = useState<string>("");
  const [sortKey, setSortKey] = useState<SortKey>("severity");
  const [sortDir, setSortDir] = useState<1 | -1>(-1);

  const filtered = useMemo(() => {
    let rows = findings;
    if (sevFilter) rows = rows.filter((f) => f.severity === sevFilter);
    if (catFilter) rows = rows.filter((f) => f.category === catFilter);
    if (query) {
      const q = query.toLowerCase();
      rows = rows.filter((f) =>
        (f.rule_name + " " + f.rule_id + " " + f.masked_value + " " +
         (f.conversation_title ?? "") + " " + f.context + " " + f.role).toLowerCase().includes(q)
      );
    }
    return [...rows].sort((a, b) => {
      let av: number | string, bv: number | string;
      if (sortKey === "severity") { av = SEV_WEIGHT[a.severity]; bv = SEV_WEIGHT[b.severity]; }
      else if (sortKey === "timestamp") { av = a.timestamp ?? 0; bv = b.timestamp ?? 0; }
      else { av = (a[sortKey] ?? "").toString().toLowerCase(); bv = (b[sortKey] ?? "").toString().toLowerCase(); }
      if (av < bv) return -1 * sortDir;
      if (av > bv) return 1 * sortDir;
      return 0;
    });
  }, [findings, query, sevFilter, catFilter, sortKey, sortDir]);

  const toggleSort = (k: SortKey) => {
    if (sortKey === k) setSortDir((d) => (d === 1 ? -1 : 1));
    else { setSortKey(k); setSortDir(k === "severity" || k === "timestamp" ? -1 : 1); }
  };

  const SortArrow = ({ k }: { k: SortKey }) =>
    sortKey === k ? (sortDir === -1 ? <ChevronDown className="inline w-3 h-3 text-text" /> : <ChevronUp className="inline w-3 h-3 text-text" />) : null;

  return (
    <div className="space-y-3">
      {/* Toolbar — cream card */}
      <div className="flex flex-wrap gap-2 items-center bg-card rounded-md2 p-2.5 shadow-soft-sm">
        <div className="flex-1 min-w-[200px] relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-text-mute" strokeWidth={1.5} />
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Filter by rule, value, conversation, context..."
            className="w-full bg-card-soft border border-border rounded-sm2 pl-9 pr-3 py-1.5 text-sm focus:outline-none focus:border-text-mute placeholder:text-text-mute"
          />
        </div>
        <select value={sevFilter} onChange={(e) => setSevFilter(e.target.value as Severity | "")}
          className="bg-card-soft border border-border rounded-sm2 px-3 py-1.5 text-sm focus:outline-none focus:border-text-mute">
          <option value="">all severities</option>
          <option value="critical">critical</option>
          <option value="high">high</option>
          <option value="medium">medium</option>
          <option value="low">low</option>
          <option value="info">info</option>
        </select>
        <select value={catFilter} onChange={(e) => setCatFilter(e.target.value)}
          className="bg-card-soft border border-border rounded-sm2 px-3 py-1.5 text-sm focus:outline-none focus:border-text-mute">
          <option value="">all categories</option>
          <option value="secret">secret</option>
          <option value="key">key</option>
          <option value="pii">pii</option>
        </select>
        <div className="text-xs text-text-faint ml-auto pr-1.5 font-mono">
          {filtered.length} / {findings.length}
        </div>
      </div>

      {/* Table — cream card */}
      <div className="rounded-lg2 overflow-hidden bg-card shadow-soft-md">
        <div className="overflow-x-auto scroll-area max-h-[600px] overflow-y-auto">
          <table className="w-full text-sm">
            <thead className="sticky top-0 bg-card-soft z-10">
              <tr className="text-text-faint text-[10px] uppercase tracking-wider">
                <Th onClick={() => toggleSort("severity")} width="w-[100px]">Severity <SortArrow k="severity" /></Th>
                <Th onClick={() => toggleSort("rule_name")}>Detector <SortArrow k="rule_name" /></Th>
                <Th onClick={() => toggleSort("masked_value")}>Value <SortArrow k="masked_value" /></Th>
                <Th onClick={() => toggleSort("conversation_title")}>Conversation <SortArrow k="conversation_title" /></Th>
                <th className="text-left p-3 font-semibold">Context</th>
                <Th onClick={() => toggleSort("timestamp")} width="w-[140px]">When <SortArrow k="timestamp" /></Th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((f, i) => (
                <tr
                  key={i}
                  onClick={() => onSelect(f)}
                  className="border-t border-border-soft cursor-pointer hover:bg-card-hover transition-colors"
                >
                  <td className="p-3 whitespace-nowrap">
                    <span
                      className="inline-flex items-center gap-2 font-mono text-[11px] font-semibold uppercase tracking-wider"
                      style={{ color: SEV_COLOR[f.severity] }}
                    >
                      <span
                        className="w-2.5 h-2.5 rounded-pixel"
                        style={{ background: SEV_COLOR[f.severity] }}
                      />
                      {f.severity}
                    </span>
                  </td>
                  <td className="p-3 text-text font-medium">
                    <div className="text-[13px]">{f.rule_name}</div>
                    <div className="text-text-faint font-mono text-[10px] mt-0.5 font-normal">{f.rule_id}</div>
                  </td>
                  <td className="p-3 font-mono text-[12px] text-text-dim break-all">{f.masked_value}</td>
                  <td className="p-3 text-text-dim">
                    <div className="truncate max-w-[200px] text-[13px]">{f.conversation_title ?? "(unknown)"}</div>
                    <div className="text-text-faint font-mono text-[10px] mt-0.5">{f.role}</div>
                  </td>
                  <td className="p-3 text-text-faint font-mono text-[11px] max-w-[320px] truncate">
                    {f.context}
                  </td>
                  <td className="p-3 text-text-faint font-mono text-[10px] whitespace-nowrap">
                    {fmtTs(f.timestamp)}
                  </td>
                </tr>
              ))}
              {filtered.length === 0 && (
                <tr>
                  <td colSpan={6} className="p-10 text-center text-text-faint text-sm">
                    No findings match the current filters.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

function Th({ children, onClick, width }: { children: React.ReactNode; onClick: () => void; width?: string }) {
  return (
    <th
      onClick={onClick}
      className={cn("text-left p-3 font-semibold cursor-pointer hover:text-text-dim whitespace-nowrap select-none", width)}
    >
      {children}
    </th>
  );
}
