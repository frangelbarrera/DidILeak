"use client";

import { X, KeyRound, User, Clock, MessageSquare, FileText } from "lucide-react";
import type { Finding } from "@/lib/types";
import { SEV_COLOR } from "@/lib/types";
import { fmtTs } from "@/lib/utils";

interface Props {
  finding: Finding | null;
  onClose: () => void;
}

export function FindingDetail({ finding, onClose }: Props) {
  if (!finding) return null;

  return (
    <>
      <div
        className="fixed inset-0 z-40"
        style={{ background: "rgba(42,38,34,0.30)" }}
        onClick={onClose}
      />
      <aside className="fixed top-0 right-0 bottom-0 w-full max-w-[500px] bg-card shadow-soft-lg z-50 overflow-y-auto scroll-area">
        <div className="p-8">
          <button
            onClick={onClose}
            className="absolute top-5 right-5 w-7 h-7 rounded-sm2 bg-card-soft text-text-dim hover:bg-card-hover hover:text-text flex items-center justify-center transition-colors"
            aria-label="close"
          >
            <X className="w-4 h-4" />
          </button>

          {/* Tags row — pixel square + severity + category */}
          <div className="flex items-center gap-2 mb-2">
            <span
              className="inline-flex items-center gap-1.5 px-2 py-1 rounded-sm2 bg-card-soft font-mono text-[10px] font-semibold uppercase tracking-wider"
              style={{ color: SEV_COLOR[finding.severity] }}
            >
              <span
                className="w-1.5 h-1.5 rounded-pixel"
                style={{ background: SEV_COLOR[finding.severity] }}
              />
              {finding.severity}
            </span>
            <span className="inline-flex items-center px-2 py-1 rounded-sm2 bg-card-soft font-mono text-[10px] uppercase tracking-wider text-text-dim">
              {finding.category}
            </span>
          </div>

          <h2 className="text-[17px] font-bold tracking-tight text-text mb-1">{finding.rule_name}</h2>
          <div className="text-text-faint font-mono text-[11px] mb-6">{finding.rule_id}</div>

          <Field icon={<KeyRound className="w-3.5 h-3.5" strokeWidth={1.5} />} label="Matched value">
            <span className="font-mono text-[12px] text-text-dim break-all">{finding.masked_value}</span>
          </Field>

          <Field icon={<MessageSquare className="w-3.5 h-3.5" strokeWidth={1.5} />} label="Conversation">
            <span className="text-[13px] text-text-dim">{finding.conversation_title ?? "(unknown)"}</span>
          </Field>

          <Field icon={<User className="w-3.5 h-3.5" strokeWidth={1.5} />} label="Message role">
            <span className="font-mono text-[11px] text-text-dim">{finding.role}</span>
          </Field>

          <Field icon={<Clock className="w-3.5 h-3.5" strokeWidth={1.5} />} label="Timestamp">
            <span className="font-mono text-[11px] text-text-dim">{fmtTs(finding.timestamp)}</span>
          </Field>

          <Field icon={<FileText className="w-3.5 h-3.5" strokeWidth={1.5} />} label="Context">
            <div className="bg-card-soft rounded-md2 p-3 font-mono text-[12px] text-text-dim whitespace-pre-wrap break-words leading-relaxed">
              <Highlight ctx={finding.context} val={finding.masked_value} />
            </div>
          </Field>

          {finding.rotation_guide && (
            <div className="mt-5 bg-card-soft rounded-md2 p-4">
              <div className="text-[10px] font-semibold uppercase tracking-wider text-text-faint mb-1.5">
                Rotation guide
              </div>
              <div className="text-[13px] text-text-dim leading-relaxed">{finding.rotation_guide}</div>
            </div>
          )}
        </div>
      </aside>
    </>
  );
}

function Field({ icon, label, children }: { icon: React.ReactNode; label: string; children: React.ReactNode }) {
  return (
    <div className="mb-4">
      <div className="flex items-center gap-1.5 text-text-faint text-[10px] uppercase tracking-wider mb-1.5 font-semibold">
        {icon}
        {label}
      </div>
      <div className="ml-4">{children}</div>
    </div>
  );
}

function Highlight({ ctx, val }: { ctx: string; val: string }) {
  if (!val) return <>{ctx}</>;
  const i = ctx.indexOf(val);
  if (i < 0) return <>{ctx}</>;
  return (
    <>
      {ctx.slice(0, i)}
      <mark className="bg-sev-critical/15 text-text px-0.5 rounded-pixel">{val}</mark>
      {ctx.slice(i + val.length)}
    </>
  );
}
