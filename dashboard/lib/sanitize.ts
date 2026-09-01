// Sanitizer for the web/API contract.
//
// The CLI's JSON report intentionally keeps the full `matched_value` for
// incident response (asserted by tests/test_reporters.py). The dashboard is a
// different trust boundary: it must never ship full secrets to the browser —
// not in the HTTP response, not in React state, not in the JSON download.
// This module strips `matched_value` and redacts every known secret from
// `context` (and titles) using the FULL set of findings, so overlapping
// secrets from other findings are masked too.
//
// Redaction mirrors didileak/reporters/redact.py exactly:
//   1. span surgery — the ±60 context window can cut a neighbouring secret
//      mid-value at its edge; the visible slice is reconstructed from
//      span_start/span_end and replaced by its mask, no string guessing;
//   2. whole-value replacement of every matched_value plus the secret "core"
//      of prefixed matches (`password = X`, `Bearer X`, `scheme://u:p@h`),
//      so bare repetitions survive nowhere.
//
// Pure functions, no Next.js imports: unit-testable in plain Node.

export interface RawFinding {
  matched_value?: unknown;
  masked_value?: unknown;
  context?: unknown;
  conversation_title?: unknown;
  message_id?: unknown;
  span_start?: unknown;
  span_end?: unknown;
  [key: string]: unknown;
}

export interface RawScanResult {
  findings?: unknown;
  source?: unknown;
  [key: string]: unknown;
}

// Must match Message.context()'s default radius in models.py.
const CTX_RADIUS = 60;
// Cores shorter than this are not worth a pair (masks already reveal 4+4).
const MIN_CORE = 8;

// Secret cores hidden inside prefixed matched values; each pattern mirrors
// the corresponding detector rule so it only fires on values that rule
// produced.
const CORE_PATTERNS: RegExp[] = [
  // generic-api-key: "password = VALUE", "api_key: VALUE"
  /[:=]\s*["']?([A-Za-z0-9_-]{16,})["']?\s*$/,
  // bearer-token: "Bearer VALUE"
  /\bbearer\s+([A-Za-z0-9_\-.=]{20,})\s*$/i,
  // connection-string: "scheme://user:PASSWORD@host"
  /^[A-Za-z][A-Za-z0-9+.-]*:\/\/[^:/@\s]+:([^@\s]+)@/,
];

type Pair = [raw: string, masked: string];

// Whole-value lookup indexed by value length: one left-to-right scan per
// text field (try every distinct secret length at each position, longest
// first) instead of one substring search per known pair. Cost per field is
// len(text) x distinct lengths, independent of finding count - replacing N
// pairs per context made an N-finding response O(N^2).
interface PairIndex {
  lengths: number[];
  buckets: Map<number, Map<string, string>>;
}

function buildPairIndex(pairs: Pair[]): PairIndex {
  const buckets = new Map<number, Map<string, string>>();
  for (const [raw, masked] of pairs) {
    let bucket = buckets.get(raw.length);
    if (!bucket) {
      bucket = new Map<string, string>();
      buckets.set(raw.length, bucket);
    }
    bucket.set(raw, masked);
  }
  return { lengths: [...buckets.keys()].sort((a, b) => b - a), buckets };
}

function replaceAll(text: string, index: PairIndex): string {
  const { lengths, buckets } = index;
  const n = text.length;
  const out: string[] = [];
  let i = 0;
  let replaced = false;
  outer: while (i < n) {
    // Binary search over the descending list: skip every length that
    // cannot fit in the remaining text instead of walking past it.
    let lo = 0;
    let hi = lengths.length;
    const remaining = n - i;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if (lengths[mid] > remaining) lo = mid + 1;
      else hi = mid;
    }
    for (let k = lo; k < lengths.length; k++) {
      const j = i + lengths[k];
      const masked = buckets.get(lengths[k])!.get(text.slice(i, j));
      if (masked !== undefined) {
        out.push(masked);
        i = j;
        replaced = true;
        continue outer;
      }
    }
    out.push(text[i]);
    i += 1;
  }
  return replaced ? out.join("") : text;
}

interface Group {
  starts: number[];
  ends: number[];
  maxEnds: number[];
  masks: string[];
}

function str(v: unknown): string | null {
  return typeof v === "string" && v.length > 0 ? v : null;
}

function msgKey(f: RawFinding): string {
  const mid = str(f?.message_id);
  return mid ?? "\0anon";
}

function coreValue(mv: string): string | null {
  for (const pat of CORE_PATTERNS) {
    const m = pat.exec(mv);
    if (m && m[1].length >= MIN_CORE) return m[1];
  }
  return null;
}

function collectPairs(findings: RawFinding[]): Pair[] {
  const pairs: Pair[] = [];
  const known = new Set<string>();
  for (const f of findings) {
    const mv = str(f?.matched_value);
    if (!mv) continue;
    const masked = str(f?.masked_value) ?? "***";
    if (!known.has(mv)) {
      known.add(mv);
      pairs.push([mv, masked]);
    }
    const core = coreValue(mv);
    if (core && !known.has(core)) {
      known.add(core);
      pairs.push([core, masked]);
    }
  }
  // Longest first: if one secret contains another, mask the longer one first.
  pairs.sort((a, b) => b[0].length - a[0].length);
  return pairs;
}

function groupByMessage(findings: RawFinding[]): Map<string, Group> {
  const buckets = new Map<string, RawFinding[]>();
  for (const f of findings) {
    const key = msgKey(f);
    const bucket = buckets.get(key);
    if (bucket) bucket.push(f);
    else buckets.set(key, [f]);
  }
  const groups = new Map<string, Group>();
  for (const [key, members] of buckets) {
    members.sort((a, b) => (Number(a.span_start) || 0) - (Number(b.span_start) || 0));
    const starts: number[] = [];
    const ends: number[] = [];
    const maxEnds: number[] = [];
    const masks: string[] = [];
    let running = 0;
    for (const f of members) {
      const s = Number(f.span_start) || 0;
      const e = Number(f.span_end) || 0;
      running = Math.max(running, e);
      starts.push(s);
      ends.push(e);
      maxEnds.push(running);
      masks.push(str(f?.masked_value) ?? "***");
    }
    groups.set(key, { starts, ends, maxEnds, masks });
  }
  return groups;
}

function upperBound(arr: number[], value: number): number {
  let lo = 0;
  let hi = arr.length;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (arr[mid] <= value) lo = mid + 1;
    else hi = mid;
  }
  return lo;
}

/**
 * Strip secrets from a CLI-generated ScanResult before it crosses the HTTP
 * boundary. `displaySource` (e.g. the uploaded file's name) replaces the
 * server-side temp path, which must not leak to the client.
 */
export function sanitizeResult(result: RawScanResult, displaySource?: string): RawScanResult {
  const findings = Array.isArray(result?.findings) ? (result.findings as RawFinding[]) : [];

  const pairs = collectPairs(findings);
  const pairIndex = buildPairIndex(pairs);
  const groups = groupByMessage(findings);

  const redactText = (value: unknown): string => {
    if (typeof value !== "string") return "";
    return pairIndex.lengths.length > 0 ? replaceAll(value, pairIndex) : value;
  };

  const redactNullable = (value: unknown): unknown =>
    typeof value === "string" ? redactText(value) : (value ?? null);

  // Span-aware context redaction: reconstruct the ±60 window from
  // span_start, then mask every same-message finding slice that is visible
  // in it — including fragments cut off at the window edges.
  const redactContext = (f: RawFinding): string => {
    const ctx = typeof f?.context === "string" ? (f.context as string) : "";
    if (!ctx) return "";

    const spanS = Number(f.span_start) || 0;
    const s = Math.max(0, spanS - CTX_RADIUS);
    let body: string;
    if (s > 0) {
      // A clipped window always starts with the "..." marker that
      // Message.context() prepends; otherwise the geometry is not ours to
      // reason about — fall back to whole-value redaction.
      if (!ctx.startsWith("...")) return redactText(ctx);
      body = ctx.slice(3);
    } else {
      body = ctx;
    }
    let tail = "";
    if (body.endsWith("...")) {
      // Assume the trailing marker; worst case a sub-threshold 3-char
      // residue at the very end of the window.
      tail = "...";
      body = body.slice(0, -3);
    }
    if (!body) return (s > 0 ? "..." : "") + tail;

    // Python offsets (span_start/span_end, and the ±60 window it derives)
    // are in CODE POINTS, but JS string indices are UTF-16 code units: an
    // astral char (emoji, rare CJK) before the secret shifts every offset
    // and leaves raw fragments at the mask edges. The surgery therefore
    // runs on a code-point array and joins back at the end.
    const cps = Array.from(body);
    const cuts = windowCuts(f, s, s + cps.length);
    // Merge overlapping cuts first: two rules can match the same text (e.g.
    // the 40-char rule inside a ghp_ token) and splicing their cuts one by
    // one would leave raw residue in between. Tuple order (start, end,
    // mask) mirrors the Python sort so tie-breaks pick the same mask.
    const byTuple = (
      a: [number, number, string],
      b: [number, number, string]
    ) => a[0] - b[0] || a[1] - b[1] || (a[2] < b[2] ? -1 : a[2] > b[2] ? 1 : 0);
    const merged: Array<[number, number, string]> = [];
    for (const cut of [...cuts].sort(byTuple)) {
      const last = merged[merged.length - 1];
      if (last && cut[0] <= last[1]) {
        last[1] = Math.max(last[1], cut[1]);
      } else {
        merged.push([...cut] as [number, number, string]);
      }
    }
    // Right-to-left (descending tuple) keeps earlier offsets valid while
    // splicing — same as the Python reporter.
    merged.sort((a, b) => -byTuple(a, b));
    for (const [relS, relE, mask] of merged) {
      if (relS < cps.length) {
        const end = Math.min(relE, cps.length);
        if (end > relS) cps.splice(relS, end - relS, mask);
      }
    }

    body = redactText(cps.join(""));
    return (s > 0 ? "..." : "") + body + tail;
  };

  const windowCuts = (
    f: RawFinding,
    s: number,
    e: number
  ): Array<[number, number, string]> => {
    const group = groups.get(msgKey(f));
    if (!group) return [];
    const { starts, ends, maxEnds, masks } = group;
    const out: Array<[number, number, string]> = [];
    let i = upperBound(starts, e - 1);
    while (i > 0) {
      i -= 1;
      if (maxEnds[i] <= s) break; // nothing at or before i reaches the window
      const lo = Math.max(starts[i], s);
      const hi = Math.min(ends[i], e);
      if (hi > lo) out.push([lo - s, hi - s, masks[i]]);
    }
    return out;
  };

  const safeFindings = findings.map((f) => {
    const { matched_value: _raw, ...rest } = f ?? {};
    void _raw;
    // Metadata fields (role, ids, title) are free text from the export and
    // can embed values matched elsewhere, so they go through the same
    // global pair set. `null` stays `null` — the UI distinguishes missing
    // values (renders "(unknown)") from empty strings.
    return {
      ...rest,
      context: redactContext(f ?? {}),
      conversation_title: redactNullable(f?.conversation_title),
      role: redactNullable(f?.role),
      conversation_id: redactNullable(f?.conversation_id),
      message_id: redactNullable(f?.message_id),
    };
  });

  return {
    ...result,
    source: displaySource ?? "scan",
    findings: safeFindings,
  };
}
