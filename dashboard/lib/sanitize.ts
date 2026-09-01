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
// Pure functions, no Next.js imports: unit-testable in plain Node.

export interface RawFinding {
  matched_value?: unknown;
  masked_value?: unknown;
  context?: unknown;
  conversation_title?: unknown;
  [key: string]: unknown;
}

export interface RawScanResult {
  findings?: unknown;
  source?: unknown;
  [key: string]: unknown;
}

/**
 * Strip secrets from a CLI-generated ScanResult before it crosses the HTTP
 * boundary. `displaySource` (e.g. the uploaded file's name) replaces the
 * server-side temp path, which must not leak to the client.
 */
export function sanitizeResult(result: RawScanResult, displaySource?: string): RawScanResult {
  const findings = Array.isArray(result?.findings) ? (result.findings as RawFinding[]) : [];

  // Collect (raw, masked) pairs BEFORE stripping the raw values.
  const pairs: Array<[string, string]> = [];
  for (const f of findings) {
    if (typeof f?.matched_value === "string" && f.matched_value.length > 0) {
      const masked =
        typeof f?.masked_value === "string" && f.masked_value.length > 0 ? f.masked_value : "***";
      if (!pairs.some(([raw]) => raw === f.matched_value)) {
        pairs.push([f.matched_value, masked]);
      }
    }
  }
  // Longest first: if one secret contains another, mask the longer one first.
  pairs.sort((a, b) => b[0].length - a[0].length);

  const redact = (value: unknown): string => {
    if (typeof value !== "string") return "";
    let out = value;
    for (const [raw, masked] of pairs) {
      if (out.includes(raw)) out = out.split(raw).join(masked);
    }
    return out;
  };

  const redactNullable = (value: unknown): unknown =>
    typeof value === "string" ? redact(value) : (value ?? null);

  const safeFindings = findings.map((f) => {
    const { matched_value: _raw, ...rest } = f ?? {};
    void _raw;
    // Metadata fields (role, ids, title) are free text from the export and
    // can embed values matched elsewhere, so they go through the same
    // global pair set. `null` stays `null` — the UI distinguishes missing
    // values (renders "(unknown)") from empty strings.
    return {
      ...rest,
      context: redact(f?.context),
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
