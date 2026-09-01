// Mirror of the Python contract in didileak/models.py (Finding.to_dict /
// ScanResult.to_dict). Keep field names in sync with the CLI JSON output.
// The dashboard never *renders* matched_value; /api/scan additionally strips
// it from the HTTP response and the JSON download (see lib/sanitize.ts).

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Finding {
  rule_id: string;
  rule_name: string;
  category: string; // "secret" | "pii" | "key"
  severity: Severity;
  provider: string;
  conversation_id: string | null;
  conversation_title: string | null;
  message_id: string | null;
  message_index: number | null;
  role: string;
  timestamp: number | null; // epoch seconds
  /** Full value. Present in CLI-generated JSON (incident response); the API route strips it. */
  matched_value?: string;
  masked_value: string;
  span_start: number;
  span_end: number;
  context: string;
  rotation_guide: string | null;
}

export interface ScanResult {
  source: string;
  provider: string;
  messages_scanned: number;
  conversations_scanned: number;
  total_findings: number;
  by_severity: Record<Severity, number>;
  by_category: Record<string, number>;
  by_rule: Record<string, number>;
  parser_warnings: string[];
  findings: Finding[];
}

/** Mirrors Severity.weight in models.py. */
export const SEV_WEIGHT: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

/** Mirrors _SEV_COLOR in reporters/html.py (and tailwind.config.ts). */
export const SEV_COLOR: Record<Severity, string> = {
  critical: "#a83232",
  high: "#c2410c",
  medium: "#b45309",
  low: "#3b5e7e",
  info: "#6b6660",
};
