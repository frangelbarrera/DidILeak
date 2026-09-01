import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";
import type { Severity } from "./types";

export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs));
}

/** epoch seconds -> locale string; "—" for missing timestamps. */
export function fmtTs(ts: number | null | undefined): string {
  if (ts == null) return "—";
  try {
    return new Date(ts * 1000).toLocaleString();
  } catch {
    return "—";
  }
}

/** Mirrors the risk score in reporters/html.py. */
export function riskScore(by: Partial<Record<Severity, number>>): number {
  return (
    (by.critical ?? 0) * 100 +
    (by.high ?? 0) * 30 +
    (by.medium ?? 0) * 10 +
    (by.low ?? 0) * 2 +
    (by.info ?? 0)
  );
}

/** Mirrors the risk label thresholds in reporters/html.py. */
export function riskLabel(score: number): { label: string; color: string } {
  if (score === 0) return { label: "Clean", color: "#5c7a52" };
  if (score < 50) return { label: "Low", color: "#b45309" };
  if (score < 200) return { label: "Medium", color: "#c2410c" };
  if (score < 500) return { label: "High", color: "#a83232" };
  return { label: "Critical", color: "#a83232" };
}
