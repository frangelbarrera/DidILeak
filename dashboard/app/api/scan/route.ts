import { NextRequest, NextResponse } from "next/server";
import { spawn } from "child_process";
import { timingSafeEqual } from "crypto";
import { writeFile, mkdtemp, readFile, rm } from "fs/promises";
import { tmpdir } from "os";
import { join } from "path";
import { sanitizeResult } from "@/lib/sanitize";

export const runtime = "nodejs";
export const maxDuration = 60;

// ---------------------------------------------------------------------------
// Guardrails: this route executes a per-request child process, so it
// needs application-level limits. All limits are in-process and dependency
// free; adjust via env if a deployment genuinely needs different values.
// ---------------------------------------------------------------------------

/** Max upload size in bytes (also enforced client-side in components/upload). */
const _envMaxBytes = Number(process.env.DIDILEAK_MAX_UPLOAD_BYTES);
const MAX_UPLOAD_BYTES =
  Number.isFinite(_envMaxBytes) && _envMaxBytes > 0 ? _envMaxBytes : 20 * 1024 * 1024;
/** File extensions we are willing to parse (exports are JSON or Claude HTML). */
const ALLOWED_EXTENSIONS = new Set(["json", "html", "htm"]);
/** Hard cap on concurrent CLI scans (each spawns a Python process). */
const MAX_CONCURRENT_SCANS = 2;
/** Kill the CLI process after this many milliseconds. */
const SCAN_TIMEOUT_MS = 55_000;
/** Per-client-IP request budget (sliding window). */
const RATE_WINDOW_MS = 60_000;
const RATE_MAX_REQUESTS = 10;
/**
 * Optional bearer token. If DIDILEAK_API_TOKEN is set, every request must
 * present `Authorization: Bearer <token>`; unset keeps local/self-hosted
 * single-user usage working without configuration.
 */
const API_TOKEN = process.env.DIDILEAK_API_TOKEN;

let inFlight = 0;
const rateHits = new Map<string, number[]>();

function clientKey(req: NextRequest): string {
  // Trust model: with a reverse proxy in front, the LAST forwarded entry is
  // the one our proxy appended; anything before it is client-supplied and
  // therefore spoofable. Without a proxy this key is advisory only.
  const fwd = req.headers.get("x-forwarded-for");
  if (fwd) return fwd.split(",").pop()!.trim();
  return req.headers.get("x-real-ip") ?? "local";
}

function isRateLimited(key: string): boolean {
  if (rateHits.size > 10_000) rateHits.clear(); // hard cap on tracking state
  const now = Date.now();
  const window = (rateHits.get(key) ?? []).filter((t) => now - t < RATE_WINDOW_MS);
  if (window.length === 0) {
    rateHits.delete(key); // don't retain state for clients that went quiet
  } else {
    rateHits.set(key, window);
  }
  if (window.length >= RATE_MAX_REQUESTS) {
    return true;
  }
  window.push(now);
  rateHits.set(key, window);
  return false;
}

function isAuthorized(req: NextRequest): boolean {
  if (!API_TOKEN) return true;
  const header = req.headers.get("authorization") ?? "";
  const presented = Buffer.from(header.startsWith("Bearer ") ? header.slice(7) : "");
  const expected = Buffer.from(API_TOKEN);
  // Length check first: timingSafeEqual throws on length mismatch.
  return (
    presented.length === expected.length &&
    timingSafeEqual(presented, expected)
  );
}

// ---------------------------------------------------------------------------
// Client-safe errors: never surface e.message, stderr, or server paths.
// ---------------------------------------------------------------------------

class ScanError extends Error {
  constructor(
    message: string,
    readonly status: number
  ) {
    super(message);
  }
}

/**
 * POST /api/scan
 * Body: multipart/form-data with `file` (the export file) and optional `provider`.
 *
 * Writes the file to a temp dir, runs `didileak scan --json <out>`, reads the
 * JSON report, and returns a SANITIZED copy of it: `matched_value` is stripped
 * and contexts are redacted, so full secrets never reach the browser.
 * The Python CLI must be on PATH: `pip install -e .` from the repo root.
 */
export async function POST(req: NextRequest) {
  if (!isAuthorized(req)) {
    return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  }
  const key = clientKey(req);
  if (isRateLimited(key)) {
    return NextResponse.json(
      { error: "too many requests; wait a minute and retry" },
      { status: 429 }
    );
  }
  if (inFlight >= MAX_CONCURRENT_SCANS) {
    return NextResponse.json({ error: "server busy; retry shortly" }, { status: 429 });
  }
  // Cheap early rejection before the body is buffered anywhere.
  const declared = Number(req.headers.get("content-length") ?? 0);
  if (declared > MAX_UPLOAD_BYTES + 64 * 1024) {
    return NextResponse.json({ error: "file too large" }, { status: 413 });
  }

  let tmpDir: string | null = null;
  inFlight++;
  try {
    const contentType = req.headers.get("content-type") ?? "";
    if (!contentType.includes("multipart/form-data")) {
      return NextResponse.json(
        { error: "expected multipart/form-data with a file field" },
        { status: 400 }
      );
    }
    const form = await req.formData();
    const file = form.get("file");
    const provider = (form.get("provider") as string | null) || undefined;

    if (!(file instanceof File)) {
      return NextResponse.json({ error: "no file uploaded" }, { status: 400 });
    }
    // Authoritative size check (multipart already materialized the file).
    if (file.size > MAX_UPLOAD_BYTES) {
      return NextResponse.json({ error: "file too large" }, { status: 413 });
    }
    const ext = fileExtension(file.name);
    if (!ALLOWED_EXTENSIONS.has(ext)) {
      return NextResponse.json(
        { error: "unsupported file type; expected .json, .html or .htm" },
        { status: 400 }
      );
    }
    if (provider && !["chatgpt", "claude", "cursor", "generic"].includes(provider)) {
      return NextResponse.json({ error: "invalid provider" }, { status: 400 });
    }

    tmpDir = await mkdtemp(join(tmpdir(), "didileak-"));
    const buf = Buffer.from(await file.arrayBuffer());
    const inPath = join(tmpDir, "export." + ext);
    const outPath = join(tmpDir, "report.json");
    await writeFile(inPath, buf);

    const result = await runScan(inPath, outPath, provider);
    // displaySource: keep the user's original filename, never the temp path.
    const safe = sanitizeResult(result as Record<string, unknown>, file.name);
    return NextResponse.json(safe);
  } catch (e) {
    // Full detail goes to server logs only; the client gets a generic message.
    console.error("[/api/scan]", e);
    if (e instanceof ScanError) {
      return NextResponse.json({ error: e.message }, { status: e.status });
    }
    return NextResponse.json({ error: "scan failed" }, { status: 500 });
  } finally {
    inFlight--;
    if (tmpDir) {
      try { await rm(tmpDir, { recursive: true, force: true }); } catch { /* best effort */ }
    }
  }
}

function fileExtension(name: string): string {
  if (!name.includes(".")) return "json";
  return name.split(".").pop()!.toLowerCase().trim();
}

function runScan(inPath: string, outPath: string, provider?: string): Promise<unknown> {
  const args = ["scan", inPath, "--json", outPath];
  if (provider) args.splice(1, 1, "--provider", provider, inPath);

  return new Promise((resolve, reject) => {
    const proc = spawn("didileak", args, { stdio: ["ignore", "pipe", "pipe"] });
    let stderr = "";
    let stdout = "";
    // Drain BOTH pipes: an undrained stdout can fill the OS pipe buffer and
    // deadlock the child (it would hang forever with no timeout).
    proc.stdout.on("data", (d) => (stdout += d.toString()));
    proc.stderr.on("data", (d) => (stderr += d.toString()));

    const timer = setTimeout(() => {
      proc.kill("SIGKILL");
      reject(new ScanError("scan timed out", 504));
    }, SCAN_TIMEOUT_MS);

    proc.on("error", (err) => {
      clearTimeout(timer);
      if ((err as NodeJS.ErrnoException).code === "ENOENT") {
        reject(
          new ScanError("didileak CLI is not installed on this server", 500)
        );
      } else {
        reject(new ScanError("scan failed", 500));
      }
    });

    proc.on("close", (code) => {
      clearTimeout(timer);
      if (code !== 0) {
        console.error("[/api/scan] didileak exit", code, "stderr:", stderr.slice(0, 2000));
        reject(new ScanError("scan failed", 500));
        return;
      }
      readFile(outPath, "utf-8").then(
        (text) => {
          try {
            resolve(JSON.parse(text));
          } catch {
            reject(new ScanError("scan failed", 500));
          }
        },
        () => reject(new ScanError("scan failed", 500))
      );
    });
  });
}
