import { NextRequest, NextResponse } from "next/server";
import { spawn } from "child_process";
import { writeFile, mkdtemp, readFile, rm } from "fs/promises";
import { tmpdir } from "os";
import { join } from "path";

export const runtime = "nodejs";
export const maxDuration = 60;

/**
 * POST /api/scan
 * Body: multipart/form-data with `file` (the export file) and optional `provider`.
 *
 * Writes the file to a temp dir, shells out to `didileak scan --json <out>`,
 * reads the JSON report, and returns it. The Python CLI must be on PATH:
 *   pip install -e .
 * from the DidILeak repo root.
 */
export async function POST(req: NextRequest) {
  let tmpDir: string | null = null;
  try {
    const form = await req.formData();
    const file = form.get("file");
    const provider = (form.get("provider") as string | null) || undefined;

    if (!(file instanceof File)) {
      return NextResponse.json({ error: "no file uploaded" }, { status: 400 });
    }

    tmpDir = await mkdtemp(join(tmpdir(), "didileak-"));
    const buf = Buffer.from(await file.arrayBuffer());
    const ext = file.name && file.name.includes(".")
      ? "." + file.name.split(".").pop()
      : ".json";
    const inPath = join(tmpDir, "export" + ext);
    const outPath = join(tmpDir, "report.json");
    await writeFile(inPath, buf);

    const result = await runScan(inPath, outPath, provider);
    return NextResponse.json(result);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return NextResponse.json({ error: msg }, { status: 500 });
  } finally {
    if (tmpDir) {
      try { await rm(tmpDir, { recursive: true, force: true }); } catch { /* best effort */ }
    }
  }
}

function runScan(inPath: string, outPath: string, provider?: string): Promise<unknown> {
  const args = ["scan", inPath, "--json", outPath];
  if (provider) args.splice(1, 1, "--provider", provider, inPath);

  return new Promise((resolve, reject) => {
    const proc = spawn("didileak", args, { stdio: ["ignore", "pipe", "pipe"] });
    let stderr = "";
    proc.stderr.on("data", (d) => (stderr += d.toString()));

    proc.on("error", (err) => {
      reject(new Error(
        `Could not start 'didileak' CLI. Install it with 'pip install -e .' from the DidILeak repo. Underlying error: ${err.message}`
      ));
    });

    proc.on("close", async (code) => {
      if (code !== 0) {
        reject(new Error(`didileak exited with code ${code}. stderr: ${stderr}`));
        return;
      }
      try {
        const text = await readFile(outPath, "utf-8");
        resolve(JSON.parse(text));
      } catch (e) {
        reject(new Error(`could not read didileak output: ${e instanceof Error ? e.message : String(e)}`));
      }
    });
  });
}
