# Security Policy — DidILeak

DidILeak is a local-first Python CLI that scans LLM chat-history exports
(ChatGPT, Claude, Cursor) for accidentally pasted secrets, credentials, and
PII. The project is **actively maintained** (12 commits as of v0.1.0, last
commit 2026-07-03) and ships a 170-test suite at 91% coverage on Python
3.9–3.12. This policy covers the Python package (`didileak/`), the Next.js
dashboard (`dashboard/`), the multi-stage Dockerfile, and the GitHub
Actions workflows.

## Supported Versions

| Version | Supported | Notes |
|---|---|---|
| `0.1.x` (current `main`) | ✅ | Active development; security fixes backported to `main` and released as patch versions. |
| `< 0.1.0` (pre-release `spillage`) | ❌ | Renamed; not supported. |

The project follows Semantic Versioning. Security fixes bump the patch
version; breaking changes to detectors or reporters bump the minor version.

## Reporting a Vulnerability

Email **frangelrcbarrera@gmail.com** with the subject
`[DidILeak SECURITY] <short summary>`. Please include:

1. Affected component (parser, detector, reporter, CLI, dashboard route,
   Dockerfile, CI workflow).
2. A minimal reproducible input — for parser/reporter bugs, a synthetic
   export file that triggers the issue (redact any real secrets first).
3. The exact file and line number(s) if known (e.g. `reporters/html.py:51`).
4. Your severity assessment and suggested fix (optional but appreciated).

**Do NOT open a public GitHub issue** for security reports. Use email
first. The maintainer will acknowledge receipt within **24 hours** and
open a private GitHub advisory if coordination is needed.

## Response Timeline

| Severity | Acknowledge | Initial Assessment | Patch Target |
|---|---|---|---|
| Critical (RCE, auth bypass, secret disclosure to 3rd parties) | 24 h | 3 days | 7 days |
| High (XSS in shared reports, path traversal, injection) | 24 h | 5 days | 14 days |
| Medium (info disclosure, DoS, weak defaults) | 48 h | 7 days | 30 days |
| Low (hardening, defense-in-depth) | 72 h | 14 days | 90 days |

After the fix lands on `main`, a patch release is cut and the advisory is
published with credit to the reporter (unless anonymity is requested).

## Scope

**In scope:** the Python package under `didileak/` (parsers, detectors,
reporters, CLI, models, rotation guides); the Next.js dashboard under
`dashboard/` (API route `/api/scan`, client components,
`next.config.mjs`); the `Dockerfile`; GitHub Actions workflows under
`.github/workflows/`; and the demo at `docs/demo/report.html`.

**Out of scope:** vulnerabilities in third-party LLM providers (ChatGPT,
Claude, Cursor) or their export formats — report those to the respective
vendor. Findings in dependencies (rich, jinja2, next, react, etc.) —
report upstream; DidILeak will bump the affected dep on confirmation.
Crashes from malformed exports that are not valid examples of any
supported provider's format. Self-DoS from running the CLI on a
multi-gigabyte export on an under-resourced machine.

## Safe Harbor

DidILeak is a defensive tool designed to scan **your own** LLM chat
history. Research conducted in good faith on your own exports, on
synthetic fixtures, or on a self-hosted dashboard instance you control
is explicitly authorized. Do not test against dashboards you do not own
or operate, and do not scan other people's exports without their
explicit consent — that crosses from research into unauthorized access.

## Legal Framework

This policy operates within the following international instruments:

- **USA** — Computer Fraud and Abuse Act (18 U.S.C. § 1030); this policy
  functions as authorization for good-faith research as described above.
- **European Union** — Directive 2013/40/EU on attacks against information
  systems; Article 9 permits Member States to exclude liability for
  authorized security testing.
- **Council of Europe** — Convention on Cybercrime (Budapest, 2001),
  Articles 2–6; the safe-harbor clause above constitutes authorization
  for the described scope.
- **United Kingdom** — Computer Misuse Act 1990 (as amended); this policy
  is intended to provide the authorization defense under s. 1/3.

Researchers must comply with all applicable local laws. If any provision
of this policy conflicts with mandatory local law, the local law prevails
and the researcher should contact the maintainer before proceeding.

## Known Security Considerations

The following are known limitations of the current release, documented
here for transparency and tracked for remediation in future patches.

1. **XSS in the HTML reporter** (`reporters/html.py:51`). The JSON payload
   embedded in `<script id="data" type="application/json">…</script>` is
   produced by `json.dumps(data, ensure_ascii=False, default=str)`, which
   does not escape `</script>` sequences. An attacker who can inject a
   conversation title or message containing `</script><script>…` into a
   chat export that the user later scans and shares can execute script in
   the victim's browser. The HTML report is explicitly designed to be
   shareable (README: "This is what you screenshot for Twitter/HN").
   **Mitigation:** do not share HTML reports from untrusted exports;
   open them in a sandboxed browser with JavaScript disabled.

2. **Cross-finding context leak in the HTML reporter**
   (`reporters/html.py:41–49`). The scrubbing loop replaces each
   finding's own `matched_value` with its masked form inside that
   finding's `context`, but does not cross-reference other findings.
   When two findings share an overlapping context window (e.g. an AWS
   access key and its secret in the same message), each finding's
   context exposes the other's full secret in plaintext.
   **Mitigation:** treat HTML reports as containing full secrets until
   patched; share only the masked summary.

3. **Markdown reporter leaks full secrets via context**
   (`reporters/markdown.py:87`). The line
   `out.append(f"  > {f.context}")` outputs `Finding.context` verbatim
   with no scrubbing. Since `Message.context()` returns a ±60-char window
   around the match, the context **always** contains the full
   `matched_value` in plaintext. This contradicts the README's statement
   that "Values are masked." **Mitigation:** do not paste Markdown
   reports into incident channels; use the JSON report under controlled
   access.

4. **Report files written world-readable** (`cli.py:139, 143, 147, 190,
   191, 192`). All three report formats are written via
   `Path.write_text(…, encoding="utf-8")` without an explicit `mode=`,
   producing files with default permissions (typically `0o644`,
   world-readable). The JSON report intentionally contains full secret
   values. On multi-user systems, other accounts can read the reports.
   **Mitigation:** run `chmod 600 didileak_report.*` after each scan, or
   set `umask 077` before invoking the CLI.

5. **Dashboard `/api/scan` endpoint is unauthenticated**
   (`dashboard/app/api/scan/route.ts`). The POST endpoint accepts file
   uploads up to 50 MB (`bodySizeLimit: "50mb"` in `next.config.mjs`),
   writes them to a temp dir, and shells out to the `didileak` CLI with
   no authentication, rate limiting, or origin check. If deployed on a
   public host, any visitor can submit files for scanning, exhausting
   CPU and disk. **Mitigation:** bind the dashboard to `127.0.0.1` or
   place it behind an authenticating reverse proxy. The README's privacy
   note ("No data leaves your deployment") holds only if the deployment
   is not public.

6. **Dockerfile runs as root** (`Dockerfile`). The image has no `USER`
   directive; the Next.js dashboard and the Python CLI both run as root
   inside the container. Combined with (5), a vulnerability in the CLI
   or SQLite could lead to container escape. **Mitigation:** add a
   non-root user and `USER` directive, or run with `--user nobody`.

7. **Dual-use nature.** DidILeak is designed to scan chat exports you
   own (your own ChatGPT/Claude/Cursor history). Running it against
   someone else's exports without consent may constitute unauthorized
   access under the legal framework cited above. The maintainer
   explicitly disclaims any responsibility for misuse.

## Contact

- **Security reports:** frangelrcbarrera@gmail.com
- **General issues / feature requests:** https://github.com/frangelbarrera/DidILeak/issues
- **Source:** https://github.com/frangelbarrera/DidILeak

The maintainer (frangelrcbarrera@gmail.com) responds within 24 hours for
security reports and 72 hours for general inquiries. There is no PGP key
published at this time; if you require encrypted communication, indicate
so in your initial email and a key will be provisioned for the thread.
