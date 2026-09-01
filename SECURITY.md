# Security Policy — DidILeak

DidILeak is a local-first Python CLI that scans LLM chat-history exports
(ChatGPT, Claude, Cursor) for accidentally pasted secrets, credentials, and
PII. The project is **actively maintained** (19 commits, last commit
2026-09-01) and ships a 193-test suite at 91% coverage on Python
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

The following issues were identified in the initial review of the current
release and have been **remediated** on `main`. They are kept documented for
transparency and regression testing.

1. **XSS in the HTML reporter** — FIXED. The JSON payload embedded in
   `<script id="data">` is now escaped by `_script_safe_json()`
   (`reporters/html.py`): `<`, `>`, `&`, U+2028 and U+2029 are emitted as
   backslash-u escapes, which is lossless for JSON and neutralizes
   `</script>` breakouts. Regression:
   `tests/test_security_regression.py::test_html_script_breakout`.

2. **Cross-finding context leak in the HTML reporter** — FIXED. The
   redaction loop now masks every known `matched_value` in every context
   (and in conversation titles, roles and ids), using the shared
   `reporters/redact.py` helpers. Redaction covers values the detectors
   matched — unrelated text inside the ±60-char context window is preserved
   as-is, so treat reports from untrusted exports with care.
   Regression: `test_html_cross_finding_redaction`.

3. **Markdown reporter leaks full secrets via context** — FIXED. Contexts
   and titles are redacted with the same global pair set before rendering;
   the report no longer recommends a nonexistent `--format` flag.
   Regression: `test_markdown_context_redacted`.

4. **Report files written world-readable** — FIXED. The CLI writes all
   reports via `_write_report()` (`cli.py`): `os.open(..., 0o600)` plus
   `fchmod` on the descriptor, so reports are owner-only regardless of
   umask and are never written through symlinks.
   Regression: `test_scan_reports_owner_only`.

5. **Dashboard `/api/scan` endpoint is unauthenticated** — HARDENED. The
   route now enforces, in-process: an optional bearer token
   (`DIDILEAK_API_TOKEN` env; set it for any non-local deployment), a
   per-IP sliding-window rate limit, a concurrency cap, upload size limits
   (early `Content-Length` check plus authoritative `file.size` check,
   20 MB default, configurable via `DIDILEAK_MAX_UPLOAD_BYTES`), an
   extension allowlist, a provider allowlist, and a hard timeout that
   SIGKILLs the CLI child. The HTTP response is sanitized
   (`dashboard/lib/sanitize.ts`): `matched_value` is stripped and contexts
   are redacted before anything reaches the browser, and error responses
   no longer include stderr or server paths. Note: the
   `experimental.serverActions.bodySizeLimit` in `next.config.mjs` applies
   to Server Actions only, never to this route — the route-level checks
   above are the effective control. The per-IP rate limit trusts the last
   `X-Forwarded-For` entry (the hop our own reverse proxy appends); request
   bodies are buffered before the authoritative size check, so a hostile
   client can still consume memory up to what it sends — for public
   deployments, still place the dashboard behind an authenticating reverse
   proxy.

6. **Dockerfile runs as root** — FIXED. The image runs as a dedicated
   non-root user (`didileak`, uid 10001), installs runtime dependencies
   only, fails the build if `npm run build` fails (no `|| true`), and
   includes a HEALTHCHECK. The runtime stage is `python:3.12-slim` so the
   pip-installed CLI and its shebang are natively compatible.

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
