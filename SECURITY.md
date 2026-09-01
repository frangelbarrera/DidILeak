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
vendor. Findings in dependencies (rich, next, react, etc.) —
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

   Follow-up (window-edge fragments): the ±60-char window can cut a
   neighbouring secret mid-value, and whole-value replacement left the
   visible fragment raw — combined with the 4+4 mask of the finding's own
   value, the full secret was reconstructible. Contexts are now redacted by
   span surgery (`Redactor.context()` in `reporters/redact.py`): the window
   is reconstructed from `span_start` and every same-message finding slice
   visible in it — full or truncated — is replaced by its mask, with no
   string guessing. The same "core" of prefixed matches (`password = X`,
   `Bearer X`, `scheme://user:pass@host`) is added as its own pair so bare
   repetitions of a value are masked too. Regressions:
   `test_html_context_redacts_truncated_neighbor`,
   `test_bare_value_repetition_redacted`,
   `test_bearer_and_uri_core_values_redacted`.

3. **Markdown reporter leaks full secrets via context** — FIXED. Contexts
   and titles are redacted with the same global pair set before rendering;
   the report no longer recommends a nonexistent `--format` flag.
   Regression: `test_markdown_context_redacted`. Contexts also go through
   the span-aware redactor described in item 2, and free text from the
   export (contexts, titles, source path) is escaped for Markdown/HTML
   injection (`_md_inline` / `_md_code` in `reporters/markdown.py`): links,
   images, raw tags and newlines cannot forge structure in the shared
   report. Regression: `test_markdown_neutralizes_injection`.

4. **Report files written world-readable** — FIXED. The CLI writes all
   reports via `_write_report()` (`cli.py`): `os.open(..., 0o600)` plus
   `fchmod` on the descriptor, so reports are owner-only regardless of
   umask and are never written through symlinks.
   Regression: `test_scan_reports_owner_only`.

5. **Dashboard `/api/scan` endpoint is unauthenticated** — HARDENED. The
   route enforces, in-process: a bearer token (`DIDILEAK_API_TOKEN`), a
   per-client rate limit, a concurrency cap, upload size limits, an
   extension allowlist, a provider allowlist, and a hard timeout that
   SIGKILLs the CLI child. Authentication is **fail-closed**: without
   `DIDILEAK_API_TOKEN` the route answers 401 unless
   `DIDILEAK_ALLOW_ANONYMOUS="true"` explicitly opts into unauthenticated
   use (single-user local self-hosting). Failed auth attempts consume the
   caller's rate budget. Requests without a numeric `Content-Length`
   (e.g. chunked uploads) are rejected with 411 before any buffering, and
   the declared length is capped — the multipart body is never materialized
   for oversized requests. Rate limiting keys on the client IP only when
   `DIDILEAK_TRUST_PROXY="true"` (reverse proxy appending to
   `X-Forwarded-For`); in direct exposure every client shares one budget,
   and a key-flood evicts a quarter of the tracked keys instead of resetting
   everyone. The HTTP response is sanitized (`dashboard/lib/sanitize.ts`):
   `matched_value` is stripped and contexts are redacted — with the same
   span surgery and core-value pairs as the Python reporters — before
   anything reaches the browser, and error responses do not include stderr
   or server paths. For public deployments, still place the dashboard behind
   an authenticating reverse proxy.

   `next.config.mjs` also sends `X-Content-Type-Options: nosniff`,
   `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer` on every
   response, and `Cache-Control: no-store` on `/api/*`.

   Residual: response sanitization is synchronous CPU work proportional to
   the export's text and distinct-secret count. A rate-limited adversarial
   upload with thousands of secrets of distinct lengths can still keep a
   core busy for seconds per request; public deployments should keep the
   reverse proxy (with its own request body limits) in front.

6. **Dockerfile runs as root** — FIXED. The image runs as a dedicated
   non-root user (`didileak`, uid 10001), installs runtime dependencies
   only, fails the build if `npm run build` fails (no `|| true`), and
   includes a HEALTHCHECK. The runtime stage is `python:3.12-slim` so the
   pip-installed CLI and its shebang are natively compatible.

7. **Lone surrogates crash the CLI** — FIXED. JSON escapes like `\ud800`
   decode to lone surrogates: valid in a Python `str`, unencodable in
   UTF-8. They used to raise `UnicodeEncodeError` inside the rich console
   and abort the scan before any report was written. Export text is
   sanitized to U+FFFD where it enters the pipeline
   (`Message.__post_init__`, `models.py`) and report files are written with
   `errors="replace"` as a belt. Regression: `test_cli_survives_lone_surrogates`.

8. **Conversation titles printed raw to stdout/TUI** — FIXED. ChatGPT
   auto-generates titles from the first message, so a secret pasted as the
   first message ends up in the title — and the rich preview table (and the
   TUI) used to print it raw. Titles are now redacted with the global pair
   set before printing. Regression: `test_stdout_summary_redacts_titles`.

9. **Multi-input scans exit green on partial failure** — FIXED. When some
   inputs failed to parse, `scan`/`report` still exited 0, so CI would treat
   a half-covered audit as a clean pass. A partial failure now exits 2
   while still writing reports for the inputs that could be read.
   Regression: `test_scan_partial_failure_exits_nonzero`.

10. **Dual-use nature.** DidILeak is designed to scan chat exports you
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
