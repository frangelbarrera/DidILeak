# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security
- HTML reporter: escape the JSON payload embedded in `<script id="data">` so `</script>` sequences cannot break out of the element (stored XSS via malicious export titles).
- HTML and Markdown reporters: redact every known secret from all context windows and conversation titles, including values matched by neighboring findings.
- CLI: report files are now written owner-only (0600, never through symlinks), and multi-input `scan` no longer overwrites its own `--json`/`--markdown`/`--html` output.
- Parser autodetection: export structure is inspected before the filename, so a Claude export named `conversations.json` is no longer scanned as an empty ChatGPT export.
- Dashboard: `/api/scan` responses are sanitized (no `matched_value`, redacted contexts) with upload, rate and concurrency limits plus an optional bearer token; the dashboard build is fixed (missing `lib/types.ts` and `lib/utils.ts`).
- Dockerfile: a failing dashboard build now fails the image; the runtime is non-root and includes a health check.
- Redaction: contexts are now redacted by span surgery, so a secret cut mid-value by the ±60 context window edge no longer survives as a raw fragment; the secret core of prefixed matches (`password = X`, `Bearer X`, connection strings) is redacted as its own value, so bare repetitions are masked too. The dashboard sanitizer applies the same two passes.
- Redaction now groups findings by message and walks the window with a binary search instead of scanning all findings per context.
- CLI: exports containing lone surrogates (`\ud800` escapes) no longer crash the scan; they are mapped to U+FFFD where export text enters the pipeline.
- CLI: conversation titles are redacted before being printed to stdout or the TUI.
- CLI: `scan`/`report` now exit 2 when some inputs fail instead of exiting green on a half-covered audit.
- Markdown reporter: free text from the export (contexts, titles, source path) is escaped so links, images, raw HTML and newlines cannot forge structure in the shared report.
- Dashboard: `/api/scan` is fail-closed without `DIDILEAK_API_TOKEN` (opt back in with `DIDILEAK_ALLOW_ANONYMOUS=true`); requests without `Content-Length` are rejected before buffering; failed auth consumes the rate budget; rate limiting keys on `X-Forwarded-For` only when `DIDILEAK_TRUST_PROXY=true`. Baseline `nosniff`/`DENY`/`no-referrer` headers and `no-store` on `/api/*`.
- Build: drop the unused jinja2 runtime dependency.

## [0.1.0] - 2025-07-02

### Added
- Initial public release under the name **DidILeak** (formerly `spillage`).
- CLI with `scan`, `report`, `rotation`, and `tui` subcommands. Entry point: `didileak`.
- Parsers for ChatGPT (`conversations.json`), Claude (JSON + HTML), Cursor (JSON + SQLite `state.vscdb`), and a generic JSON walker.
- Detector engine with 18 rules inspired by gitleaks v8: AWS, GitHub, Google, Slack, Stripe, PEM private keys, JWT, Bearer tokens, DB connection strings, generic env-style secrets, and PII (email, US phone, US SSN, IBAN, credit cards).
- Luhn validator for credit cards, character-class validators for AWS keys and GitHub tokens, context-keyword guards for loose patterns (e.g. AWS secret), allowlist filters for obvious placeholders.
- Three reporters: Markdown triage report, JSON report (with full `matched_value` for incident response), and a self-contained HTML dashboard with embedded data, filtering, sorting, and a slide-in detail drawer.
- Rotation guides for every critical/high detector — exactly what to rotate and where.
- Next.js 15 dashboard (`dashboard/`) with drag-and-drop upload, sortable findings table, slide-in finding detail, and risk-score visualization. Editor-grade visual aesthetic: near-black neutral palette, muted Radix-style severity colors, no gradients, no glow effects.
- pytest suite: 68 tests, 82% coverage, with synthetic fixtures for every parser and detector.
- GitHub Actions CI matrix on Python 3.9 / 3.10 / 3.11 / 3.12.
- Multi-stage Dockerfile bundling the Python CLI + Next.js dashboard.
- MIT license.

### Suggested commit message

```
feat: initial release of DidILeak — LLM history secret scanner

- Python CLI (scan, report, rotation, tui) with auto-detecting parsers for
  ChatGPT, Claude, Cursor, and generic JSON exports
- 18 gitleaks-inspired detectors with validators, context guards, and
  allowlists; Luhn check for credit cards
- Three reporters: self-contained HTML dashboard (the shareable one),
  Markdown triage, JSON for incident response
- Per-detector rotation guides
- Next.js 15 web dashboard with drag-and-drop upload + detail drawer,
  editor-grade visual design (neutral palette, muted severity colors,
  no gradients, no glow)
- 68 pytest tests, 82% coverage, GitHub Actions CI on py3.9-3.12
- Multi-stage Dockerfile for self-hosted deployments

OSINT-BIBLE taught you to investigate others.
DidILeak teaches you to investigate yourself.
```
