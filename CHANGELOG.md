# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
