# DidILeak

> I scanned 2 years of my ChatGPT history. I found **47 API keys**, **12 passwords**, **3 private SSH keys**, and my SSN. All pasted without thinking. — *the hook*

`DidILeak` scans your LLM chat history (ChatGPT, Claude, Cursor) for secrets, credentials, and PII you may have pasted accidentally. It runs locally, generates a triage report with rotation instructions, and ships a self-contained HTML dashboard you can screenshot and share.

**OSINT-BIBLE taught you to investigate others. `DidILeak` teaches you to investigate yourself.**

---

## Quick start

```bash
# install
pip install -e .

# scan your ChatGPT export (Settings -> Data controls -> Export)
didileak report ~/Downloads/chatgpt-export/conversations.json --outdir ./reports

# open the HTML dashboard
open reports/didileak_report.html
```

You'll get three files in `./reports/`:

| File | What it's for |
|---|---|
| `didileak_report.html` | Self-contained dashboard — filter, sort, drill into each finding. **This is what you screenshot for Twitter/HN.** |
| `didileak_report.md` | Markdown triage report for your incident channel. |
| `didileak_report.json` | Machine-readable, with **full secret values** (not just masked) for incident response. |

## CLI reference

```bash
# scan + print summary to stdout
didileak scan ~/Downloads/conversations.json

# scan + write HTML / Markdown / JSON to specific paths
didileak scan ~/Downloads/conversations.json --html report.html --json report.json

# scan + write all three formats to a directory
didileak report ~/Downloads/claude-export/ --outdir ./reports

# print a rotation guide for a specific rule
didileak rotation aws-access-token

# interactive terminal UI (optional extra)
pip install 'DidILeak[tui]'
didileak tui ~/Downloads/conversations.json
```

Force a parser with `--provider chatgpt|claude|cursor|generic`. By default, DidILeak sniffs the file format from filename and content.

## What it detects

Patterns inspired by [gitleaks](https://github.com/gitleaks/gitleaks) v8 and [trufflehog](https://github.com/trufflesecurity/trufflehog).

| Category | Detector | Severity |
|---|---|---|
| Cloud | AWS Access Key (`AKIA…`) | critical |
| Cloud | AWS Secret Access Key (context-checked) | critical |
| Cloud | Google API Key (`AIza…`) | high |
| Cloud | Google OAuth token (`ya29.…`) | high |
| VCS | GitHub PAT (`ghp_…`) | critical |
| VCS | GitHub OAuth (`gho_…`) | critical |
| VCS | GitHub App / User-to-Server (`ghu_`, `ghs_`, `ghr_`) | critical |
| Chat | Slack Token (`xox[bpars]-…`) | high |
| Chat | Slack Webhook URL | medium |
| Payments | Stripe live secret key (`sk_live_…`) | critical |
| Payments | Stripe live restricted key (`rk_live_…`) | critical |
| Crypto | PEM private key block (RSA / DSA / EC / OpenSSH / PGP) | critical |
| Auth | JWT (`eyJ…`) | high |
| Auth | Bearer token in `Authorization` header | high |
| DB | Database connection string (`postgres://user:pass@host`) | critical |
| Generic | `api_key=` / `password=` / `secret=` env-style assignments | high |
| PII | Email address | low |
| PII | US phone number | info |
| PII | US Social Security Number | critical |
| PII | IBAN | high |
| PII | Credit Card Number (Luhn-validated) | critical |

Every critical/high finding ships with a **rotation guide** — exactly what to do, where to click, what to audit.

## Web dashboard (Next.js)

For a richer experience with drag-and-drop upload and a slide-in detail drawer:

```bash
cd dashboard
npm install
npm run dev
```

See [`dashboard/README.md`](dashboard/README.md) for details.

## Docker

```bash
docker build -t didileak .
docker run -p 3000:3000 didileak
```

## How it works

```
export file (JSON / HTML)
      │
      ▼
   parser ─── chatgpt | claude | cursor | generic
      │
      ▼
 list<Message>  ──▶  DetectorEngine (regex + validators + context)
                          │
                          ▼
                    list<Finding>
                          │
                          ▼
              reporters: markdown | json | html
```

- **Parsers** yield `Message` objects with role, content, timestamp, and conversation context.
- **DetectorEngine** runs every rule against every message. Rules can use:
  - **Validators** (Luhn for cards, character-class checks for AWS keys) to drop false positives
  - **Context keywords** (e.g. AWS secret only fires when `AKIA` / `aws_secret` appears nearby)
  - **Allowlists** (e.g. `noreply@example.com`, `user:pass@` placeholders)
- **Reporters** render the findings. The HTML report strips the full secret value before embedding data, so the dashboard is safe to share.

## Why I built this

In the last 2 years, millions of developers have pasted API keys, passwords, tokens, and PII into ChatGPT/Claude/Cursor without thinking. Nobody knows what leaked. It's a security time bomb.

[OSINT-BIBLE](https://github.com/frangelbarrera/OSINT-BIBLE) taught 569+ stargazers how to investigate *others*. `DidILeak` flips that lens: investigate *yourself* — your own chat history, your own accidental leaks — and rotate what you find before someone else finds it.

## Limitations (honest)

- **Regex-based detection only.** No entropy analysis (yet), no ML. Some secrets with unusual formats may be missed. False negatives are possible.
- **Context is text-only.** Image attachments in ChatGPT/Claude exports are not OCR'd.
- **No deduplication across files.** The same key leaked in 5 conversations shows up 5 times.
- **Cursor SQLite parsing is best-effort.** Cursor's schema changes between versions; if you hit a warning, export from the chat panel to JSON instead.
- **Claude HTML export structure varies.** The parser tries structured extraction first, falls back to a plain-text sweep. The JSON path is more reliable — prefer it when available.
- **Rotation guides are general.** They tell you the right *place* to rotate; they can't tell you *which* specific key it was (only the masked value, by design).

## Roadmap (Phase 2)

- [ ] Entropy-based secret detection (high-entropy strings without known prefix)
- [ ] OCR for image attachments
- [ ] Cross-file deduplication with a fingerprint index
- [ ] HuggingFace / Together AI / Replicate token patterns
- [ ] Browser extension that warns *before* you paste a secret

## Contributing

```bash
pip install -e ".[dev]"
pytest  # 68 tests, 82% coverage
ruff check didileak tests
```

PRs welcome. Add new detectors to `didileak/detectors/__init__.py` — each rule is one `Rule(...)` entry with a `pattern`, optional `validator`, optional `context_keywords`, and a `rotation_guide`.

## License

MIT — see [LICENSE](LICENSE).

## Acknowledgements

- [gitleaks](https://github.com/gitleaks/gitleaks) — the canonical secret-pattern reference
- [trufflehog](https://github.com/trufflesecurity/trufflehog) — entropy + verifier approach inspiration
- [OSINT-BIBLE](https://github.com/frangelbarrera/OSINT-BIBLE) — the spiritual predecessor
