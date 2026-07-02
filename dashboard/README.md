# DidILeak dashboard

A Next.js 15 dashboard for visualizing DidILeak scan results.

## Quick start

```bash
# 1. Install the didileak Python CLI (so the dashboard's API can call it)
cd .. && pip install -e .

# 2. Install dashboard dependencies
cd dashboard && npm install

# 3. Run
npm run dev
# open http://localhost:3000
```

## Two ways to use it

1. **Drop an export file** (ChatGPT `conversations.json`, Claude HTML/JSON, Cursor JSON).
   The dashboard's API route shells out to the `didileak` Python CLI and renders the findings.

2. **Drop a pre-built `didileak_report.json`** (from `didileak report --outdir ...`).
   The dashboard loads it directly — no Python needed.

## Architecture

- `app/page.tsx` — upload UI + findings visualization
- `app/api/scan/route.ts` — POST endpoint that runs the Python CLI via subprocess
- `components/upload.tsx` — drag & drop file picker
- `components/findings-table.tsx` — sortable, filterable findings table
- `components/finding-detail.tsx` — slide-in drawer with full context + rotation guide
- `components/stats.tsx` — risk score + severity breakdown

## Visual design

The dashboard follows a warm, minimalist aesthetic inspired by the Anthropic/Claude brand language.
The background uses a solid terracotta tone (`#d97757`) — warm, intentional, and serious. Cream
cards (`#faf6f0`) float on top with soft box-shadows (no gradients anywhere) and rounded corners
(14px on cards, 8px on inputs, 1px on severity markers). Severity is indicated by small vintage
pixel-squares in muted earthy colors (deep brick red, burnt sienna, dark amber, steel blue, warm
gray) — never neon, never round dots. Typography is a bold geometric sans-serif (Inter) with tight
letter-spacing for titles. Just the app name appears at the top — no logo mark.

## Privacy

Files are processed locally by the Python CLI on the server. Nothing leaves your
deployment. For paranoid use, run `didileak scan` in an offline VM and upload
only the resulting JSON report.
