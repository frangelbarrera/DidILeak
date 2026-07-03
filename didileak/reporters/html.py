"""Self-contained HTML dashboard renderer.

Output is a single `didileak_report.html` with embedded CSS, JS, and scan data.
Open in any browser - no server, no build step, no deps.

Visual language: warm, minimal, editor-grade. Terracotta background (#d97757)
inspired by the Anthropic/Claude brand aesthetic, cream cards floating on top
with soft shadows (no gradients anywhere), bold geometric sans-serif typography,
and small pixel-square severity markers in vintage muted colors. Rounded corners
throughout. No sharp edges, no glow effects, no neon.
"""
from __future__ import annotations

import html
import json

from didileak.models import ScanResult, Severity

# Vintage muted severity colors for the pixel squares.
# Desaturated, earthy — no neon, no pure RGB primaries.
_SEV_COLOR = {
    Severity.CRITICAL: "#a83232",  # deep brick red
    Severity.HIGH:     "#c2410c",  # burnt sienna
    Severity.MEDIUM:   "#b45309",  # dark amber
    Severity.LOW:      "#3b5e7e",  # steel blue
    Severity.INFO:     "#6b6660",  # warm gray
}


def _esc(s) -> str:
    if s is None:
        return ""
    return html.escape(str(s))


def render_html(result: ScanResult) -> str:
    data = result.to_dict()
    by_sev = data["by_severity"]
    total = data["total_findings"]
    # Strip full secret values from the HTML payload.
    safe_findings = []
    for f in data["findings"]:
        sf = dict(f)
        sf.pop("matched_value", None)
        ctx = sf.get("context") or ""
        mv = f.get("matched_value")
        if mv and mv in ctx:
            sf["context"] = ctx.replace(mv, f.get("masked_value", "***"))
        safe_findings.append(sf)
    data["findings"] = safe_findings
    payload = json.dumps(data, ensure_ascii=False, default=str)

    sev_badges = "".join(
        f'<span class="sev-pill">'
        f'<span class="pixel" style="background:{_SEV_COLOR[sev]}"></span>'
        f'<span class="sev-name">{sev.value}</span>'
        f'<span class="sev-n">{by_sev.get(sev.value, 0)}</span>'
        f'</span>'
        for sev in Severity if by_sev.get(sev.value, 0)
    )

    risk_score = (
        by_sev.get("critical", 0) * 100
        + by_sev.get("high", 0) * 30
        + by_sev.get("medium", 0) * 10
        + by_sev.get("low", 0) * 2
        + by_sev.get("info", 0)
    )

    if risk_score == 0:
        risk_label, risk_color = "Clean", "#5c7a52"
    elif risk_score < 50:
        risk_label, risk_color = "Low", "#b45309"
    elif risk_score < 200:
        risk_label, risk_color = "Medium", "#c2410c"
    elif risk_score < 500:
        risk_label, risk_color = "High", "#a83232"
    else:
        risk_label, risk_color = "Critical", "#a83232"

    return _TEMPLATE.format(
        payload=payload,
        sev_badges=sev_badges,
        total=total,
        messages=data["messages_scanned"],
        conversations=data["conversations_scanned"],
        provider=_esc(data["provider"]),
        source=_esc(data["source"]),
        risk_score=risk_score,
        risk_label=risk_label,
        risk_color=risk_color,
    )


_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DidILeak report</title>
<style>
  :root {{
    --bg: #d97757;
    --bg-deep: #c66a4c;
    --card: #faf6f0;
    --card-soft: #f3ede3;
    --card-hover: #ede5d8;
    --border: #e8dfd0;
    --border-soft: #efe7d8;
    --text: #2a2622;
    --text-dim: #6b6660;
    --text-faint: #9a9388;
    --text-mute: #b8b0a3;
    --text-on-bg: #faf6f0;
    --text-on-bg-dim: #f0e4d4;
    --text-on-bg-faint: #e0d4c0;
    --accent: #c2410c;
    --ok: #5c7a52;
    --mono: 'JetBrains Mono','SF Mono',ui-monospace,Menlo,Consolas,monospace;
    --sans: 'Inter',-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;
    --shadow-sm: 0 1px 2px rgba(42,38,34,0.04);
    --shadow-md: 0 1px 3px rgba(42,38,34,0.05), 0 4px 16px rgba(42,38,34,0.06);
    --shadow-lg: 0 2px 8px rgba(42,38,34,0.08), 0 12px 40px rgba(42,38,34,0.10);
  }}
  * {{ box-sizing: border-box; }}
  html, body {{ margin: 0; padding: 0; }}
  body {{
    background: var(--bg);
    color: var(--text);
    font-family: var(--sans);
    font-size: 14px;
    line-height: 1.55;
    -webkit-font-smoothing: antialiased;
    font-feature-settings: 'cv11','ss01';
  }}
  .wrap {{ max-width: 1100px; margin: 0 auto; padding: 48px 28px 80px; }}

  /* Header — just the app name, nothing else */
  header.top {{
    margin-bottom: 36px;
  }}
  .app-name {{
    font-family: var(--sans);
    font-size: 28px;
    font-weight: 700;
    letter-spacing: -0.02em;
    color: var(--text-on-bg);
    margin: 0;
    line-height: 1.1;
  }}
  .app-tag {{
    font-size: 13px;
    color: var(--text-on-bg-faint);
    margin-top: 4px;
    letter-spacing: 0.01em;
  }}
  .meta-line {{
    font-family: var(--mono);
    font-size: 11px;
    color: var(--text-on-bg-faint);
    margin-top: 16px;
    line-height: 1.6;
  }}
  .meta-line span {{ color: var(--text-on-bg-dim); }}

  /* Risk badge — floats on the terracotta */
  .risk {{
    display: inline-flex; align-items: center; gap: 10px;
    padding: 8px 14px; border-radius: 10px;
    background: var(--card); box-shadow: var(--shadow-md);
    font-size: 12px;
  }}
  .risk .pixel {{
    width: 8px; height: 8px; border-radius: 1px;
    background: {risk_color};
  }}
  .risk .label {{
    font-weight: 600; color: {risk_color};
    font-size: 11px; text-transform: uppercase; letter-spacing: 0.06em;
  }}
  .risk .score {{
    font-family: var(--mono); color: var(--text-dim);
    font-size: 11px; padding-left: 10px; border-left: 1px solid var(--border);
  }}

  /* Stats — cream cards floating on terracotta */
  .grid-stats {{
    display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px;
    margin-bottom: 24px;
  }}
  .stat {{
    background: var(--card); border-radius: 14px;
    padding: 18px 20px; box-shadow: var(--shadow-md);
  }}
  .stat .n {{
    font-family: var(--sans); font-size: 26px; font-weight: 700;
    color: var(--text); letter-spacing: -0.03em; line-height: 1;
  }}
  .stat .l {{
    font-size: 11px; color: var(--text-faint);
    text-transform: uppercase; letter-spacing: 0.08em; margin-top: 6px;
    font-weight: 500;
  }}

  /* Severity pills — pixel squares + label + count */
  .pills {{ display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 28px; }}
  .sev-pill {{
    display: inline-flex; align-items: center; gap: 8px;
    padding: 6px 12px 6px 10px; border-radius: 8px;
    background: var(--card); box-shadow: var(--shadow-sm);
    font-family: var(--sans); font-size: 12px; color: var(--text-dim);
  }}
  .sev-pill .pixel {{
    width: 8px; height: 8px; border-radius: 1px;
  }}
  .sev-pill .sev-name {{ color: var(--text); font-weight: 500; }}
  .sev-pill .sev-n {{
    color: var(--text); font-weight: 700; font-family: var(--mono);
    font-size: 11px; padding-left: 4px;
  }}

  /* Toolbar */
  .toolbar {{
    display: flex; gap: 8px; margin-bottom: 12px; flex-wrap: wrap; align-items: center;
    background: var(--card); padding: 10px; border-radius: 12px; box-shadow: var(--shadow-sm);
  }}
  .toolbar input, .toolbar select {{
    background: var(--card-soft); color: var(--text);
    border: 1px solid var(--border); border-radius: 8px;
    padding: 7px 12px; font-family: var(--sans); font-size: 13px;
    outline: none; transition: border-color 0.12s;
  }}
  .toolbar input {{ flex: 1; min-width: 200px; }}
  .toolbar input:focus, .toolbar select:focus {{ border-color: var(--text-mute); }}
  .toolbar input::placeholder {{ color: var(--text-mute); }}
  .toolbar select {{ cursor: pointer; }}
  .toolbar .count {{
    margin-left: auto; color: var(--text-faint); font-size: 11px;
    font-family: var(--mono); padding-right: 6px;
  }}

  /* Table — cream card */
  table {{
    width: 100%; border-collapse: separate; border-spacing: 0;
    background: var(--card); border-radius: 14px; overflow: hidden;
    box-shadow: var(--shadow-md);
  }}
  thead th {{
    text-align: left; padding: 12px 16px;
    font-size: 10px; text-transform: uppercase; letter-spacing: 0.08em;
    color: var(--text-faint); font-weight: 600;
    border-bottom: 1px solid var(--border); cursor: pointer; user-select: none;
    white-space: nowrap; background: var(--card-soft);
  }}
  thead th:hover {{ color: var(--text-dim); }}
  thead th .arrow {{ opacity: 0.3; margin-left: 3px; font-size: 9px; }}
  thead th.sorted .arrow {{ opacity: 1; color: var(--text); }}
  tbody tr {{ cursor: pointer; transition: background 0.1s; }}
  tbody tr:hover {{ background: var(--card-hover); }}
  tbody td {{
    padding: 12px 16px; border-bottom: 1px solid var(--border-soft);
    vertical-align: top; font-size: 13px;
  }}
  tbody tr:last-child td {{ border-bottom: 0; }}
  td.sev {{ white-space: nowrap; }}
  td.sev .sev-cell {{
    display: inline-flex; align-items: center; gap: 7px;
    font-family: var(--mono); font-size: 11px; font-weight: 600;
    text-transform: uppercase; letter-spacing: 0.04em;
  }}
  td.sev .pixel {{
    width: 9px; height: 9px; border-radius: 1px;
  }}
  td.detector {{ color: var(--text); font-weight: 500; }}
  td.detector .rid {{
    color: var(--text-faint); font-family: var(--mono); font-size: 10px;
    display: block; margin-top: 2px; font-weight: 400;
  }}
  td.value {{
    font-family: var(--mono); font-size: 12px; color: var(--text-dim);
    word-break: break-all;
  }}
  td.conv {{ color: var(--text-dim); }}
  td.conv .role {{
    color: var(--text-faint); font-size: 10px; font-family: var(--mono);
    display: block; margin-top: 2px;
  }}
  td.context {{
    color: var(--text-faint); font-size: 12px; max-width: 320px;
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
    font-family: var(--mono);
  }}
  td.context mark {{
    background: rgba(168,50,50,0.12); color: var(--text);
    padding: 0 2px; border-radius: 2px;
  }}
  td.when {{
    color: var(--text-faint); font-family: var(--mono); font-size: 10px;
    white-space: nowrap;
  }}

  .empty {{
    padding: 56px 24px; text-align: center; color: var(--text-faint);
    background: var(--card); border-radius: 14px; box-shadow: var(--shadow-md);
  }}
  .empty .ok {{
    color: var(--ok); font-size: 14px; font-weight: 600; margin-bottom: 4px;
  }}

  /* Drawer */
  .overlay {{
    position: fixed; inset: 0; background: rgba(42,38,34,0.30);
    opacity: 0; pointer-events: none; transition: opacity 0.18s; z-index: 50;
  }}
  .overlay.open {{ opacity: 1; pointer-events: auto; }}
  .drawer {{
    position: fixed; top: 0; right: 0; bottom: 0; width: 500px; max-width: 100vw;
    background: var(--card); box-shadow: var(--shadow-lg);
    transform: translateX(100%); transition: transform 0.22s; z-index: 60;
    overflow-y: auto; padding: 32px 28px;
  }}
  .drawer.open {{ transform: translateX(0); }}
  .drawer h2 {{
    margin: 0 0 4px; font-size: 17px; font-weight: 700; letter-spacing: -0.01em;
    color: var(--text);
  }}
  .drawer .close {{
    position: absolute; top: 18px; right: 18px;
    background: var(--card-soft); border: 0; color: var(--text-dim); cursor: pointer;
    width: 28px; height: 28px; border-radius: 8px;
    font-size: 16px; line-height: 1; transition: background 0.12s;
  }}
  .drawer .close:hover {{ background: var(--card-hover); color: var(--text); }}
  .drawer .tag-row {{
    display: flex; align-items: center; gap: 8px; margin-bottom: 8px;
  }}
  .drawer .tag {{
    display: inline-flex; align-items: center; gap: 6px;
    font-family: var(--mono); font-size: 10px; font-weight: 600;
    text-transform: uppercase; letter-spacing: 0.06em;
    padding: 3px 8px; border-radius: 6px;
    background: var(--card-soft);
  }}
  .drawer .tag .pixel {{
    width: 7px; height: 7px; border-radius: 1px;
  }}
  .drawer .rid-line {{
    font-family: var(--mono); font-size: 11px; color: var(--text-faint);
    margin-bottom: 24px;
  }}
  .drawer .field {{ margin: 16px 0; }}
  .drawer .field .lbl {{
    font-size: 10px; color: var(--text-faint);
    text-transform: uppercase; letter-spacing: 0.08em; margin-bottom: 6px;
    font-weight: 600;
  }}
  .drawer .field .val {{
    font-family: var(--mono); font-size: 12px; word-break: break-all;
    color: var(--text-dim);
  }}
  .drawer .ctx-box {{
    background: var(--card-soft); border-radius: 8px; padding: 12px 14px;
    font-family: var(--mono); font-size: 12px;
    color: var(--text-dim); white-space: pre-wrap; word-break: break-word;
    line-height: 1.6;
  }}
  .drawer .ctx-box mark {{
    background: rgba(168,50,50,0.15); color: var(--text);
    padding: 0 2px; border-radius: 2px;
  }}
  .rotation {{
    background: var(--card-soft); border-radius: 10px;
    padding: 14px 16px; margin-top: 18px;
    color: var(--text-dim); font-size: 13px; line-height: 1.6;
  }}
  .rotation::before {{
    content: 'Rotation guide';
    display: block; font-size: 10px; font-weight: 600;
    letter-spacing: 0.08em; text-transform: uppercase;
    color: var(--text-faint); margin-bottom: 6px;
  }}

  footer {{
    margin-top: 48px; padding-top: 24px;
    color: var(--text-on-bg-faint); font-size: 12px; text-align: center;
  }}
  footer a {{ color: var(--text-on-bg-dim); text-decoration: none; }}
  footer a:hover {{ color: var(--text-on-bg); }}

  @media (max-width: 720px) {{
    .grid-stats {{ grid-template-columns: repeat(2, 1fr); }}
    .drawer {{ width: 100vw; }}
    table {{ font-size: 12px; }}
    td.context {{ max-width: 180px; }}
    .wrap {{ padding: 32px 18px 60px; }}
    .app-name {{ font-size: 24px; }}
  }}
</style>
</head>
<body>
<div class="wrap">
  <header class="top">
    <h1 class="app-name">DidILeak</h1>
    <div class="app-tag">LLM history secret scanner</div>
    <div class="meta-line">
      <span>source</span> {source} &nbsp;·&nbsp; <span>provider</span> {provider}
    </div>
  </header>

  <div style="margin-bottom: 20px">
    <div class="risk">
      <span class="pixel"></span>
      <span class="label">{risk_label}</span>
      <span class="score">risk {risk_score}</span>
    </div>
  </div>

  <section class="grid-stats">
    <div class="stat"><div class="n">{total}</div><div class="l">Findings</div></div>
    <div class="stat"><div class="n">{messages}</div><div class="l">Messages</div></div>
    <div class="stat"><div class="n">{conversations}</div><div class="l">Conversations</div></div>
    <div class="stat"><div class="n">{risk_score}</div><div class="l">Risk score</div></div>
  </section>

  <div class="pills">{sev_badges}</div>

  <div class="toolbar">
    <input id="q" placeholder="Filter by rule, value, conversation, context..." autocomplete="off">
    <select id="sevf">
      <option value="">all severities</option>
      <option value="critical">critical</option>
      <option value="high">high</option>
      <option value="medium">medium</option>
      <option value="low">low</option>
      <option value="info">info</option>
    </select>
    <select id="catf">
      <option value="">all categories</option>
      <option value="secret">secret</option>
      <option value="key">key</option>
      <option value="pii">pii</option>
    </select>
    <span id="count" class="count"></span>
  </div>

  <table id="tbl">
    <thead>
      <tr>
        <th data-k="severity" style="width:100px">Severity <span class="arrow">&darr;</span></th>
        <th data-k="rule_name">Detector <span class="arrow"></span></th>
        <th data-k="masked_value">Value <span class="arrow"></span></th>
        <th data-k="conversation_title">Conversation <span class="arrow"></span></th>
        <th>Context</th>
        <th data-k="timestamp" style="width:140px">When <span class="arrow"></span></th>
      </tr>
    </thead>
    <tbody id="rows"></tbody>
  </table>

  <div id="empty" class="empty" style="display:none;margin-top:12px">
    <div class="ok">No findings match the current filters.</div>
  </div>

  <div id="cleanEmpty" class="empty" style="display:none;margin-top:12px">
    <div class="ok">Clean.</div>
    <div>No secrets or PII detected in this export. Stay vigilant.</div>
  </div>

  <footer>
    Generated by <a href="https://github.com/frangelbarrera/DidILeak">DidILeak</a>
    &nbsp;·&nbsp; OSINT-BIBLE taught you to investigate others. DidILeak teaches you to investigate yourself.
  </footer>
</div>

<div class="overlay" id="overlay"></div>
<aside class="drawer" id="drawer">
  <button class="close" id="closeBtn" aria-label="close">&times;</button>
  <div id="drawerBody"></div>
</aside>

<script id="data" type="application/json">{payload}</script>
<script>
  const DATA = JSON.parse(document.getElementById('data').textContent);
  const FINDINGS = DATA.findings;
  const sevColor = {{critical:'#a83232',high:'#c2410c',medium:'#b45309',low:'#3b5e7e',info:'#6b6660'}};
  let sortKey = 'severity';
  let sortDir = -1;

  function fmtTs(ts) {{
    if (!ts) return '—';
    const d = new Date(ts * 1000);
    return d.toISOString().replace('T',' ').replace(/\\.\\d+Z/,' UTC');
  }}
  function esc(s) {{
    if (s === null || s === undefined) return '';
    return String(s).replace(/[&<>"']/g, c => ({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}})[c]);
  }}
  function highlight(ctx, val) {{
    if (!val) return esc(ctx);
    const i = ctx.indexOf(val);
    if (i < 0) return esc(ctx);
    return esc(ctx.slice(0, i)) + '<mark>' + esc(val) + '</mark>' + esc(ctx.slice(i + val.length));
  }}
  function sevWeight(s) {{ return {{critical:5,high:4,medium:3,low:2,info:1}}[s] || 0; }}

  function render() {{
    const q = document.getElementById('q').value.toLowerCase().trim();
    const sev = document.getElementById('sevf').value;
    const cat = document.getElementById('catf').value;
    let rows = FINDINGS.filter(f => {{
      if (sev && f.severity !== sev) return false;
      if (cat && f.category !== cat) return false;
      if (q) {{
        const hay = (f.rule_name + ' ' + f.rule_id + ' ' + f.masked_value + ' ' +
                     (f.conversation_title||'') + ' ' + f.context + ' ' + f.role).toLowerCase();
        if (!hay.includes(q)) return false;
      }}
      return true;
    }});
    rows.sort((a, b) => {{
      let av, bv;
      if (sortKey === 'severity') {{ av = sevWeight(a.severity); bv = sevWeight(b.severity); }}
      else if (sortKey === 'timestamp') {{ av = a.timestamp || 0; bv = b.timestamp || 0; }}
      else {{ av = (a[sortKey]||'').toString().toLowerCase(); bv = (b[sortKey]||'').toString().toLowerCase(); }}
      if (av < bv) return -1 * sortDir;
      if (av > bv) return 1 * sortDir;
      return 0;
    }});
    document.querySelectorAll('thead th').forEach(th => {{
      const k = th.getAttribute('data-k');
      const arrow = th.querySelector('.arrow');
      if (!arrow) return;  // th without data-k (e.g. Context column) has no arrow
      if (k === sortKey) {{
        th.classList.add('sorted');
        arrow.textContent = sortDir === -1 ? '\\u2193' : '\\u2191';
      }} else {{
        th.classList.remove('sorted');
        arrow.textContent = '';
      }}
    }});

    const tbody = document.getElementById('rows');
    const tbl = document.getElementById('tbl');
    const emptyFiltered = document.getElementById('empty');
    const cleanEmpty = document.getElementById('cleanEmpty');
    tbody.innerHTML = '';

    if (FINDINGS.length === 0) {{
      tbl.style.display = 'none';
      emptyFiltered.style.display = 'none';
      cleanEmpty.style.display = 'block';
      document.getElementById('count').textContent = '';
      return;
    }}
    cleanEmpty.style.display = 'none';

    if (rows.length === 0) {{
      tbl.style.display = 'table';
      emptyFiltered.style.display = 'block';
    }} else {{
      tbl.style.display = 'table';
      emptyFiltered.style.display = 'none';
    }}
    document.getElementById('count').textContent = rows.length + ' / ' + FINDINGS.length;

    for (const f of rows) {{
      const tr = document.createElement('tr');
      tr.innerHTML =
        '<td class="sev"><span class="sev-cell" style="color:' + sevColor[f.severity] + '">' +
          '<span class="pixel" style="background:' + sevColor[f.severity] + '"></span>' +
          esc(f.severity) +
        '</span></td>' +
        '<td class="detector">' + esc(f.rule_name) + '<span class="rid">' + esc(f.rule_id) + '</span></td>' +
        '<td class="value">' + esc(f.masked_value) + '</td>' +
        '<td class="conv">' + esc(f.conversation_title || '(unknown)') + '<span class="role">' + esc(f.role) + '</span></td>' +
        '<td class="context">' + highlight(f.context || '', f.masked_value) + '</td>' +
        '<td class="when">' + fmtTs(f.timestamp) + '</td>';
      tr.addEventListener('click', () => openDrawer(f));
      tbody.appendChild(tr);
    }}
  }}

  function openDrawer(f) {{
    const body = document.getElementById('drawerBody');
    body.innerHTML =
      '<div class="tag-row">' +
        '<span class="tag" style="color:' + sevColor[f.severity] + '">' +
          '<span class="pixel" style="background:' + sevColor[f.severity] + '"></span>' +
          esc(f.severity) +
        '</span>' +
        '<span class="tag" style="color:var(--text-dim)">' + esc(f.category) + '</span>' +
      '</div>' +
      '<h2>' + esc(f.rule_name) + '</h2>' +
      '<div class="rid-line">' + esc(f.rule_id) + '</div>' +
      '<div class="field"><div class="lbl">Matched value</div><div class="val">' + esc(f.masked_value) + '</div></div>' +
      '<div class="field"><div class="lbl">Conversation</div><div class="val">' + esc(f.conversation_title || '(unknown)') + '</div></div>' +
      '<div class="field"><div class="lbl">Message role</div><div class="val">' + esc(f.role) + '</div></div>' +
      '<div class="field"><div class="lbl">Timestamp</div><div class="val">' + fmtTs(f.timestamp) + '</div></div>' +
      '<div class="field"><div class="lbl">Context</div><div class="ctx-box">' + highlight(f.context || '', f.masked_value) + '</div></div>' +
      (f.rotation_guide ? '<div class="rotation">' + esc(f.rotation_guide) + '</div>' : '');
    document.getElementById('drawer').classList.add('open');
    document.getElementById('overlay').classList.add('open');
  }}
  function closeDrawer() {{
    document.getElementById('drawer').classList.remove('open');
    document.getElementById('overlay').classList.remove('open');
  }}

  document.getElementById('q').addEventListener('input', render);
  document.getElementById('sevf').addEventListener('change', render);
  document.getElementById('catf').addEventListener('change', render);
  document.getElementById('closeBtn').addEventListener('click', closeDrawer);
  document.getElementById('overlay').addEventListener('click', closeDrawer);
  document.addEventListener('keydown', e => {{ if (e.key === 'Escape') closeDrawer(); }});
  document.querySelectorAll('thead th[data-k]').forEach(th => {{
    th.addEventListener('click', () => {{
      const k = th.getAttribute('data-k');
      if (sortKey === k) sortDir = -sortDir;
      else {{ sortKey = k; sortDir = (k === 'severity' || k === 'timestamp') ? -1 : 1; }}
      render();
    }});
  }});

  render();
</script>
</body>
</html>"""
