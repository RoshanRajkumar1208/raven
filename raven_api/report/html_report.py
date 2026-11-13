"""Self-contained HTML report.

* one file, no external requests (no fonts, scripts or images from the internet)
* everything that came from the scanned API is HTML-escaped: it is untrusted input
* works without JavaScript; JavaScript only adds filtering, search and copy buttons
"""

from __future__ import annotations

import datetime as dt
import html
from collections import OrderedDict
from typing import Dict, List, Tuple

from raven_api import __version__
from raven_api.engine import ScanResult
from raven_api.models import SEVERITIES, Finding

E = lambda s: html.escape(str(s if s is not None else ""), quote=True)  # noqa: E731

SEV_LABEL = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Info"}
GRADE_TEXT = {
    "A": "No significant issues found",
    "B": "Some issues worth fixing",
    "C": "Important issues to fix",
    "D": "Serious issues: fix before release",
    "F": "Critical issues: fix immediately",
}


def _group(findings: List[Finding]) -> "OrderedDict[Tuple[str, str, str], List[Finding]]":
    groups: "OrderedDict[Tuple[str, str, str], List[Finding]]" = OrderedDict()
    for f in findings:
        groups.setdefault((f.severity, f.check_id, f.title), []).append(f)
    return groups


def _bar(counts: Dict[str, int]) -> str:
    total = sum(counts.values())
    if not total:
        return '<div class="bar empty" role="img" aria-label="No findings"><span>No findings</span></div>'
    parts = []
    for s in SEVERITIES:
        n = counts.get(s, 0)
        if n:
            parts.append(f'<i class="sev-bg-{s}" style="flex:{n}" title="{SEV_LABEL[s]}: {n}"></i>')
    label = ", ".join(f"{counts.get(s, 0)} {s}" for s in SEVERITIES)
    return f'<div class="bar" role="img" aria-label="{E(label)}">{"".join(parts)}</div>'


def _code(label: str, text: str) -> str:
    if not text:
        return ""
    return (
        f'<div class="code"><div class="code-h"><span>{E(label)}</span>'
        f'<button type="button" class="copy" data-copy>Copy</button></div><pre>{E(text)}</pre></div>'
    )


def _instance(f: Finding, n: int, total: int) -> str:
    head = f'<span class="where">{E(f.endpoint)}</span>'
    if f.confidence == "tentative":
        head += '<span class="tag tentative" title="Needs a human to confirm">needs review</span>'
    body = ""
    if f.evidence:
        body += f'<div class="evidence"><h5>Evidence</h5><pre>{E(f.evidence)}</pre></div>'
    body += f'<p class="url">URL <code>{E(f.url)}</code></p>'
    body += _code("Request", f.request) + _code("Response", f.response)
    return f'<details class="inst"{" open" if total == 1 else ""}><summary>{head}</summary><div class="inst-b">{body}</div></details>'


def _group_card(key: Tuple[str, str, str], items: List[Finding], idx: int) -> str:
    sev, cid, title = key
    first = items[0]
    chips = f'<span class="tag mono">{E(cid)}</span>'
    if first.cwe:
        chips += f'<a class="tag mono" href="https://cwe.mitre.org/data/definitions/{int(first.cwe)}.html" target="_blank" rel="noopener noreferrer">CWE-{int(first.cwe)}</a>'
    if first.owasp:
        chips += f'<span class="tag">{E(first.owasp)}</span>'
    refs = "".join(
        f'<li><a href="{E(r)}" target="_blank" rel="noopener noreferrer">{E(r)}</a></li>' for r in first.references
    )
    where = f"{len(items)} place{'s' if len(items) != 1 else ''}"
    search = " ".join([title, cid, first.owasp, first.description] + [i.endpoint for i in items]).lower()
    instances = "".join(_instance(f, i, len(items)) for i, f in enumerate(items, 1))
    return f"""
<article class="finding sev-{sev}" data-sev="{sev}" data-check="{E(cid)}" data-search="{E(search)}" id="f{idx}">
  <details{" open" if idx <= 3 else ""}>
    <summary>
      <span class="pill sev-{sev}">{SEV_LABEL[sev]}</span>
      <span class="f-title">{E(title)}</span>
      <span class="f-where">{where}</span>
    </summary>
    <div class="f-body">
      <div class="chips">{chips}</div>
      <div class="cols">
        <div><h4>What it means</h4><p>{E(first.description)}</p></div>
        <div class="fix"><h4>How to fix it</h4><p>{E(first.fix)}</p>{f'<ul class="refs">{refs}</ul>' if refs else ''}</div>
      </div>
      <h4 class="inst-h">Where RAVEN found it</h4>
      {instances}
    </div>
  </details>
</article>"""


def render(result: ScanResult) -> str:
    from raven_api.report import grade

    counts = result.counts()
    g = grade(counts)
    groups = _group(result.findings)
    when = dt.datetime.fromtimestamp(result.finished).strftime("%d %b %Y, %H:%M")
    bases = sorted({e.base_url for e in result.spec.endpoints})
    scanned = sum(1 for e in result.endpoints if e.state == "scanned")
    skipped = sum(1 for e in result.endpoints if e.state == "skipped")
    errored = sum(1 for e in result.endpoints if e.state == "error")

    tiles = "".join(
        f'<button type="button" class="tile sev-{s}" data-filter="{s}" aria-pressed="false">'
        f'<b>{counts.get(s, 0)}</b><span>{SEV_LABEL[s]}</span></button>'
        for s in SEVERITIES
    )

    top = [k for k in groups if k[0] in ("critical", "high", "medium")][:3]
    top_html = ""
    if top:
        items = "".join(
            f'<li><a href="#f{list(groups).index(k) + 1}"><span class="pill sev-{k[0]}">{SEV_LABEL[k[0]]}</span>'
            f'<span>{E(k[2])}</span><em>{len(groups[k])}×</em></a></li>'
            for k in top
        )
        top_html = f'<section class="first"><h2>Fix these first</h2><ol>{items}</ol></section>'

    cards = "".join(_group_card(k, v, i) for i, (k, v) in enumerate(groups.items(), 1))
    if not cards:
        cards = '<p class="none">RAVEN found no issues with the checks it ran. Check the Coverage section for endpoints that were skipped.</p>'

    check_options = "".join(f'<option value="{E(c.id)}">{E(c.id)} · {E(c.name)}</option>' for c in result.checks)

    per_check: Dict[str, int] = {}
    for f in result.findings:
        per_check[f.check_id] = per_check.get(f.check_id, 0) + 1
    check_rows = "".join(
        f"<tr><td class='mono'>{E(c.id)}</td><td><b>{E(c.name)}</b><br><span class='muted'>{E(c.summary)}</span></td>"
        f"<td><span class='kind {E(c.kind)}'>{E(c.kind)}</span></td><td class='muted'>{E(c.limits)}</td>"
        f"<td class='num'>{per_check.get(c.id, 0)}</td></tr>"
        for c in result.checks
    )

    ep_rows = []
    for o in result.endpoints:
        status = f'<span class="st st{str(o.status)[0]}">{o.status}</span>' if o.status else "—"
        state = {"scanned": "Scanned", "skipped": "Skipped", "error": "No response"}[o.state]
        ep_rows.append(
            f"<tr class='state-{o.state}'><td><span class='m m-{E(o.method.lower())}'>{E(o.method)}</span></td>"
            f"<td class='mono path'>{E(o.path)}</td><td>{status}</td>"
            f"<td class='num'>{f'{o.elapsed_ms:.0f} ms' if o.elapsed_ms else '—'}</td>"
            f"<td class='num'>{o.findings or '—'}</td><td class='num'>{o.requests}</td>"
            f"<td><span class='state'>{state}</span>{f'<br><span class=muted>{E(o.note)}</span>' if o.note else ''}</td></tr>"
        )

    warn_html = ""
    if result.warnings:
        warn_html = '<section><h2>Notes from the scan</h2><ul class="warn">' + "".join(
            f"<li>{E(w)}</li>" for w in result.warnings
        ) + "</ul></section>"

    settings = [
        ("Input", f"{result.spec.source_type} · {result.source}"),
        ("Target", ", ".join(bases)),
        ("Authentication", result.auth_description),
        ("Write requests (POST/PUT/PATCH/DELETE)", "sent (--unsafe)" if result.options.unsafe else "not sent (safe mode)"),
        ("Checks", ", ".join(c.id for c in result.checks)),
        ("Slow-response threshold", f"{result.options.slow_ms} ms"),
    ]
    settings_html = "".join(f"<dt>{E(k)}</dt><dd>{E(v)}</dd>" for k, v in settings)

    return TEMPLATE.format(
        title=E(result.spec.title),
        version=__version__,
        when=E(when),
        input_type=E(result.spec.source_type),
        base=E(bases[0] if bases else ""),
        more_bases=E(f" +{len(bases) - 1} more" if len(bases) > 1 else ""),
        grade=g,
        grade_text=E(GRADE_TEXT[g]),
        total=len(result.findings),
        groups=len(groups),
        bar=_bar(counts),
        tiles=tiles,
        endpoints=len(result.endpoints),
        scanned=scanned,
        skipped=skipped,
        errored=errored,
        requests=result.requests_sent,
        duration=result.duration_s,
        checks=len(result.checks),
        top=top_html,
        cards=cards,
        check_options=check_options,
        check_rows=check_rows,
        ep_rows="".join(ep_rows),
        warnings=warn_html,
        settings=settings_html,
        stopped=f'<div class="stopped">{E(result.stopped_reason)}</div>' if result.stopped_reason else "",
        skipped_hint=(
            f'<p class="hint">{skipped} write endpoint(s) were not sent, so most checks did not run on them. '
            "Re-run with <code>--unsafe</code> against a test system to include them.</p>" if skipped else ""
        ),
    )


TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:">
<meta name="referrer" content="no-referrer">
<title>RAVEN report · {title}</title>
<style>
/* Layout: report = header band (grade + counts) → fix-first list → filterable finding groups → coverage tables. */
:root{{
  --bg:#0b0d13; --panel:#121624; --raise:#181d2d; --ink:#e8ebf4; --muted:#98a0b5; --line:#262d40;
  --accent:#8a92ff; --accent-2:#ff5c8a; --code:#080a10; --code-ink:#d6dcf0;
  --critical:#c084fc; --high:#ff5c6c; --medium:#ffa149; --low:#f2d14b; --info:#5fb8ff;
  --ok:#43d39a; --warn:#f3b546; --bad:#ff5c6c;
  --sans: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  --mono: ui-monospace, "SFMono-Regular", "JetBrains Mono", Menlo, Consolas, "Liberation Mono", monospace;
  color-scheme: dark;
}}
@media (prefers-color-scheme: light){{ :root:not([data-theme="dark"]){{
  --bg:#f3f4f8; --panel:#ffffff; --raise:#f6f7fb; --ink:#141824; --muted:#5a6276; --line:#dde1ea;
  --accent:#3b44e6; --accent-2:#d61f5a; --code:#0f1220; --code-ink:#dfe4f5;
  --critical:#8b3fd9; --high:#d92638; --medium:#c46200; --low:#9a7a00; --info:#1c73c4;
  --ok:#0b8257; --warn:#a35f00; --bad:#d92638; color-scheme: light;
}}}}
:root[data-theme="light"]{{
  --bg:#f3f4f8; --panel:#ffffff; --raise:#f6f7fb; --ink:#141824; --muted:#5a6276; --line:#dde1ea;
  --accent:#3b44e6; --accent-2:#d61f5a; --code:#0f1220; --code-ink:#dfe4f5;
  --critical:#8b3fd9; --high:#d92638; --medium:#c46200; --low:#9a7a00; --info:#1c73c4;
  --ok:#0b8257; --warn:#a35f00; --bad:#d92638; color-scheme: light;
}}
*{{box-sizing:border-box}}
html,body{{margin:0}}
body{{background:var(--bg);color:var(--ink);font:15px/1.55 var(--sans);padding:0 max(16px,env(safe-area-inset-left)) 48px max(16px,env(safe-area-inset-right))}}
a{{color:var(--accent)}}
:focus-visible{{outline:2px solid var(--accent);outline-offset:2px;border-radius:4px}}
.wrap{{max-width:1180px;margin:0 auto}}
.mono,code,pre{{font-family:var(--mono)}}
.muted{{color:var(--muted);font-size:13px}}
h2{{font-size:20px;margin:0 0 14px;letter-spacing:-.01em}}
h4{{font-size:12px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);margin:0 0 6px}}
section{{margin-top:36px}}

/* header */
.top{{display:flex;align-items:center;gap:14px;flex-wrap:wrap;padding:20px 0 18px;border-bottom:1px solid var(--line)}}
.logo{{display:flex;align-items:center;gap:10px;font:800 20px var(--mono);letter-spacing:.12em}}
.logo svg{{width:30px;height:30px}}
.logo small{{font:500 11px var(--mono);letter-spacing:.04em;color:var(--muted);display:block}}
.meta{{margin-left:auto;text-align:right;font:12.5px var(--mono);color:var(--muted)}}
.theme{{border:1px solid var(--line);background:var(--panel);color:var(--ink);border-radius:8px;padding:5px 10px;font:12px var(--mono);cursor:pointer}}

/* hero */
.hero{{display:grid;grid-template-columns:auto 1fr;gap:28px;align-items:center;margin-top:26px;
  background:linear-gradient(135deg,color-mix(in srgb,var(--accent) 12%,var(--panel)),var(--panel) 60%);border:1px solid var(--line);border-radius:18px;padding:24px}}
.grade{{width:132px;height:132px;border-radius:50%;display:grid;place-items:center;font:800 64px var(--sans);
  border:6px solid var(--g);color:var(--g);background:color-mix(in srgb,var(--g) 10%,transparent)}}
.grade-A{{--g:var(--ok)}} .grade-B{{--g:var(--info)}} .grade-C{{--g:var(--medium)}} .grade-D{{--g:var(--high)}} .grade-F{{--g:var(--critical)}}
.hero h1{{margin:0 0 4px;font-size:clamp(22px,3vw,30px);letter-spacing:-.02em;text-wrap:balance}}
.hero .sub{{color:var(--muted);font:13px var(--mono);word-break:break-all}}
.verdict{{font-size:17px;margin:10px 0 14px}}
.verdict b{{color:var(--g)}}
.bar{{display:flex;height:12px;border-radius:99px;overflow:hidden;background:var(--raise);gap:2px}}
.bar.empty{{height:auto;padding:4px 10px;font-size:12px;color:var(--ok)}}
.stats{{display:flex;flex-wrap:wrap;gap:6px 22px;margin-top:14px;font-size:13.5px;color:var(--muted)}}
.stats b{{color:var(--ink);font-variant-numeric:tabular-nums}}
.tiles{{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:10px;margin-top:14px}}
.tile{{background:var(--panel);border:1px solid var(--line);border-left:4px solid var(--c);border-radius:12px;padding:12px 14px;text-align:left;color:var(--ink);cursor:pointer;font:inherit}}
.tile b{{display:block;font-size:28px;line-height:1.1;font-variant-numeric:tabular-nums}}
.tile span{{font-size:13px;color:var(--muted)}}
.tile[aria-pressed="true"]{{background:color-mix(in srgb,var(--c) 16%,var(--panel));border-color:var(--c)}}
.sev-critical{{--c:var(--critical)}} .sev-high{{--c:var(--high)}} .sev-medium{{--c:var(--medium)}} .sev-low{{--c:var(--low)}} .sev-info{{--c:var(--info)}}
.sev-bg-critical{{background:var(--critical)}} .sev-bg-high{{background:var(--high)}} .sev-bg-medium{{background:var(--medium)}} .sev-bg-low{{background:var(--low)}} .sev-bg-info{{background:var(--info)}}
.pill{{display:inline-block;font:700 11px var(--mono);letter-spacing:.04em;text-transform:uppercase;padding:3px 8px;border-radius:6px;
  color:var(--c);background:color-mix(in srgb,var(--c) 16%,transparent);border:1px solid color-mix(in srgb,var(--c) 40%,transparent);white-space:nowrap}}

.first ol{{list-style:none;margin:0;padding:0;display:grid;gap:8px}}
.first a{{display:flex;align-items:center;gap:12px;padding:12px 14px;background:var(--panel);border:1px solid var(--line);border-radius:12px;color:var(--ink);text-decoration:none}}
.first a:hover{{border-color:var(--accent)}}
.first em{{margin-left:auto;font:12px var(--mono);color:var(--muted);font-style:normal}}

/* toolbar */
.toolbar{{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin-bottom:14px}}
.toolbar input,.toolbar select{{background:var(--panel);border:1px solid var(--line);color:var(--ink);border-radius:10px;padding:9px 12px;font:14px var(--sans);min-width:0}}
.toolbar input{{flex:1 1 240px}}
.toolbar .count{{font:12.5px var(--mono);color:var(--muted)}}
.toolbar button{{background:none;border:1px solid var(--line);color:var(--muted);border-radius:10px;padding:8px 12px;cursor:pointer;font:13px var(--sans)}}

/* findings */
.findings{{display:grid;gap:10px}}
.finding{{background:var(--panel);border:1px solid var(--line);border-left:4px solid var(--c);border-radius:12px;min-width:0}}
.finding > details > summary{{display:flex;align-items:center;gap:12px;padding:14px 16px;cursor:pointer;list-style:none}}
.finding > details > summary::-webkit-details-marker{{display:none}}
.finding > details > summary::after{{content:"+";margin-left:8px;font:600 18px var(--mono);color:var(--muted)}}
.finding > details[open] > summary::after{{content:"–"}}
.f-title{{font-weight:600;font-size:15.5px;min-width:0}}
.f-where{{margin-left:auto;font:12.5px var(--mono);color:var(--muted);white-space:nowrap}}
.f-body{{padding:0 16px 16px;display:grid;gap:14px;min-width:0}}
.chips{{display:flex;flex-wrap:wrap;gap:6px}}
.tag{{font-size:12px;padding:2px 8px;border-radius:6px;background:var(--raise);border:1px solid var(--line);color:var(--ink);text-decoration:none}}
.tag.tentative{{color:var(--warn);border-color:color-mix(in srgb,var(--warn) 45%,transparent);margin-left:8px}}
.cols{{display:grid;grid-template-columns:1fr 1fr;gap:18px}}
.cols p{{margin:0}}
.fix{{background:color-mix(in srgb,var(--ok) 7%,transparent);border:1px solid color-mix(in srgb,var(--ok) 30%,transparent);border-radius:10px;padding:12px 14px}}
.fix h4{{color:var(--ok)}}
.refs{{margin:8px 0 0;padding-left:18px;font-size:13px;word-break:break-all}}
.inst-h{{margin-top:4px}}
.inst{{border:1px solid var(--line);border-radius:10px;background:var(--raise);min-width:0}}
.inst > summary{{padding:9px 12px;cursor:pointer;font:13px var(--mono)}}
.inst-b{{padding:0 12px 12px;display:grid;gap:10px;min-width:0}}
.url{{margin:0;font-size:13px;word-break:break-all}}
.evidence h5{{margin:0 0 4px;font-size:12px;color:var(--muted)}}
.evidence pre{{margin:0;padding:10px 12px;border-radius:8px;background:color-mix(in srgb,var(--accent) 9%,var(--panel));border:1px solid var(--line);white-space:pre-wrap;word-break:break-word;font-size:12.5px}}
.code{{border-radius:8px;overflow:hidden;border:1px solid var(--line);min-width:0}}
.code-h{{display:flex;justify-content:space-between;align-items:center;background:var(--code);color:var(--muted);font:11px var(--mono);padding:6px 10px;text-transform:uppercase;letter-spacing:.08em}}
.copy{{background:none;border:1px solid #2b3248;color:#aab2cc;border-radius:6px;font:11px var(--mono);padding:2px 8px;cursor:pointer}}
.code pre{{margin:0;background:var(--code);color:var(--code-ink);padding:10px 12px;font-size:12px;line-height:1.5;max-height:340px;overflow:auto;white-space:pre-wrap;word-break:break-word}}
.none{{padding:24px;background:var(--panel);border:1px dashed var(--line);border-radius:12px;color:var(--muted)}}
.hidden{{display:none!important}}

/* tables */
.tbl{{overflow-x:auto;border:1px solid var(--line);border-radius:12px;background:var(--panel)}}
table{{border-collapse:collapse;width:100%;font-size:13.5px}}
th,td{{padding:10px 12px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}}
th{{font-size:11.5px;text-transform:uppercase;letter-spacing:.07em;color:var(--muted);background:var(--raise);position:sticky;top:0}}
tr:last-child td{{border-bottom:0}}
.num{{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}}
.path{{word-break:break-all}}
.m{{font:700 11px var(--mono);padding:2px 7px;border-radius:5px;background:var(--raise);border:1px solid var(--line)}}
.m-get{{color:var(--ok)}} .m-post{{color:var(--accent)}} .m-put,.m-patch{{color:var(--medium)}} .m-delete{{color:var(--high)}}
.st{{font:600 12.5px var(--mono)}} .st2{{color:var(--ok)}} .st3{{color:var(--info)}} .st4{{color:var(--warn)}} .st5{{color:var(--bad)}}
.state-skipped td{{opacity:.75}} .state-error .state{{color:var(--bad)}}
.kind{{font:11px var(--mono);padding:2px 7px;border-radius:5px;border:1px solid var(--line)}}
.kind.active{{color:var(--accent-2)}} .kind.passive{{color:var(--info)}}
.hint{{font-size:13.5px;color:var(--muted);margin:10px 0 0}}
dl{{display:grid;grid-template-columns:max-content 1fr;gap:6px 18px;margin:0;font-size:13.5px}}
dt{{color:var(--muted)}} dd{{margin:0;word-break:break-word}}
.warn{{margin:0;padding-left:18px;color:var(--warn);font-size:13.5px}}
.stopped{{margin-top:16px;padding:12px 14px;border-radius:10px;border:1px solid var(--warn);color:var(--warn)}}
footer{{margin-top:40px;padding-top:16px;border-top:1px solid var(--line);font:12px var(--mono);color:var(--muted);display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap}}

@media (max-width:820px){{
  .hero{{grid-template-columns:1fr;justify-items:start}}
  .cols{{grid-template-columns:1fr}}
  .meta{{margin-left:0;text-align:left}}
  .f-where{{display:none}}
}}
@media (max-width:460px){{ .tiles{{grid-template-columns:repeat(2,minmax(0,1fr))}} .tile:last-child{{grid-column:span 2}} .grade{{width:100px;height:100px;font-size:48px}} }}
@media print{{
  body{{background:#fff;color:#000}} .toolbar,.theme,.copy{{display:none}} details{{display:block}}
  .finding,.tile,.hero,.tbl{{break-inside:avoid;border-color:#ccc;background:#fff}}
}}
@media (prefers-reduced-motion:reduce){{*{{transition:none!important}}}}
</style>
</head>
<body>
<div class="wrap">
<header class="top">
  <div class="logo">
    <svg viewBox="0 0 32 32" aria-hidden="true"><path d="M4 18c4-1 7-4 9-8 2-4 6-6 11-5l4 3-4 1c1 3 0 6-2 8l4 7-6-4c-3 2-7 2-11 1l-5 3 2-4c-1 0-2-1-2-2z" fill="var(--accent)"/><circle cx="21" cy="8.5" r="1.2" fill="var(--bg)"/></svg>
    <div>RAVEN<small>REST API Validation Engine · v{version}</small></div>
  </div>
  <div class="meta">{when}<br>{input_type}</div>
  <button type="button" class="theme" id="theme">Theme</button>
</header>

<section class="hero grade-{grade}" style="margin-top:26px">
  <div class="grade" aria-label="Grade {grade}">{grade}</div>
  <div style="min-width:0">
    <h1>{title}</h1>
    <div class="sub">{base}{more_bases}</div>
    <p class="verdict"><b>{grade_text}.</b> {total} findings in {groups} groups.</p>
    {bar}
    <div class="stats">
      <span><b>{scanned}</b> of {endpoints} endpoints scanned</span>
      <span><b>{skipped}</b> skipped</span>
      <span><b>{errored}</b> no response</span>
      <span><b>{requests}</b> requests</span>
      <span><b>{checks}</b> checks</span>
      <span><b>{duration}s</b></span>
    </div>
  </div>
</section>
<div class="tiles" role="group" aria-label="Filter by severity">{tiles}</div>
{stopped}
{top}

<section>
  <h2>Findings</h2>
  <div class="toolbar">
    <input id="q" type="search" placeholder="Search findings, endpoints, OWASP category…" aria-label="Search findings">
    <select id="check" aria-label="Filter by check"><option value="">All checks</option>{check_options}</select>
    <button type="button" id="expand">Expand all</button>
    <span class="count" id="count"></span>
  </div>
  <div class="findings" id="findings">{cards}</div>
</section>

<section>
  <h2>Coverage</h2>
  <div class="tbl"><table>
    <thead><tr><th>Method</th><th>Path</th><th>Status</th><th class="num">Time</th><th class="num">Findings</th><th class="num">Requests</th><th>Result</th></tr></thead>
    <tbody>{ep_rows}</tbody>
  </table></div>
  {skipped_hint}
</section>

<section>
  <h2>Checks that ran</h2>
  <div class="tbl"><table>
    <thead><tr><th>ID</th><th>Check</th><th>Type</th><th>Limits</th><th class="num">Findings</th></tr></thead>
    <tbody>{check_rows}</tbody>
  </table></div>
</section>

{warnings}

<section>
  <h2>Scan settings</h2>
  <dl>{settings}</dl>
</section>

<footer>
  <span>Generated by RAVEN v{version} · github.com/RoshanRajkumar1208/raven</span>
  <span>Only scan systems you own or are authorised to test.</span>
</footer>
</div>
<script>
(function(){{
  var active = new Set(), q = document.getElementById('q'), sel = document.getElementById('check');
  var cards = Array.prototype.slice.call(document.querySelectorAll('.finding'));
  var count = document.getElementById('count');
  function apply(){{
    var term = (q.value || '').toLowerCase().trim(), chk = sel.value, shown = 0;
    cards.forEach(function(c){{
      var ok = (!active.size || active.has(c.dataset.sev)) && (!chk || c.dataset.check === chk) && (!term || c.dataset.search.indexOf(term) > -1);
      c.classList.toggle('hidden', !ok); if (ok) shown++;
    }});
    count.textContent = shown + ' of ' + cards.length + ' groups';
  }}
  document.querySelectorAll('[data-filter]').forEach(function(b){{
    b.addEventListener('click', function(){{
      var s = b.dataset.filter; if (active.has(s)) active.delete(s); else active.add(s);
      b.setAttribute('aria-pressed', active.has(s)); apply();
    }});
  }});
  q.addEventListener('input', apply); sel.addEventListener('change', apply);
  var open = false;
  document.getElementById('expand').addEventListener('click', function(e){{
    open = !open; document.querySelectorAll('.finding > details').forEach(function(d){{ d.open = open; }});
    e.target.textContent = open ? 'Collapse all' : 'Expand all';
  }});
  document.addEventListener('click', function(e){{
    var b = e.target.closest('[data-copy]'); if (!b) return;
    var text = b.closest('.code').querySelector('pre').textContent;
    var done = function(){{ b.textContent = 'Copied'; setTimeout(function(){{ b.textContent = 'Copy'; }}, 1400); }};
    if (navigator.clipboard) navigator.clipboard.writeText(text).then(done, function(){{}});
  }});
  var root = document.documentElement;
  document.getElementById('theme').addEventListener('click', function(){{
    var dark = root.dataset.theme ? root.dataset.theme === 'dark' : !matchMedia('(prefers-color-scheme: light)').matches;
    root.dataset.theme = dark ? 'light' : 'dark';
  }});
  apply();
}})();
</script>
</body>
</html>
"""
