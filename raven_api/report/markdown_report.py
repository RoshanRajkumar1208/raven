"""Short Markdown summary: paste it into a ticket, a pull request or a CI job summary."""

from __future__ import annotations

from collections import OrderedDict

from raven_api.engine import ScanResult

_ICON = {"critical": "🟣", "high": "🔴", "medium": "🟠", "low": "🟡", "info": "🔵"}


def render(result: ScanResult) -> str:
    from raven_api.report import grade

    counts = result.counts()
    lines = [
        f"## RAVEN scan: {result.spec.title}",
        "",
        f"**Grade {grade(counts)}** · {len(result.findings)} findings · {len(result.endpoints)} endpoints · "
        f"{result.requests_sent} requests · {result.duration_s}s",
        "",
        "| Severity | Count |",
        "|---|---|",
    ]
    lines += [f"| {_ICON[s]} {s.title()} | {n} |" for s, n in counts.items()]
    grouped: "OrderedDict[tuple, list]" = OrderedDict()
    for f in result.findings:
        grouped.setdefault((f.severity, f.check_id, f.title), []).append(f.endpoint)
    if grouped:
        lines += ["", "### Findings", "", "| Severity | Check | Finding | Where |", "|---|---|---|---|"]
        for (sev, cid, title), where in grouped.items():
            shown = ", ".join(f"`{w}`" for w in where[:4]) + (f" +{len(where) - 4} more" if len(where) > 4 else "")
            lines.append(f"| {_ICON[sev]} {sev} | {cid} | {title} | {shown} |")
    skipped = [e for e in result.endpoints if e.state == "skipped"]
    if skipped:
        lines += ["", f"_{len(skipped)} write endpoint(s) were not sent. Re-run with `--unsafe` against a test system to include them._"]
    if result.stopped_reason:
        lines += ["", f"> ⚠️ {result.stopped_reason}"]
    return "\n".join(lines) + "\n"
