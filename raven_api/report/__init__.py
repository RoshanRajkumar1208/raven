"""Report writers: HTML, JSON, SARIF and Markdown."""

from __future__ import annotations

import os
from typing import Dict, List

from raven_api.engine import ScanResult

FORMATS = ("html", "json", "sarif", "md")


def write_reports(result: ScanResult, out_dir: str, formats: List[str]) -> Dict[str, str]:
    from raven_api.report import html_report, json_report, markdown_report, sarif_report

    os.makedirs(out_dir, exist_ok=True)
    writers = {
        "html": ("report.html", html_report.render),
        "json": ("findings.json", json_report.render),
        "sarif": ("findings.sarif", sarif_report.render),
        "md": ("summary.md", markdown_report.render),
    }
    written = {}
    for fmt in formats:
        name, render = writers[fmt]
        path = os.path.join(out_dir, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(render(result))
        written[fmt] = path
    return written


def grade(counts: Dict[str, int]) -> str:
    """A simple letter grade so non-specialists can read the result at a glance."""
    if counts.get("critical"):
        return "F"
    if counts.get("high", 0) >= 2:
        return "D"
    if counts.get("high") or counts.get("medium", 0) > 3:
        return "C"
    if counts.get("medium"):
        return "B"
    return "A"
