"""Machine-readable JSON report."""

from __future__ import annotations

import datetime as dt
import json
from dataclasses import asdict

from raven_api import __version__
from raven_api.engine import ScanResult


def to_dict(result: ScanResult) -> dict:
    from raven_api.report import grade

    counts = result.counts()
    return {
        "tool": "RAVEN",
        "version": __version__,
        "generated": dt.datetime.fromtimestamp(result.finished).astimezone().isoformat(timespec="seconds"),
        "source": result.source,
        "api": {
            "title": result.spec.title,
            "input_type": result.spec.source_type,
            "spec_version": result.spec.version,
            "base_urls": sorted({e.base_url for e in result.spec.endpoints}),
        },
        "summary": {
            "grade": grade(counts),
            "counts": counts,
            "findings": len(result.findings),
            "endpoints": len(result.endpoints),
            "endpoints_scanned": sum(1 for e in result.endpoints if e.state == "scanned"),
            "requests_sent": result.requests_sent,
            "duration_seconds": result.duration_s,
            "stopped_reason": result.stopped_reason,
        },
        "settings": {
            "unsafe": result.options.unsafe,
            "auth": result.auth_description,
            "slow_ms": result.options.slow_ms,
            "checks": [c.id for c in result.checks],
        },
        "endpoints": [asdict(e) for e in result.endpoints],
        "findings": [f.to_dict() for f in result.findings],
        "warnings": result.warnings,
    }


def render(result: ScanResult) -> str:
    return json.dumps(to_dict(result), indent=2, ensure_ascii=False)
