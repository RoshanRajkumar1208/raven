"""SARIF 2.1.0 output, for GitHub code scanning and other security dashboards."""

from __future__ import annotations

import hashlib
import json
import os

from raven_api import __version__
from raven_api.engine import ScanResult

_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
_SCORE = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "1.0"}


def render(result: ScanResult) -> str:
    source = result.source or "api-description"
    if source.lower().startswith(("http://", "https://")):
        artifact = source
    else:
        try:
            artifact = os.path.relpath(source).replace(os.sep, "/")
        except ValueError:  # Windows: file on another drive
            artifact = os.path.basename(source)
    rules = {}
    for check in result.checks:
        rules[check.id] = {
            "id": check.id,
            "name": check.name.replace(" ", ""),
            "shortDescription": {"text": check.name},
            "fullDescription": {"text": check.summary},
            "help": {"text": f"{check.summary}\nLimits: {check.limits}"},
            "properties": {"tags": ["security", "api"]},
        }
    results = []
    for f in result.findings:
        rule = rules.setdefault(f.check_id, {"id": f.check_id, "shortDescription": {"text": f.title}})
        sev = rule.setdefault("properties", {}).get("security-severity")
        if sev is None or float(_SCORE[f.severity]) > float(sev):
            rule["properties"]["security-severity"] = _SCORE[f.severity]
        fingerprint = hashlib.sha256(f"{f.check_id}|{f.title}|{f.endpoint}".encode()).hexdigest()[:32]
        results.append({
            "ruleId": f.check_id,
            "level": _LEVEL.get(f.severity, "note"),
            "message": {"text": f"{f.title} — {f.endpoint}\n{f.description}\nFix: {f.fix}" + (f"\nEvidence: {f.evidence}" if f.evidence else "")},
            "locations": [{
                "physicalLocation": {"artifactLocation": {"uri": artifact}, "region": {"startLine": 1}},
                "logicalLocations": [{"name": f.endpoint, "fullyQualifiedName": f.url, "kind": "resource"}],
            }],
            "partialFingerprints": {"ravenFinding/v1": fingerprint},
            "properties": {"severity": f.severity, "confidence": f.confidence, "cwe": f.cwe, "owasp": f.owasp},
        })
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "RAVEN",
                "version": __version__,
                "informationUri": "https://github.com/RoshanRajkumar1208/raven",
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }
    return json.dumps(doc, indent=2)
