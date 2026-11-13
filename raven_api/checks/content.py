"""Response content checks: verbose errors and sensitive data."""

from __future__ import annotations

import re
from typing import List, Tuple

from raven_api.checks.base import Check, ScanContext
from raven_api.models import Endpoint, Finding

ERROR_SIGNATURES: List[Tuple[str, re.Pattern]] = [
    ("Python stack trace", re.compile(r"Traceback \(most recent call last\)")),
    ("Java stack trace", re.compile(r"\bat [a-z]+(\.[A-Za-z0-9_$]+){2,}\([A-Za-z0-9_]+\.java:\d+\)")),
    ("Java exception", re.compile(r"\b(java|javax|org\.springframework)\.[A-Za-z.]+(Exception|Error)\b")),
    (".NET exception", re.compile(r"System\.[A-Za-z.]+Exception|   at [A-Za-z0-9_.]+\(.*\) in .*:line \d+")),
    ("Node.js stack trace", re.compile(r"at [^\n]+ \((/[^\n)]+|[A-Z]:\\[^\n)]+)\.js:\d+:\d+\)")),
    ("PHP error", re.compile(r"(Fatal error|Warning|Parse error)</b>?:.* on line <b>?\d+|PHP (Fatal|Warning|Notice)")),
    ("Database error message", re.compile(r"SQLSTATE\[|ORA-\d{5}|PG::[A-Za-z]+Error|psycopg2\.|sqlite3\.[A-Za-z]+Error|"
                                          r"You have an error in your SQL syntax|Unclosed quotation mark|SequelizeDatabaseError")),
    ("Framework debug page", re.compile(r"Werkzeug Debugger|Whitelabel Error Page|DEBUG = True|<title>Django.*Error|Laravel.*Exception")),
    ("Internal file path", re.compile(r"(/home/[a-z0-9_-]+/|/var/www/|/usr/src/app/|/opt/[a-z0-9_-]+/[a-z0-9_/-]+\.(py|js|rb|php|java)|[A-Z]:\\(inetpub|Users)\\)")),
]

SECRET_PATTERNS: List[Tuple[str, re.Pattern, str]] = [
    ("Private key", re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----"), "critical"),
    ("AWS access key ID", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), "high"),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "high"),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), "high"),
    ("Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), "high"),
    ("Stripe secret key", re.compile(r"\bsk_live_[0-9A-Za-z]{20,}\b"), "high"),
    ("Password field with a value", re.compile(r'"(password|passwd|pwd|password_hash|passwordHash|secret|client_secret)"\s*:\s*"([^"*•]{4,})"', re.I), "high"),
]


def _mask(text: str) -> str:
    return text[:4] + "…" + f"({len(text)} chars, masked)" if len(text) > 6 else "****"


def collect_secrets(results, secrets: set) -> None:
    """Remember secret values seen in responses so the report never repeats them.

    Runs on every scan, even when the Sensitive data check is switched off.
    """
    for res in results:
        if not res.ok:
            continue
        text = res.text[:500000]
        for label, pattern, _ in SECRET_PATTERNS:
            for m in pattern.finditer(text):
                secrets.add(m.group(2) if label.startswith("Password") else m.group(0))


class VerboseErrors(Check):
    id = "RAV-E01"
    name = "Verbose error messages"
    kind = "passive"
    summary = "Looks through every response RAVEN received for stack traces, database errors, debug pages and internal file paths."
    limits = "Pattern-based: recognises common frameworks and databases; unusual stacks may be missed."

    def run_endpoint(self, ctx: ScanContext, ep: Endpoint, baseline) -> List[Finding]:
        seen = set()
        out: List[Finding] = []
        for res in ctx.results:
            if not res.ok:
                continue
            text = res.text[:200000]
            for label, pattern in ERROR_SIGNATURES:
                m = pattern.search(text)
                if m and label not in seen:
                    seen.add(label)
                    start = max(0, m.start() - 60)
                    out.append(self.finding(
                        title=f"Verbose error: {label}",
                        severity="medium" if label != "Internal file path" else "low",
                        endpoint=ep.key,
                        url=res.exchange.url,
                        description="The API returned internal error details. They reveal the technology stack, code structure or database, "
                        "which makes targeted attacks much easier.",
                        fix="Return a short, generic error body (e.g. {\"error\": \"invalid request\"}) and log the details on the server only. "
                        "Turn off debug mode in production.",
                        evidence=text[start:m.end() + 120].strip(),
                        result=res,
                        cwe=209,
                        owasp="API8:2023 Security Misconfiguration",
                    ))
        return out


class SensitiveData(Check):
    id = "RAV-D01"
    name = "Sensitive data in responses"
    kind = "passive"
    summary = "Scans the normal responses for secrets: private keys, cloud and service API keys, and password fields with values."
    limits = "Recognises well-known secret formats only. Personal data (names, addresses) is not classified."

    def run_endpoint(self, ctx: ScanContext, ep: Endpoint, baseline) -> List[Finding]:
        if baseline is None or not baseline.ok:
            return []
        text = baseline.text[:500000]
        out: List[Finding] = []
        for label, pattern, severity in SECRET_PATTERNS:
            m = pattern.search(text)
            if not m:
                continue
            value = m.group(2) if label.startswith("Password") else m.group(0)
            ctx.secrets.add(value)
            shown = m.group(0).replace(value, _mask(value)) if label.startswith("Password") else _mask(value)
            out.append(self._masked(value, self.finding(
                title=f"Secret in response: {label}",
                severity=severity,
                endpoint=ep.key,
                url=baseline.exchange.url,
                description="The response contains something that looks like a secret. Anyone who can call this endpoint can read it.",
                fix="Remove the field from the response (use an explicit response model / serializer allow-list) and rotate the exposed secret.",
                evidence=shown,
                result=baseline,
                cwe=200,
                owasp="API3:2023 Broken Object Property Level Authorization",
            )))
        return out

    @staticmethod
    def _masked(secret: str, finding: Finding) -> Finding:
        """Never copy the secret itself into the report."""
        finding.response = finding.response.replace(secret, _mask(secret))
        return finding
