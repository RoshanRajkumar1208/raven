"""Response header checks: security headers, technology disclosure, cookies."""

from __future__ import annotations

import re
from typing import List

from raven_api.checks.base import Check, ScanContext
from raven_api.models import Endpoint, Finding

OWASP_MISCONFIG = "API8:2023 Security Misconfiguration"


class SecurityHeaders(Check):
    id = "RAV-H01"
    name = "Security headers"
    kind = "passive"
    summary = "Checks that responses carry the headers that protect API clients: HSTS, nosniff, Cache-Control on authenticated data, and framing protection on HTML."
    limits = "Header requirements differ by API type; X-XSS-Protection is not required because modern browsers ignore it."

    def run_endpoint(self, ctx: ScanContext, ep: Endpoint, baseline) -> List[Finding]:
        if not baseline.ok:
            return []
        h = {k.lower(): v for k, v in baseline.headers.items()}
        problems = []
        severity = "low"
        https = baseline.request.url.lower().startswith("https://")

        if https:
            hsts = h.get("strict-transport-security")
            if not hsts:
                problems.append("Strict-Transport-Security is missing")
                severity = "medium"
            else:
                m = re.search(r"max-age\s*=\s*(\d+)", hsts)
                if not m or int(m.group(1)) < 15552000:
                    problems.append(f"Strict-Transport-Security max-age is below 180 days ({hsts})")
        if h.get("x-content-type-options", "").lower() != "nosniff":
            problems.append("X-Content-Type-Options: nosniff is missing")
        sent_credentials = ctx.client.auth.configured or ep.auth_required
        if sent_credentials and 200 <= baseline.status < 300:
            cc = h.get("cache-control", "").lower()
            if "no-store" not in cc and "private" not in cc:
                problems.append("Cache-Control does not prevent caching of authenticated data (add no-store)")
        if "text/html" in baseline.content_type:
            csp = h.get("content-security-policy", "")
            if "frame-ancestors" not in csp and not h.get("x-frame-options"):
                problems.append("HTML response has no framing protection (X-Frame-Options or CSP frame-ancestors)")

        if not problems:
            return []
        return [
            self.finding(
                title="Missing or weak security headers",
                severity=severity,
                endpoint=ep.key,
                url=baseline.exchange.url,
                description="The response is missing headers that tell clients and browsers how to handle it safely.",
                fix="Set these headers once, in your API gateway or web framework middleware, so every response gets them: "
                "Strict-Transport-Security: max-age=31536000; includeSubDomains, X-Content-Type-Options: nosniff, "
                "Cache-Control: no-store (for authenticated responses).",
                evidence="\n".join("• " + p for p in problems),
                result=baseline,
                cwe=693,
                owasp=OWASP_MISCONFIG,
                references=["https://owasp.org/www-project-secure-headers/"],
            )
        ]


class TechnologyDisclosure(Check):
    id = "RAV-H02"
    name = "Technology disclosure"
    kind = "passive"
    summary = "Flags headers that reveal server software and exact versions (Server, X-Powered-By, X-AspNet-Version...)."
    limits = "Only looks at response headers, not at page content."

    HEADERS = ("x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator", "x-runtime", "x-version")

    def run_endpoint(self, ctx: ScanContext, ep: Endpoint, baseline) -> List[Finding]:
        if not baseline.ok:
            return []
        leaks = []
        for k, v in baseline.headers.items():
            low = k.lower()
            if low in self.HEADERS:
                leaks.append(f"{k}: {v}")
            elif low == "server" and re.search(r"\d", v):
                leaks.append(f"{k}: {v}")
        if not leaks:
            return []
        return [
            self.finding(
                title="Server software and version disclosed",
                severity="low",
                endpoint=ep.key,
                url=baseline.exchange.url,
                description="Response headers reveal which software (and which version) runs the API. "
                "This helps someone match the server to publicly known vulnerabilities.",
                fix="Remove or genericise these headers (e.g. app.disable('x-powered-by') in Express, "
                "server_tokens off in nginx, ServerTokens Prod in Apache).",
                evidence="\n".join(leaks),
                result=baseline,
                cwe=200,
                owasp=OWASP_MISCONFIG,
            )
        ]


class CookieFlags(Check):
    id = "RAV-H03"
    name = "Cookie security flags"
    kind = "passive"
    summary = "Checks every Set-Cookie for the Secure, HttpOnly and SameSite attributes."
    limits = "Cannot tell which cookies hold sessions; session-like names are rated higher."

    SESSION_HINT = re.compile(r"sess|sid|auth|token|jwt|login", re.I)

    def run_endpoint(self, ctx: ScanContext, ep: Endpoint, baseline) -> List[Finding]:
        if baseline.response is None:
            return []
        raw = baseline.response.raw
        cookies = []
        try:
            cookies = raw.headers.getlist("Set-Cookie") if raw is not None else []
        except AttributeError:
            pass
        if not cookies and baseline.header("Set-Cookie"):
            cookies = [baseline.header("Set-Cookie")]
        https = baseline.request.url.lower().startswith("https://")
        out = []
        for cookie in cookies:
            name = cookie.split("=", 1)[0].strip()
            attrs = cookie.lower()
            missing = []
            if https and "secure" not in [a.strip() for a in attrs.split(";")]:
                missing.append("Secure")
            if "httponly" not in attrs:
                missing.append("HttpOnly")
            if "samesite" not in attrs:
                missing.append("SameSite")
            if not missing:
                continue
            sev = "medium" if self.SESSION_HINT.search(name) and ("HttpOnly" in missing or "Secure" in missing) else "low"
            out.append(
                self.finding(
                    title="Cookie set without security flags",
                    severity=sev,
                    endpoint=ep.key,
                    url=baseline.exchange.url,
                    description=f"The cookie '{name}' is missing: {', '.join(missing)}. Without HttpOnly, page scripts can read it; "
                    "without Secure it can travel over plain HTTP; without SameSite it is sent on cross-site requests.",
                    fix="Set cookies with: Secure; HttpOnly; SameSite=Lax (or Strict).",
                    evidence=f"Set-Cookie: {cookie}",
                    result=baseline,
                    cwe=614 if "Secure" in missing else 1004,
                    owasp=OWASP_MISCONFIG,
                )
            )
        return out
