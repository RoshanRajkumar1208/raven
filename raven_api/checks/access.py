"""Authentication enforcement and operational checks (response time, rate-limit signals)."""

from __future__ import annotations

from typing import Dict, List

from raven_api.checks.base import Check, ScanContext
from raven_api.models import Endpoint, Finding


class AuthEnforcement(Check):
    id = "RAV-A01"
    name = "Authentication enforcement"
    kind = "active"
    summary = "Repeats the request with all credentials removed. Endpoints the description marks as protected must answer 401 or 403."
    limits = "Checks that a login is required, not what a logged-in user is allowed to see (object-level authorization needs two test accounts)."

    def run_endpoint(self, ctx: ScanContext, ep: Endpoint, baseline) -> List[Finding]:
        if baseline is None or not baseline.ok:
            return []
        has_creds = ctx.client.auth.configured or any(
            k.lower() in ctx.client.auth.secret_names for k in baseline.request.headers
        )
        if ep.auth_required is False or (ep.auth_required is None and not has_creds):
            return []
        res = ctx.send(baseline.request.copy(), with_auth=False)
        if not res.ok or not (200 <= res.status < 300):
            return []
        if ep.auth_required:
            title, severity, confidence = "Protected endpoint answers without credentials", "high", "firm"
            why = "The API description says this endpoint requires authentication, but it answered successfully to a request with no credentials at all."
        else:
            title, severity, confidence = "Endpoint answers without credentials", "medium", "tentative"
            why = ("RAVEN removed every credential and the endpoint still answered successfully. "
                   "The description does not say whether it should be public, so please confirm this is intended.")
        same = baseline.ok and res.text[:2000] == baseline.text[:2000]
        return [self.finding(
            title=title,
            severity=severity,
            endpoint=ep.key,
            url=res.exchange.url,
            description=why,
            fix="Enforce authentication in one central place (gateway or middleware) that denies by default, and opt endpoints out explicitly when they are public.",
            evidence=f"With credentials: {baseline.status}\nWithout credentials: {res.status}" + ("\nResponse bodies are identical." if same else ""),
            result=res,
            confidence=confidence,
            cwe=306,
            owasp="API2:2023 Broken Authentication",
        )]


class SlowResponses(Check):
    id = "RAV-P01"
    name = "Slow responses"
    kind = "passive"
    summary = "Reports endpoints whose normal response takes longer than --slow-ms (default 2000 ms)."
    limits = "One measurement per endpoint; network latency is included."

    def run_endpoint(self, ctx: ScanContext, ep: Endpoint, baseline) -> List[Finding]:
        if baseline is None or not baseline.ok or baseline.elapsed_ms < ctx.options.slow_ms:
            return []
        return [self.finding(
            title="Slow response",
            severity="info",
            endpoint=ep.key,
            url=baseline.exchange.url,
            description=f"The endpoint took {baseline.elapsed_ms:.0f} ms to answer. Slow endpoints are the easiest target for resource-exhaustion (denial of service).",
            fix="Add pagination and limits, cache expensive results, and protect slow endpoints with rate limiting.",
            evidence=f"{baseline.elapsed_ms:.0f} ms (threshold {ctx.options.slow_ms} ms)",
            result=baseline,
            owasp="API4:2023 Unrestricted Resource Consumption",
        )]


class RateLimitSignals(Check):
    """Looks at headers only. RAVEN does not flood the API to test rate limits."""

    id = "RAV-R01"
    name = "Rate-limit signals"
    kind = "passive"
    scope = "summary"
    summary = "After the scan, reports hosts where no response carried rate-limit headers (RateLimit-*, X-RateLimit-*, Retry-After)."
    limits = "Absence of headers does not prove there is no limit; RAVEN deliberately does not send bursts of traffic."

    NAMES = ("ratelimit-limit", "ratelimit-remaining", "ratelimit", "ratelimit-policy", "x-ratelimit-limit",
             "x-ratelimit-remaining", "x-rate-limit-limit", "retry-after")

    def run_summary(self, ctx: ScanContext, seen: Dict[str, bool]) -> List[Finding]:
        out = []
        for base_url, has_headers in seen.items():
            if has_headers:
                continue
            out.append(self.finding(
                title="No rate-limit headers seen",
                severity="info",
                endpoint="host",
                url=base_url,
                description="None of the responses from this host said anything about rate limits. If there is no limit, "
                "clients can call the API without restriction (brute force, scraping, cost explosion).",
                fix="Apply rate limits per client and per endpoint at the gateway and announce them with RateLimit / Retry-After headers.",
                evidence="No RateLimit-*, X-RateLimit-* or Retry-After header in any response.",
                confidence="tentative",
                cwe=770,
                owasp="API4:2023 Unrestricted Resource Consumption",
            ))
        return out
