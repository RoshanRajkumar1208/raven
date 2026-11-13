"""CORS policy review."""

from __future__ import annotations

from typing import List

from raven_api.checks.base import Check, ScanContext
from raven_api.models import Endpoint, Finding


class CorsPolicy(Check):
    works_without_baseline = True
    id = "RAV-C01"
    name = "CORS policy"
    kind = "active"
    summary = "Sends the request with an Origin the API should not trust and reads the CORS headers it returns."
    limits = "Uses one untrusted test origin. Allow-lists that only check part of the origin name are not explored."

    def run_endpoint(self, ctx: ScanContext, ep: Endpoint, baseline) -> List[Finding]:
        origin = ctx.options.cors_origin
        if baseline is not None and baseline.ok:
            req = baseline.request.copy()
            req.headers["Origin"] = origin
        else:
            # Write endpoint not sent (no --unsafe): ask with a CORS preflight instead, which changes nothing.
            from raven_api.client import build_request

            req = build_request(ep, ctx.options.values)
            req.method, req.body, req.content_type = "OPTIONS", None, None
            req.headers.update({"Origin": origin, "Access-Control-Request-Method": ep.method})
        res = ctx.send(req)
        if not res.ok:
            return []
        acao = res.header("Access-Control-Allow-Origin").strip()
        creds = res.header("Access-Control-Allow-Credentials").strip().lower() == "true"
        evidence = f"Origin sent: {origin}\nAccess-Control-Allow-Origin: {acao or '(none)'}\nAccess-Control-Allow-Credentials: {res.header('Access-Control-Allow-Credentials') or '(none)'}"
        common = dict(endpoint=ep.key, url=res.exchange.url, evidence=evidence, result=res, cwe=942,
                      owasp="API8:2023 Security Misconfiguration",
                      references=["https://developer.mozilla.org/docs/Web/HTTP/CORS"])
        if acao == origin and creds:
            return [self.finding(
                title="CORS trusts any origin, with credentials",
                severity="high",
                description="The API copies whatever Origin it receives into Access-Control-Allow-Origin and allows credentials. "
                "Any website a logged-in user visits can call this API as that user and read the answers.",
                fix="Compare the Origin against a fixed allow-list of your own front-end domains. Never echo it back unchecked.",
                **common)]
        if acao == origin:
            return [self.finding(
                title="CORS trusts any origin",
                severity="medium",
                description="The API copies whatever Origin it receives into Access-Control-Allow-Origin, so any website can read its responses from a browser.",
                fix="Use an explicit allow-list of trusted origins. If the API is truly public and uses no cookies, a fixed '*' is clearer.",
                **common)]
        if acao == "*" and creds:
            return [self.finding(
                title="CORS wildcard combined with credentials",
                severity="low",
                description="Access-Control-Allow-Origin: * together with Allow-Credentials: true is an invalid combination. "
                "Browsers refuse it, but it shows the policy was not designed deliberately.",
                fix="Decide whether the API is public (use '*' and no credentials) or private (use an allow-list).",
                **common)]
        if acao.lower() == "null":
            return [self.finding(
                title="CORS allows the 'null' origin",
                severity="medium",
                description="Allowing the origin 'null' lets sandboxed pages and local files read responses.",
                fix="Remove 'null' from the allowed origins.",
                **common)]
        return []
