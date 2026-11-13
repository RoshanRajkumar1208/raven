"""HTTP method hygiene: TRACE and methods the API advertises but does not document."""

from __future__ import annotations

from typing import List, Set

from raven_api.checks.base import Check, ScanContext
from raven_api.models import Endpoint, Finding


class HttpMethods(Check):
    works_without_baseline = True
    id = "RAV-M01"
    name = "HTTP methods"
    kind = "active"
    summary = "Asks each path which methods it allows (OPTIONS) and compares that with the documented ones; checks that TRACE is disabled."
    limits = "Relies on the Allow header; servers that do not send it cannot be compared. Undocumented methods are listed, never called."

    def __init__(self) -> None:
        self._done: Set[str] = set()
        self._trace_done: Set[str] = set()

    def run_endpoint(self, ctx: ScanContext, ep: Endpoint, baseline) -> List[Finding]:
        path_key = ep.base_url + ep.path
        if path_key in self._done:
            return []
        self._done.add(path_key)
        documented = {e.method for e in ctx.spec.endpoints if e.path == ep.path and e.base_url == ep.base_url}
        documented |= {"OPTIONS", "HEAD"}
        if "GET" not in documented:
            documented.discard("HEAD")

        from raven_api.client import build_request

        out: List[Finding] = []
        req = build_request(ep, ctx.options.values)
        req.method, req.body, req.content_type = "OPTIONS", None, None
        res = ctx.send(req)
        allow = res.header("Allow") or res.header("Access-Control-Allow-Methods")
        if res.ok and allow:
            advertised = {m.strip().upper() for m in allow.split(",") if m.strip()}
            extra = sorted(advertised - documented - {"TRACE"})
            if extra:
                out.append(self.finding(
                    title="Undocumented HTTP methods advertised",
                    severity="info",
                    endpoint=ep.path,
                    url=res.exchange.url,
                    description=f"The server says it accepts {', '.join(extra)} on this path, but the API description does not document them. "
                    "Undocumented operations are often untested and unprotected.",
                    fix="Disable methods you do not use, or document and secure them like the rest of the API.",
                    evidence=f"Documented: {', '.join(sorted(documented))}\nAllow: {allow}",
                    result=res,
                    cwe=749,
                    owasp="API9:2023 Improper Inventory Management",
                ))

        if ep.base_url in self._trace_done:  # TRACE is a server setting: test it once per host
            return out
        self._trace_done.add(ep.base_url)
        trace = req.copy()
        trace.method = "TRACE"
        t = ctx.send(trace)
        if t.ok and t.status == 200 and "TRACE" in t.text[:200].upper():
            out.append(self.finding(
                title="TRACE method enabled",
                severity="low",
                endpoint="host",
                url=t.exchange.url,
                description="The server answers TRACE requests by echoing the request back, including its headers. "
                "It serves no purpose in an API and can expose header values to scripts.",
                fix="Disable TRACE in the web server or gateway (e.g. TraceEnable off in Apache).",
                evidence=f"TRACE -> {t.status}",
                result=t,
                cwe=693,
                owasp="API8:2023 Security Misconfiguration",
            ))
        return out

