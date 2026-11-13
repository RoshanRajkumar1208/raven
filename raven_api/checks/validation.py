"""Contract checks: does the API enforce what its own description promises?"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Tuple

from raven_api.checks.base import Check, ScanContext
from raven_api.client import PlannedRequest
from raven_api.models import Endpoint, Finding, Param

OWASP_VALIDATION = "API8:2023 Security Misconfiguration"


def invalid_values(schema: Dict[str, Any], limit: int) -> List[Tuple[Any, str]]:
    """Values that break the declared schema, each with a plain-English reason.

    Only harmless, ordinary values are used (wrong type, out of range, too long).
    """
    t = schema.get("type")
    if isinstance(t, list):
        t = next((x for x in t if x != "null"), None)
    cases: List[Tuple[Any, str]] = []
    if schema.get("enum"):
        cases.append(("raven-not-an-allowed-value", "value outside the allowed list (enum)"))
    if t in ("integer", "number"):
        cases.append(("raven-text", f"text where a {t} is required"))
        if isinstance(schema.get("maximum"), (int, float)):
            cases.append((schema["maximum"] + 1, f"number above the maximum ({schema['maximum']})"))
        if isinstance(schema.get("minimum"), (int, float)):
            cases.append((schema["minimum"] - 1, f"number below the minimum ({schema['minimum']})"))
        if t == "integer":
            cases.append(("1.5", "decimal where an integer is required"))
    elif t == "boolean":
        cases.append(("raven-maybe", "text where true/false is required"))
    elif t == "string" or t is None:
        if isinstance(schema.get("maxLength"), int):
            cases.append(("r" * (schema["maxLength"] + 1), f"text longer than maxLength ({schema['maxLength']})"))
        if isinstance(schema.get("minLength"), int) and schema["minLength"] > 0:
            cases.append(("", f"text shorter than minLength ({schema['minLength']})"))
        fmt = schema.get("format")
        if fmt in ("email", "uuid", "date", "date-time", "uri", "ipv4"):
            cases.append((f"raven-not-a-{fmt}", f"value that is not a valid {fmt}"))
    elif t == "array":
        cases.append(("raven-not-a-list", "text where a list is required"))
    return cases[:limit]


class InputValidation(Check):
    id = "RAV-V01"
    name = "Input validation (spec contract)"
    kind = "active"
    summary = "For every parameter and JSON body field with a declared type or limit, sends one value that breaks it and expects a 4xx error."
    limits = "Only tests what the description declares (types, enums, min/max, lengths, formats, required). Needs an OpenAPI/Swagger input to be useful; " \
             "Postman, HAR and URL lists carry no schemas."

    def run_endpoint(self, ctx: ScanContext, ep: Endpoint, baseline) -> List[Finding]:
        if baseline is None or not baseline.ok or baseline.status >= 500:
            return []
        limit = ctx.options.max_validation_cases
        out: List[Finding] = []
        server_errors: List[str] = []
        accepted: List[str] = []
        first_error = first_accept = None

        def judge(res, label: str) -> None:
            nonlocal first_error, first_accept
            if not res.ok:
                return
            if res.status >= 500:
                server_errors.append(f"{label} -> {res.status}")
                first_error = first_error or res
            elif 200 <= res.status < 300:
                accepted.append(f"{label} -> {res.status}")
                first_accept = first_accept or res

        # 1. parameters
        for p in ep.params:
            if p.location not in ("query", "path", "header"):
                continue
            for value, reason in invalid_values(p.schema, limit):
                res = ctx.send(self._with_param(baseline.request, ep, p, value))
                judge(res, f"{p.location} '{p.name}': {reason}")
            if p.location == "query" and p.required:
                req = baseline.request.copy()
                req.params = [(k, v) for k, v in req.params if k != p.name]
                judge(ctx.send(req), f"required query '{p.name}' left out")

        # 2. JSON body fields
        if isinstance(baseline.request.body, dict) and isinstance(ep.body_schema, dict):
            props = ep.body_schema.get("properties") or {}
            for field_name, field_schema in list(props.items())[:25]:
                if not isinstance(field_schema, dict):
                    continue
                for value, reason in invalid_values(field_schema, min(limit, 2)):
                    req = baseline.request.copy()
                    req.body[field_name] = value
                    judge(ctx.send(req), f"body field '{field_name}': {reason}")
            for field_name in (ep.body_schema.get("required") or [])[:10]:
                if field_name in baseline.request.body:
                    req = baseline.request.copy()
                    req.body.pop(field_name, None)
                    judge(ctx.send(req), f"required body field '{field_name}' left out")

            # 3. Content-Type enforcement for JSON bodies
            if "json" in (baseline.request.content_type or ""):
                req = baseline.request.copy()
                req.body = json.dumps(baseline.request.body)
                req.content_type = "text/plain"
                req.headers = {k: v for k, v in req.headers.items() if k.lower() != "content-type"}
                req.headers["Content-Type"] = "text/plain"
                res = ctx.send(req)
                if res.ok and 200 <= res.status < 300:
                    out.append(self.finding(
                        title="Request Content-Type not enforced",
                        severity="low",
                        endpoint=ep.key,
                        url=res.exchange.url,
                        description="The endpoint accepted a JSON body sent as text/plain. Browsers send text/plain cross-site without a CORS preflight, "
                        "so if the API uses cookies this can make cross-site request forgery easier.",
                        fix="Reject bodies whose Content-Type is not application/json with 415 Unsupported Media Type.",
                        evidence=f"Content-Type: text/plain -> {res.status}",
                        result=res,
                        cwe=352,
                        owasp=OWASP_VALIDATION,
                    ))

        if server_errors:
            out.append(self.finding(
                title="Server error on invalid input",
                severity="medium",
                endpoint=ep.key,
                url=first_error.exchange.url,
                description="Input that breaks the documented rules made the server fail with a 5xx error instead of answering 400. "
                "Unhandled errors often leak internal details and point to missing validation.",
                fix="Validate every input against the schema before using it (most frameworks can do this from the OpenAPI file) and return 400 with a short message.",
                evidence="\n".join("• " + x for x in server_errors[:12]),
                result=first_error,
                cwe=20,
                owasp=OWASP_VALIDATION,
            ))
        if accepted:
            out.append(self.finding(
                title="Invalid input accepted",
                severity="low",
                endpoint=ep.key,
                url=first_accept.exchange.url,
                description="The endpoint answered with success to input that breaks its own documented rules. "
                "The description and the implementation disagree, and the code behind it may receive data it does not expect.",
                fix="Enforce the documented types, limits and required fields on the server, or correct the description.",
                evidence="\n".join("• " + x for x in accepted[:12]),
                result=first_accept,
                confidence="tentative",
                cwe=20,
                owasp=OWASP_VALIDATION,
            ))
        return out

    @staticmethod
    def _with_param(base: PlannedRequest, ep: Endpoint, p: Param, value: Any) -> PlannedRequest:
        from urllib.parse import quote

        req = base.copy()
        if p.location == "query":
            req.params = [(k, v) for k, v in req.params if k != p.name] + [(p.name, str(value))]
        elif p.location == "header":
            req.headers[p.name] = str(value)
        elif p.location == "path":
            # rebuild the URL with this one path value changed
            from raven_api.samples import value_for_param

            path = ep.path
            for other in ep.params_in("path"):
                v = value if other.name == p.name else value_for_param(other, {})
                path = path.replace("{" + other.name + "}", quote(str(v), safe=""))
            req.url = ep.base_url.rstrip("/") + path
        return req


class ResponseContract(Check):
    id = "RAV-V02"
    name = "Response contract"
    kind = "passive"
    summary = "Compares the normal response with the description: undocumented status codes, and missing or misleading Content-Type."
    limits = "Does not validate response bodies against their schemas."

    def run_endpoint(self, ctx: ScanContext, ep: Endpoint, baseline) -> List[Finding]:
        if baseline is None or not baseline.ok:
            return []
        out: List[Finding] = []
        documented = [s.upper() for s in ep.expected_status]
        status = str(baseline.status)
        if documented and status not in documented and "DEFAULT" not in documented and f"{status[0]}XX" not in documented:
            out.append(self.finding(
                title="Undocumented response status",
                severity="info",
                endpoint=ep.key,
                url=baseline.exchange.url,
                description=f"The endpoint answered {status}, which the description does not list. Clients and tests built from the description will not expect it.",
                fix="Add the status code to the description, or fix the endpoint if the status is wrong.",
                evidence=f"Documented: {', '.join(ep.expected_status)}\nReceived: {status}",
                result=baseline,
                owasp="API9:2023 Improper Inventory Management",
            ))
        body = baseline.text.strip()
        ctype = baseline.content_type
        if body and not ctype:
            out.append(self.finding(
                title="Response has no Content-Type",
                severity="low",
                endpoint=ep.key,
                url=baseline.exchange.url,
                description="The response has a body but no Content-Type header, so clients and browsers have to guess its type.",
                fix="Always send Content-Type (e.g. application/json; charset=utf-8).",
                evidence=f"Body starts with: {body[:80]}",
                result=baseline,
                cwe=16,
            ))
        elif body[:1] in ("{", "[") and "text/html" in ctype:
            try:
                json.loads(body)
                out.append(self.finding(
                    title="JSON served as text/html",
                    severity="low",
                    endpoint=ep.key,
                    url=baseline.exchange.url,
                    description="The body is JSON but is labelled text/html. A browser opening it directly will treat it as a web page, "
                    "so any user-supplied text inside it could be interpreted as HTML.",
                    fix="Send JSON with Content-Type: application/json.",
                    evidence=f"Content-Type: {baseline.header('Content-Type')}",
                    result=baseline,
                    cwe=16,
                ))
            except ValueError:
                pass
        return out
