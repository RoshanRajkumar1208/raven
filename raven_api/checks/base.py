"""Building blocks every check uses."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from raven_api.models import Endpoint, Finding

if TYPE_CHECKING:  # pragma: no cover
    from raven_api.client import HttpClient, Result
    from raven_api.models import ApiSpec


@dataclass
class ScanOptions:
    values: Dict[str, Any] = field(default_factory=dict)
    unsafe: bool = False  # send POST/PUT/PATCH/DELETE requests
    slow_ms: int = 2000
    max_validation_cases: int = 4  # invalid-input requests per parameter
    cors_origin: str = "https://raven-cors-check.invalid"


@dataclass
class ScanContext:
    client: "HttpClient"
    spec: "ApiSpec"
    options: ScanOptions
    # all results collected for the current endpoint (baseline + check requests)
    results: List["Result"] = field(default_factory=list)
    # secret values found in responses; removed from every finding before reporting
    secrets: set = field(default_factory=set)

    def send(self, req: Any, **kwargs: Any) -> "Result":
        res = self.client.send(req, **kwargs)
        self.results.append(res)
        return res


class Check:
    """A single security check.

    kind:
      passive  - only reads the normal (baseline) response, sends nothing extra
      active   - sends a few extra, harmless requests (no data is created or changed
                 unless --unsafe is set and the endpoint itself is a write operation)
    """

    id = "RAV-000"
    name = "Unnamed check"
    kind = "passive"
    scope = "endpoint"  # "endpoint", "host" or "summary"
    works_without_baseline = False  # may run on write endpoints that were not sent (no --unsafe)
    summary = ""
    limits = ""

    def run_endpoint(self, ctx: ScanContext, ep: Endpoint, baseline: "Result") -> List[Finding]:
        return []

    def run_host(self, ctx: ScanContext, base_url: str) -> List[Finding]:
        return []

    # helper so every check builds findings the same way
    def finding(
        self,
        title: str,
        severity: str,
        endpoint: str,
        url: str,
        description: str,
        fix: str,
        evidence: str = "",
        result: Optional["Result"] = None,
        confidence: str = "firm",
        cwe: Optional[int] = None,
        owasp: str = "",
        references: Optional[List[str]] = None,
    ) -> Finding:
        return Finding(
            check_id=self.id,
            title=title,
            severity=severity,
            endpoint=endpoint,
            url=url,
            description=description,
            fix=fix,
            evidence=evidence,
            confidence=confidence,
            cwe=cwe,
            owasp=owasp,
            references=references or [],
            request=result.exchange.request_raw if result is not None else "",
            response=result.exchange.response_raw if result is not None else "",
        )
