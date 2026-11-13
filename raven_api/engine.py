"""Runs the checks against every endpoint and collects the results."""

from __future__ import annotations

import time
import traceback
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from raven_api.checks import Check
from raven_api.checks.access import RateLimitSignals
from raven_api.checks.base import ScanContext, ScanOptions
from raven_api.checks.content import collect_secrets
from raven_api.client import BudgetExceeded, HttpClient, build_request
from raven_api.models import SEVERITY_RANK, ApiSpec, Finding


@dataclass
class EndpointOutcome:
    method: str
    path: str
    url: str
    state: str  # "scanned" | "skipped" | "error"
    status: Optional[int] = None
    elapsed_ms: float = 0.0
    note: str = ""
    findings: int = 0
    requests: int = 0


@dataclass
class ScanResult:
    spec: ApiSpec
    findings: List[Finding]
    endpoints: List[EndpointOutcome]
    checks: List[Check]
    started: float
    finished: float
    requests_sent: int
    options: ScanOptions
    auth_description: str
    warnings: List[str] = field(default_factory=list)
    stopped_reason: str = ""
    source: str = ""  # the file or URL that was scanned

    @property
    def duration_s(self) -> float:
        return round(self.finished - self.started, 1)

    def counts(self) -> Dict[str, int]:
        out = {s: 0 for s in SEVERITY_RANK}
        for f in self.findings:
            out[f.severity] = out.get(f.severity, 0) + 1
        return out


Event = Callable[..., None]


class Scanner:
    def __init__(
        self,
        client: HttpClient,
        spec: ApiSpec,
        checks: List[Check],
        options: ScanOptions,
        on_event: Optional[Event] = None,
    ):
        self.client = client
        self.spec = spec
        self.checks = checks
        self.options = options
        self.on_event = on_event or (lambda *a, **k: None)
        self.warnings: List[str] = list(spec.warnings)

    def _emit(self, kind: str, **data) -> None:
        try:
            self.on_event(kind, **data)
        except Exception:  # noqa: BLE001 - never let the UI break a scan
            pass

    def _safe_run(self, check: Check, fn: Callable[[], List[Finding]]) -> List[Finding]:
        try:
            return fn() or []
        except BudgetExceeded:
            raise
        except KeyboardInterrupt:
            raise
        except Exception as exc:  # noqa: BLE001 - one broken check must not stop the scan
            msg = f"{check.id} failed: {type(exc).__name__}: {exc}"
            if msg not in self.warnings:
                self.warnings.append(msg)
            self._emit("check_error", check=check.id, error=msg, trace=traceback.format_exc())
            return []

    def run(self) -> ScanResult:
        started = time.time()
        findings: List[Finding] = []
        outcomes: List[EndpointOutcome] = []
        stopped = ""
        ctx = ScanContext(self.client, self.spec, self.options)
        host_checks = [c for c in self.checks if c.scope == "host"]
        ep_checks = [c for c in self.checks if c.scope == "endpoint"]
        summary_checks = [c for c in self.checks if c.scope == "summary"]
        rate_limit_seen: Dict[str, bool] = {}
        hosts = sorted({e.base_url for e in self.spec.endpoints})

        try:
            for base in hosts:
                for check in host_checks:
                    self._emit("host_check", check=check.id, host=base)
                    ctx.results = []
                    findings += self._safe_run(check, lambda c=check, b=base: c.run_host(ctx, b))

            total = len(self.spec.endpoints)
            for index, ep in enumerate(self.spec.endpoints, start=1):
                ctx.results = []
                before_requests = self.client.count
                before_findings = len(findings)
                self._emit("endpoint_start", index=index, total=total, endpoint=ep)
                outcome = EndpointOutcome(ep.method, ep.path, ep.base_url + ep.path, "scanned")

                if not ep.is_safe and not self.options.unsafe:
                    outcome.state = "skipped"
                    outcome.note = f"{ep.method} not sent (it could change data). Add --unsafe on a test system to include it."
                    for check in ep_checks:
                        if check.works_without_baseline:
                            findings += self._safe_run(check, lambda c=check: c.run_endpoint(ctx, ep, None))
                else:
                    req = build_request(ep, self.options.values)
                    if self.client.auth.configured:  # credentials from the command line beat those in the file
                        configured = {k.lower() for k in self.client.auth.headers}
                        req.headers = {k: v for k, v in req.headers.items() if k.lower() not in configured}
                    baseline = ctx.send(req)
                    outcome.status = baseline.status or None
                    outcome.elapsed_ms = baseline.elapsed_ms
                    if not baseline.ok:
                        outcome.state = "error"
                        outcome.note = baseline.error or "No response"
                    else:
                        if baseline.status in (401, 403) and ep.auth_required is not False and not self.client.auth.configured:
                            outcome.note = "Answered 401/403: add credentials (see --auth-bearer) to test what is behind the login."
                        rl = any(h.lower() in RateLimitSignals.NAMES for h in baseline.headers)
                        rate_limit_seen[ep.base_url] = rate_limit_seen.get(ep.base_url, False) or rl
                        for check in ep_checks:
                            findings += self._safe_run(check, lambda c=check: c.run_endpoint(ctx, ep, baseline))

                collect_secrets(ctx.results, ctx.secrets)
                outcome.requests = self.client.count - before_requests
                outcome.findings = len(findings) - before_findings
                outcomes.append(outcome)
                self._emit("endpoint_done", index=index, total=total, endpoint=ep, outcome=outcome)

            for check in summary_checks:
                if isinstance(check, RateLimitSignals):
                    findings += self._safe_run(check, lambda c=check: c.run_summary(ctx, rate_limit_seen))
        except BudgetExceeded as exc:
            stopped = str(exc)
        except KeyboardInterrupt:
            stopped = "Scan interrupted by the user (Ctrl+C). The report contains the results collected so far."

        if stopped:
            self.warnings.append(stopped)
        _scrub_secrets(findings, ctx.secrets)
        return ScanResult(
            spec=self.spec,
            findings=_dedupe_and_sort(findings),
            endpoints=outcomes,
            checks=self.checks,
            started=started,
            finished=time.time(),
            requests_sent=self.client.count,
            options=self.options,
            auth_description=self.client.auth.describe(),
            warnings=self.warnings,
            stopped_reason=stopped,
        )


def _scrub_secrets(findings: List[Finding], secrets: set) -> None:
    """Secrets found in responses must never be copied into a report, by any finding."""
    from raven_api.checks.content import _mask

    for value in sorted(secrets, key=len, reverse=True):
        if len(value) < 4:
            continue
        masked = _mask(value)
        for f in findings:
            f.request = f.request.replace(value, masked)
            f.response = f.response.replace(value, masked)
            f.evidence = f.evidence.replace(value, masked)


def _dedupe_and_sort(findings: List[Finding]) -> List[Finding]:
    seen = set()
    unique = []
    for f in findings:
        if f.dedupe_key in seen:
            continue
        seen.add(f.dedupe_key)
        unique.append(f)
    return sorted(unique, key=lambda f: (SEVERITY_RANK.get(f.severity, 9), f.check_id, f.endpoint))
