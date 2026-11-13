"""HTTP client: sends requests, applies auth, keeps redacted evidence."""

from __future__ import annotations

import json
import time
import warnings
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, quote, urlencode, urlparse, urlunparse

import requests

from raven_api import __version__
from raven_api.auth import Auth
from raven_api.models import Endpoint, Exchange
from raven_api.samples import value_for_param

MAX_EVIDENCE_BODY = 3000


class BudgetExceeded(Exception):
    """The --max-requests limit was reached."""


@dataclass
class PlannedRequest:
    """A request RAVEN is about to send. Checks copy and mutate it."""

    method: str
    url: str  # without query string
    params: List[Tuple[str, str]] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    body: Any = None
    content_type: Optional[str] = None

    def copy(self) -> "PlannedRequest":
        return PlannedRequest(
            self.method, self.url, list(self.params), dict(self.headers), _deep_copy(self.body), self.content_type
        )

    def full_url(self) -> str:
        return self.url + ("?" + urlencode(self.params) if self.params else "")


def _deep_copy(value: Any) -> Any:
    if isinstance(value, (dict, list)):
        return json.loads(json.dumps(value))
    return value


def build_request(ep: Endpoint, values: Optional[Dict[str, Any]] = None) -> PlannedRequest:
    """Turn an endpoint description into a concrete, sendable request."""
    values = values or {}
    path = ep.path
    for p in ep.params_in("path"):
        path = path.replace("{" + p.name + "}", quote(str(value_for_param(p, values)), safe=""))
    req = PlannedRequest(method=ep.method, url=ep.base_url.rstrip("/") + path)
    req.headers.update(ep.headers)
    cookies = []
    for p in ep.params:
        if p.location == "path":
            continue
        has_value = p.required or p.example is not None or p.name in values or f"{p.location}.{p.name}" in values
        if not has_value:
            continue
        value = value_for_param(p, values)
        if p.location == "query":
            if isinstance(value, list):
                req.params.extend((p.name, _scalar(v)) for v in value)
            else:
                req.params.append((p.name, _scalar(value)))
        elif p.location == "header" and p.name.lower() not in ("authorization", "content-type", "accept"):
            req.headers[p.name] = _scalar(value)
        elif p.location == "cookie":
            cookies.append(f"{p.name}={_scalar(value)}")
    if cookies:
        req.headers["Cookie"] = "; ".join(filter(None, [req.headers.get("Cookie", "")] + cookies))
    if ep.method not in ("GET", "HEAD", "DELETE") or ep.body is not None:
        if ep.body is not None:
            req.body = _deep_copy(ep.body)
            req.content_type = ep.content_type or ("application/json" if isinstance(ep.body, (dict, list)) else "text/plain")
    return req


def _scalar(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (dict, list)):
        return json.dumps(value)
    return "" if value is None else str(value)


@dataclass
class Result:
    """What came back. `response` is None when the request failed (timeout, refused...)."""

    request: PlannedRequest
    response: Optional[requests.Response]
    exchange: Exchange
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.response is not None

    @property
    def status(self) -> int:
        return self.response.status_code if self.response is not None else 0

    @property
    def headers(self) -> Dict[str, str]:
        return dict(self.response.headers) if self.response is not None else {}

    def header(self, name: str) -> str:
        if self.response is None:
            return ""
        return self.response.headers.get(name, "")

    @property
    def text(self) -> str:
        if self.response is None:
            return ""
        try:
            return self.response.text
        except Exception:  # noqa: BLE001 - undecodable bodies
            return ""

    @property
    def content_type(self) -> str:
        return self.header("Content-Type").lower()

    @property
    def elapsed_ms(self) -> float:
        return self.exchange.elapsed_ms


class HttpClient:
    def __init__(
        self,
        auth: Optional[Auth] = None,
        timeout: float = 15.0,
        verify_tls: bool = True,
        proxy: Optional[str] = None,
        delay_ms: int = 0,
        extra_headers: Optional[Dict[str, str]] = None,
        max_requests: int = 5000,
        redact: bool = True,
        user_agent: Optional[str] = None,
    ):
        self.auth = auth or Auth()
        self.timeout = timeout
        self.verify_tls = verify_tls
        self.proxies = {"http": proxy, "https": proxy} if proxy else None
        self.delay = max(0, delay_ms) / 1000.0
        self.extra_headers = extra_headers or {}
        self.max_requests = max_requests
        self.redact = redact
        self.count = 0
        self.errors = 0
        self.session = requests.Session()
        self.session.headers.update(
            {"User-Agent": user_agent or f"RAVEN/{__version__} (+https://github.com/RoshanRajkumar1208/raven)", "Accept": "*/*"}
        )
        if not verify_tls:
            warnings.filterwarnings("ignore", message="Unverified HTTPS request")
        self._last = 0.0

    # ------------------------------------------------------------------ sending
    def send(
        self,
        req: PlannedRequest,
        with_auth: bool = True,
        allow_redirects: bool = False,
        timeout: Optional[float] = None,
        probe_headers: Optional[Dict[str, str]] = None,
    ) -> Result:
        """Send a request.

        with_auth=False removes every credential (auth headers, API keys, cookies).
        probe_headers are added last and never removed, so a check can send e.g. a
        forged token while all real credentials are stripped.
        """
        if self.count >= self.max_requests:
            raise BudgetExceeded(f"Stopped after {self.max_requests} requests (--max-requests).")
        if self.delay:
            wait = self._last + self.delay - time.time()
            if wait > 0:
                time.sleep(wait)

        headers = dict(self.extra_headers)
        params = list(req.params)
        if with_auth:
            self.auth.refresh_if_needed(self.session, self.timeout, self.verify_tls, self.proxies)
            for k, v in self.auth.headers.items():
                if k.lower() == "cookie" and "Cookie" in req.headers:
                    continue
                headers[k] = v
            params.extend(self.auth.query.items())
        headers.update(req.headers)  # request-specific headers win (checks rely on this)
        if not with_auth:
            secret = self.auth.secret_names
            headers = {k: v for k, v in headers.items() if k.lower() not in secret}
            params = [(k, v) for k, v in params if k.lower() not in secret]
        for k, v in (probe_headers or {}).items():
            headers = {hk: hv for hk, hv in headers.items() if hk.lower() != k.lower()}
            headers[k] = v

        kwargs: Dict[str, Any] = {}
        if req.body is not None:
            ctype = (req.content_type or "").lower()
            if "json" in ctype and not isinstance(req.body, (str, bytes)):
                kwargs["data"] = json.dumps(req.body)
            elif "multipart/form-data" in ctype and isinstance(req.body, dict):
                kwargs["files"] = {k: (None, _scalar(v)) for k, v in req.body.items()}
            elif "x-www-form-urlencoded" in ctype and isinstance(req.body, dict):
                kwargs["data"] = {k: _scalar(v) for k, v in req.body.items()}
            elif isinstance(req.body, (dict, list)):
                kwargs["data"] = json.dumps(req.body)
            else:
                kwargs["data"] = req.body if isinstance(req.body, (str, bytes)) else str(req.body)
            if "files" not in kwargs and not any(k.lower() == "content-type" for k in headers):
                headers["Content-Type"] = req.content_type or "application/json"
        if "files" in kwargs:
            headers = {k: v for k, v in headers.items() if k.lower() != "content-type"}

        secrets = self._secret_values(headers, params)
        self.count += 1
        self._last = time.time()
        prepared = None
        try:
            r = requests.Request(req.method, req.url, params=params, headers=headers, **kwargs)
            prepared = self.session.prepare_request(r)
            started = time.perf_counter()
            resp = self.session.send(
                prepared,
                timeout=timeout or self.timeout,
                verify=self.verify_tls,
                proxies=self.proxies,
                allow_redirects=allow_redirects,
            )
            elapsed = (time.perf_counter() - started) * 1000
        except requests.RequestException as exc:
            self.errors += 1
            message = _short_error(exc)
            ex = Exchange(req.method, self._scrub(self._mask_url(req.full_url()), secrets), None, self._scrub(self._raw_request(prepared, req, headers), secrets), "", 0.0, message)
            return Result(req, None, ex, message)

        ex = Exchange(
            method=req.method,
            url=self._scrub(self._mask_url(prepared.url or req.url), secrets),
            status=resp.status_code,
            request_raw=self._scrub(self._raw_request(prepared, req, headers), secrets),
            response_raw=self._scrub(self._raw_response(resp), secrets),
            elapsed_ms=round(elapsed, 1),
        )
        return Result(req, resp, ex)

    # ---------------------------------------------------------------- evidence
    def _mask_url(self, url: str) -> str:
        """Mask API keys and other secrets passed in the query string."""
        parsed = urlparse(url)
        if not self.redact or not parsed.query:
            return url
        names = self.auth.secret_names
        parts = []
        for k, v in parse_qsl(parsed.query, keep_blank_values=True):
            if k.lower() in names:
                parts.append(f"{quote(k)}={_mask_value(v)}")
            else:
                parts.append(urlencode([(k, v)]))
        return urlunparse(parsed._replace(query="&".join(parts)))

    def _secret_values(self, headers: Dict[str, str], params: List[Tuple[str, str]]) -> List[str]:
        """Credential values in this request. Servers sometimes echo them back (TRACE, debug pages)."""
        if not self.redact:
            return []
        names = self.auth.secret_names
        values = set()
        for k, v in list(headers.items()) + list(params):
            if k.lower() in names and v:
                values.add(str(v))
                for part in str(v).replace(";", " ").split():  # "Bearer xyz", "a=b; c=d"
                    if part.lower() in ("bearer", "basic", "token", "digest", "negotiate"):
                        continue  # scheme names are not secrets
                    values.add(part.split("=", 1)[-1])
        return sorted((v for v in values if len(v) >= 6), key=len, reverse=True)

    def _scrub(self, text: str, secrets: List[str]) -> str:
        for value in secrets:
            if value in text:
                text = text.replace(value, _mask_value(value))
        return text

    def _mask(self, name: str, value: str) -> str:
        if not self.redact or name.lower() not in self.auth.secret_names:
            return value
        return _mask_value(value)

    def _raw_request(self, prepared: Any, req: PlannedRequest, headers: Dict[str, str]) -> str:
        if prepared is not None:
            url = prepared.url or req.url
            hdrs = dict(prepared.headers)
            body = prepared.body
        else:
            url, hdrs, body = req.full_url(), headers, req.body
        parsed = urlparse(self._mask_url(url))
        target = urlunparse(parsed._replace(scheme="", netloc="")) or "/"
        lines = [f"{req.method} {target} HTTP/1.1", f"Host: {parsed.netloc}"]
        lines += [f"{k}: {self._mask(k, str(v))}" for k, v in hdrs.items() if k.lower() != "host"]
        text = "\n".join(lines)
        if body:
            if isinstance(body, bytes):
                body = body.decode("utf-8", "replace")
            text += "\n\n" + _clip(str(body))
        return text

    def _raw_response(self, resp: requests.Response) -> str:
        lines = [f"HTTP/1.1 {resp.status_code} {resp.reason or ''}".rstrip()]
        lines += [f"{k}: {self._mask(k, v) if k.lower() != 'set-cookie' else v}" for k, v in resp.headers.items()]
        try:
            body = resp.text
        except Exception:  # noqa: BLE001
            body = "<binary body>"
        return "\n".join(lines) + ("\n\n" + _clip(body) if body else "")


def _mask_value(value: str) -> str:
    """'Bearer abcdef123456' -> 'Bearer abcd…[redacted]'; other values keep 4 characters."""
    scheme, _, credential = value.partition(" ")
    if credential and scheme.lower() in ("bearer", "basic", "token", "digest"):
        return f"{scheme} {credential[:4]}…[redacted]" if len(credential) > 8 else f"{scheme} [redacted]"
    return value[:4] + "…[redacted]" if len(value) > 8 else "[redacted]"


def _clip(text: str, limit: int = MAX_EVIDENCE_BODY) -> str:
    return text if len(text) <= limit else text[:limit] + f"\n… [{len(text) - limit} more characters]"


def _short_error(exc: Exception) -> str:
    name = type(exc).__name__
    if isinstance(exc, requests.exceptions.SSLError):
        return "TLS/SSL error (certificate problem). Use --insecure to scan anyway."
    if isinstance(exc, requests.exceptions.ConnectTimeout):
        return "Connection timed out"
    if isinstance(exc, requests.exceptions.ReadTimeout):
        return "No response before the timeout"
    if isinstance(exc, requests.exceptions.ConnectionError):
        return "Could not connect (server down, wrong URL, or blocked)"
    return f"{name}: {str(exc)[:200]}"
