"""Data structures shared by every part of RAVEN."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

SAFE_METHODS = ("GET", "HEAD", "OPTIONS")
ALL_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")

SEVERITIES = ("critical", "high", "medium", "low", "info")
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}  # lower = worse


@dataclass
class Param:
    """One input of an endpoint: a path, query, header or cookie parameter."""

    name: str
    location: str  # "path" | "query" | "header" | "cookie"
    required: bool = False
    schema: Dict[str, Any] = field(default_factory=dict)
    example: Any = None

    @property
    def type(self) -> str:
        t = self.schema.get("type")
        if isinstance(t, list):  # OpenAPI 3.1 allows ["string", "null"]
            t = next((x for x in t if x != "null"), "string")
        return t or "string"


@dataclass
class Endpoint:
    """One operation of the API, e.g. GET /users/{id}."""

    method: str
    path: str  # path template, parameters written as {name}
    base_url: str = ""
    params: List[Param] = field(default_factory=list)
    body: Any = None  # example request body (dict, list or str)
    body_schema: Optional[Dict[str, Any]] = None
    content_type: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)  # fixed headers (Postman/HAR)
    auth_required: Optional[bool] = None  # None = the description does not say
    expected_status: List[str] = field(default_factory=list)
    summary: str = ""
    source: str = ""

    def __post_init__(self) -> None:
        self.method = self.method.upper()
        if not self.path.startswith("/"):
            self.path = "/" + self.path

    @property
    def key(self) -> str:
        return f"{self.method} {self.path}"

    @property
    def is_safe(self) -> bool:
        return self.method in SAFE_METHODS

    def params_in(self, location: str) -> List[Param]:
        return [p for p in self.params if p.location == location]


@dataclass
class ApiSpec:
    """Everything a loader extracted from an API description."""

    title: str
    source_type: str  # "openapi3", "swagger2", "postman", "blueprint", "har", "urls"
    endpoints: List[Endpoint]
    base_url: str = ""
    version: str = ""
    warnings: List[str] = field(default_factory=list)


@dataclass
class Exchange:
    """A request RAVEN sent and the response it got, kept as evidence."""

    method: str
    url: str
    status: Optional[int]
    request_raw: str
    response_raw: str
    elapsed_ms: float = 0.0
    error: Optional[str] = None


@dataclass
class Finding:
    check_id: str
    title: str
    severity: str
    endpoint: str  # "GET /users/{id}" or "host" for host-wide findings
    url: str
    description: str
    fix: str
    evidence: str = ""
    confidence: str = "firm"  # "firm" | "tentative"
    cwe: Optional[int] = None
    owasp: str = ""
    references: List[str] = field(default_factory=list)
    request: str = ""
    response: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @property
    def dedupe_key(self) -> tuple:
        return (self.check_id, self.title, self.endpoint, self.evidence[:120])
