"""URL list loader. One request per line:

    https://api.example.com/v1/users
    GET https://api.example.com/v1/users/42?expand=orders
    POST /v1/orders            (relative paths need --target)
    # lines starting with # are comments
"""

from __future__ import annotations

from typing import List
from urllib.parse import parse_qsl, urlparse

from raven_api.models import ALL_METHODS, ApiSpec, Endpoint, Param


def load(text: str) -> ApiSpec:
    endpoints: List[Endpoint] = []
    warnings: List[str] = []
    seen = set()
    for n, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        method = "GET"
        if parts[0].upper() in ALL_METHODS and len(parts) > 1:
            method, target = parts[0].upper(), parts[1]
        else:
            target = parts[0]
        parsed = urlparse(target)
        if parsed.scheme not in ("http", "https", "") or (not parsed.scheme and not target.startswith("/")):
            warnings.append(f"Line {n} ignored, not a URL: {line[:80]}")
            continue
        base = f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme else ""
        key = (method, base, parsed.path, parsed.query)
        if key in seen:
            continue
        seen.add(key)
        ep = Endpoint(method=method, path=parsed.path or "/", base_url=base, source="urls")
        for k, v in parse_qsl(parsed.query, keep_blank_values=True):
            ep.params.append(Param(name=k, location="query", example=v))
        endpoints.append(ep)
    title = "URL list" if len(endpoints) != 1 else "Single URL"
    return ApiSpec(title=title, source_type="urls", endpoints=endpoints, warnings=warnings)
