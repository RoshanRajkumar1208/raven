"""HAR loader: replay API traffic recorded in a browser, Burp Suite or OWASP ZAP."""

from __future__ import annotations

import json
from typing import Any, Dict, List
from urllib.parse import urlparse

from raven_api.models import ApiSpec, Endpoint, Param

_STATIC = (".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".map", ".webp", ".mp4")
_SKIP_HEADERS = {
    "host", "content-length", "connection", "accept-encoding", "user-agent", "referer", "origin",
    "upgrade-insecure-requests", "te", "priority", "pragma", "cache-control", "if-none-match", "if-modified-since",
}
_STATIC_MIME = ("text/css", "javascript", "image/", "font/", "video/", "audio/")


def load(data: Dict[str, Any]) -> ApiSpec:
    entries = ((data.get("log") or {}).get("entries")) or []
    endpoints: List[Endpoint] = []
    seen = set()
    skipped = 0
    for entry in entries:
        req = (entry or {}).get("request") or {}
        url = req.get("url") or ""
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            continue
        mime = str((((entry.get("response") or {}).get("content") or {}).get("mimeType")) or "")
        if parsed.path.lower().endswith(_STATIC) or any(s in mime for s in _STATIC_MIME) or "text/html" in mime:
            skipped += 1
            continue
        method = str(req.get("method") or "GET").upper()
        base = f"{parsed.scheme}://{parsed.netloc}"
        key = (method, base, parsed.path)
        if key in seen:
            continue
        seen.add(key)
        ep = Endpoint(method=method, path=parsed.path or "/", base_url=base, source="har")
        for q in req.get("queryString") or []:
            if isinstance(q, dict) and q.get("name"):
                ep.params.append(Param(name=q["name"], location="query", example=q.get("value", "")))
        for h in req.get("headers") or []:
            name = str((h or {}).get("name") or "")
            if not name or name.startswith(":") or name.lower() in _SKIP_HEADERS or name.lower().startswith("sec-"):
                continue
            ep.headers[name] = str(h.get("value", ""))
        post = req.get("postData") or {}
        if post:
            ep.content_type = post.get("mimeType") or None
            text = post.get("text")
            if text:
                try:
                    ep.body = json.loads(text)
                except ValueError:
                    ep.body = text
            elif post.get("params"):
                ep.body = {p.get("name"): p.get("value", "") for p in post["params"] if isinstance(p, dict)}
        if any(k.lower() in ("authorization", "cookie", "x-api-key") for k in ep.headers):
            ep.auth_required = True
        endpoints.append(ep)

    warnings = [f"Skipped {skipped} static files and web pages in the HAR (images, scripts, HTML)."] if skipped else []
    title = "HAR capture"
    creator = (data.get("log") or {}).get("creator") or {}
    if creator.get("name"):
        title = f"HAR capture ({creator['name']})"
    return ApiSpec(title=title, source_type="har", endpoints=endpoints, warnings=warnings)
