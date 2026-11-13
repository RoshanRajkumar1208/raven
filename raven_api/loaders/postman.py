"""Postman collection (v2.0 / v2.1) loader, with environment-variable support."""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlparse

from raven_api.models import ApiSpec, Endpoint, Param

_VAR = re.compile(r"{{\s*([^{}\s]+)\s*}}")


def read_environment(path: str) -> Dict[str, str]:
    """Read a Postman environment export ({"values": [{"key", "value", "enabled"}]})."""
    with open(path, "r", encoding="utf-8-sig") as fh:
        data = json.load(fh)
    out: Dict[str, str] = {}
    for item in data.get("values") or []:
        if isinstance(item, dict) and item.get("enabled", True) and "key" in item:
            out[str(item["key"])] = str(item.get("value", ""))
    return out


class _Vars:
    def __init__(self, values: Dict[str, str]):
        self.values = values
        self.unresolved: set = set()

    def sub(self, text: Any) -> Any:
        if not isinstance(text, str):
            return text
        for _ in range(5):  # variables may reference other variables
            new = _VAR.sub(lambda m: self.values.get(m.group(1), m.group(0)), text)
            if new == text:
                break
            text = new
        for name in _VAR.findall(text):
            self.unresolved.add(name)
        return text

    def sub_deep(self, value: Any) -> Any:
        if isinstance(value, dict):
            return {self.sub(k): self.sub_deep(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self.sub_deep(v) for v in value]
        return self.sub(value)


def load(data: Dict[str, Any], env: Optional[Dict[str, str]] = None) -> ApiSpec:
    info = data.get("info") or {}
    collection_vars = {
        str(v["key"]): str(v.get("value", ""))
        for v in data.get("variable") or []
        if isinstance(v, dict) and "key" in v and not v.get("disabled")
    }
    collection_vars.update(env or {})  # environment / --var values win
    variables = _Vars(collection_vars)
    warnings: List[str] = []
    endpoints: List[Endpoint] = []
    seen: set = set()

    def walk(items: List[Any], inherited_auth: Optional[Dict[str, Any]]) -> None:
        for item in items or []:
            if not isinstance(item, dict):
                continue
            auth = item.get("auth", inherited_auth)
            if "item" in item:
                walk(item["item"], auth)
            if "request" in item:
                ep = _to_endpoint(item, auth, variables, warnings)
                if ep and ep.key + ep.base_url not in seen:
                    seen.add(ep.key + ep.base_url)
                    endpoints.append(ep)

    walk(data.get("item") or [], data.get("auth"))
    if variables.unresolved:
        warnings.append(
            "Postman variables without a value (pass them with --var name=value or --postman-env): "
            + ", ".join(sorted(variables.unresolved))
        )
    return ApiSpec(
        title=str(info.get("name") or "Postman collection"),
        source_type="postman",
        endpoints=endpoints,
        warnings=warnings,
    )


def _to_endpoint(item: Dict[str, Any], auth: Optional[Dict[str, Any]], v: _Vars, warnings: List[str]) -> Optional[Endpoint]:
    req = item["request"]
    if isinstance(req, str):
        req = {"method": "GET", "url": req}
    method = str(req.get("method") or "GET").upper()
    url_obj = req.get("url")
    raw, path_vars, query = _url_parts(url_obj)
    raw = v.sub(raw)
    if not raw:
        return None
    if not raw.lower().startswith(("http://", "https://")):
        if raw.startswith("{{") or "://" not in raw:
            # Base URL variable could not be resolved; keep the path so --target can fill in the host.
            path_only = "/" + raw.split("}}", 1)[-1].lstrip("/") if "}}" in raw else "/" + raw.lstrip("/")
            raw = path_only
    parsed = urlparse(raw)
    base = f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme else ""
    path = parsed.path or "/"
    # Postman writes path variables as :name — convert to {name}
    path = re.sub(r"/:([A-Za-z0-9_\-]+)", r"/{\1}", path)

    ep = Endpoint(method=method, path=path, base_url=base, source="postman", summary=str(item.get("name") or ""))
    for name in re.findall(r"{([^}/]+)}", path):
        ep.params.append(Param(name=name, location="path", required=True, example=v.sub(path_vars.get(name)) or None))
    query_pairs = query if query else parse_qsl(parsed.query, keep_blank_values=True)
    for key, value in query_pairs:
        if key:
            ep.params.append(Param(name=key, location="query", example=v.sub(value)))

    for h in req.get("header") or []:
        if isinstance(h, dict) and h.get("key") and not h.get("disabled"):
            ep.headers[v.sub(str(h["key"]))] = v.sub(str(h.get("value", "")))

    _apply_auth(ep, auth, v)
    _apply_body(ep, req.get("body"), v)
    if ep.content_type and not any(k.lower() == "content-type" for k in ep.headers):
        ep.headers["Content-Type"] = ep.content_type
    return ep


def _url_parts(url_obj: Any) -> Tuple[str, Dict[str, Any], List[Tuple[str, str]]]:
    if isinstance(url_obj, str):
        return url_obj, {}, []
    if not isinstance(url_obj, dict):
        return "", {}, []
    path_vars = {
        str(x["key"]): x.get("value")
        for x in url_obj.get("variable") or []
        if isinstance(x, dict) and "key" in x
    }
    query = [
        (str(q.get("key") or ""), str(q.get("value") or ""))
        for q in url_obj.get("query") or []
        if isinstance(q, dict) and not q.get("disabled")
    ]
    raw = url_obj.get("raw")
    if not raw:
        host = url_obj.get("host") or []
        host = ".".join(host) if isinstance(host, list) else str(host)
        path = url_obj.get("path") or []
        path = "/".join(path) if isinstance(path, list) else str(path)
        protocol = url_obj.get("protocol")
        raw = (f"{protocol}://" if protocol else "") + host + ("/" + path if path else "")
    raw = str(raw).split("?", 1)[0] if query else str(raw)
    return raw, path_vars, query


def _apply_auth(ep: Endpoint, auth: Optional[Dict[str, Any]], v: _Vars) -> None:
    if not isinstance(auth, dict) or auth.get("type") in (None, "noauth"):
        if any(k.lower() in ("authorization", "x-api-key") for k in ep.headers):
            ep.auth_required = True
        return
    kind = auth.get("type")
    entries = auth.get(kind) or []
    if isinstance(entries, dict):  # v2.0 format
        values = entries
    else:
        values = {str(e.get("key")): e.get("value") for e in entries if isinstance(e, dict)}
    ep.auth_required = True
    if kind == "bearer" and values.get("token"):
        ep.headers.setdefault("Authorization", "Bearer " + str(v.sub(values["token"])))
    elif kind == "apikey" and values.get("key"):
        if values.get("in", "header") == "header":
            ep.headers.setdefault(str(v.sub(values["key"])), str(v.sub(values.get("value", ""))))
        else:
            ep.params.append(Param(name=str(v.sub(values["key"])), location="query", example=v.sub(values.get("value", ""))))
    elif kind == "basic" and values.get("username") is not None:
        import base64

        pair = f"{v.sub(values.get('username', ''))}:{v.sub(values.get('password', ''))}"
        ep.headers.setdefault("Authorization", "Basic " + base64.b64encode(pair.encode()).decode())


def _apply_body(ep: Endpoint, body: Any, v: _Vars) -> None:
    if not isinstance(body, dict) or body.get("disabled"):
        return
    mode = body.get("mode")
    if mode == "raw":
        raw = v.sub(body.get("raw") or "")
        language = ((body.get("options") or {}).get("raw") or {}).get("language", "")
        try:
            ep.body = json.loads(raw)
            ep.content_type = "application/json"
        except ValueError:
            ep.body = raw
            ep.content_type = {"xml": "application/xml", "json": "application/json"}.get(language, "text/plain")
    elif mode in ("urlencoded", "formdata"):
        fields = {}
        for f in body.get(mode) or []:
            if isinstance(f, dict) and f.get("key") and not f.get("disabled") and f.get("type", "text") == "text":
                fields[v.sub(str(f["key"]))] = v.sub(str(f.get("value", "")))
        ep.body = fields
        ep.content_type = "application/x-www-form-urlencoded" if mode == "urlencoded" else "multipart/form-data"
    elif mode == "graphql":
        gql = body.get("graphql") or {}
        variables = gql.get("variables") or "{}"
        try:
            variables = json.loads(v.sub(variables)) if isinstance(variables, str) else variables
        except ValueError:
            variables = {}
        ep.body = {"query": v.sub(gql.get("query", "")), "variables": variables}
        ep.content_type = "application/json"
