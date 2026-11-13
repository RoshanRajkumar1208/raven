"""OpenAPI 3.x and Swagger 2.0 loader."""

from __future__ import annotations

import copy
from typing import Any, Dict, List, Optional

from raven_api.models import ApiSpec, Endpoint, Param
from raven_api.samples import example_from_schema

METHODS = ("get", "post", "put", "patch", "delete", "head", "options")
_BODY_PREFERENCE = (
    "application/json",
    "+json",
    "application/x-www-form-urlencoded",
    "multipart/form-data",
    "text/plain",
    "application/xml",
    "text/xml",
)


class RefResolver:
    """Resolves local "$ref": "#/components/..." pointers, safely handling cycles."""

    def __init__(self, root: Dict[str, Any], warnings: List[str]):
        self.root = root
        self.warnings = warnings

    def lookup(self, ref: str) -> Any:
        if not ref.startswith("#/"):
            msg = f"External $ref not followed: {ref}"
            if msg not in self.warnings:
                self.warnings.append(msg)
            return {}
        node: Any = self.root
        for part in ref[2:].split("/"):
            part = part.replace("~1", "/").replace("~0", "~")
            if not isinstance(node, dict) or part not in node:
                self.warnings.append(f"Broken $ref: {ref}")
                return {}
            node = node[part]
        return node

    def resolve(self, node: Any, seen: Optional[frozenset] = None, depth: int = 0) -> Any:
        seen = seen or frozenset()
        if depth > 40:
            return {}
        if isinstance(node, dict):
            if "$ref" in node and isinstance(node["$ref"], str):
                ref = node["$ref"]
                if ref in seen:
                    return {}  # recursive schema: stop here
                target = self.resolve(self.lookup(ref), seen | {ref}, depth + 1)
                extra = {k: v for k, v in node.items() if k != "$ref"}
                if extra and isinstance(target, dict):
                    target = {**target, **self.resolve(extra, seen, depth + 1)}
                return target
            return {k: self.resolve(v, seen, depth + 1) for k, v in node.items()}
        if isinstance(node, list):
            return [self.resolve(v, seen, depth + 1) for v in node]
        return node


def load(data: Dict[str, Any], origin: Optional[str] = None) -> ApiSpec:
    warnings: List[str] = []
    resolver = RefResolver(data, warnings)
    is_v2 = "swagger" in data
    info = data.get("info") or {}
    title = str(info.get("title") or "Untitled API")

    base_url = _swagger_base(data) if is_v2 else _openapi3_base(data)
    global_security = data.get("security")
    global_consumes = data.get("consumes") or []

    endpoints: List[Endpoint] = []
    for raw_path, path_item in (data.get("paths") or {}).items():
        if not isinstance(path_item, dict):
            continue
        path_item = resolver.resolve(path_item)
        shared_params = path_item.get("parameters") or []
        path_servers = path_item.get("servers")
        for method in METHODS:
            op = path_item.get(method)
            if not isinstance(op, dict):
                continue
            params_raw = _merge_params(shared_params, op.get("parameters") or [])
            ep = Endpoint(method=method, path=raw_path, source="swagger2" if is_v2 else "openapi3")
            ep.summary = str(op.get("summary") or op.get("operationId") or "")
            op_servers = op.get("servers") or path_servers
            if not is_v2 and op_servers:
                ep.base_url = _server_url(op_servers[0])

            form_fields: Dict[str, Any] = {}
            for p in params_raw:
                if not isinstance(p, dict) or "name" not in p:
                    continue
                loc = p.get("in", "query")
                if is_v2 and loc == "body":
                    schema = p.get("schema") or {}
                    ep.body_schema = schema
                    ep.body = example_from_schema(schema)
                    ep.content_type = _first_json(op.get("consumes") or global_consumes) or "application/json"
                    continue
                if is_v2 and loc == "formData":
                    form_fields[p["name"]] = p.get("x-example", example_from_schema(_v2_param_schema(p), p["name"]))
                    continue
                if loc not in ("path", "query", "header", "cookie"):
                    continue
                schema = p.get("schema") if not is_v2 else _v2_param_schema(p)
                example = p.get("example", p.get("x-example"))
                if example is None and isinstance(p.get("examples"), dict) and p["examples"]:
                    first = next(iter(p["examples"].values()))
                    if isinstance(first, dict):
                        example = first.get("value")
                ep.params.append(
                    Param(
                        name=str(p["name"]),
                        location=loc,
                        required=bool(p.get("required")) or loc == "path",
                        schema=schema or {},
                        example=example,
                    )
                )
            if form_fields:
                ep.body = form_fields
                consumes = op.get("consumes") or global_consumes
                ep.content_type = (
                    "multipart/form-data" if "multipart/form-data" in consumes else "application/x-www-form-urlencoded"
                )

            if not is_v2 and isinstance(op.get("requestBody"), dict):
                _apply_request_body(ep, op["requestBody"])

            security = op.get("security", global_security)
            if security is not None:
                ep.auth_required = bool(security) and any(bool(s) for s in security)

            ep.expected_status = [str(code) for code in (op.get("responses") or {}).keys()]
            _ensure_path_params(ep)
            endpoints.append(ep)

    version = str(data.get("openapi") or data.get("swagger") or "")
    return ApiSpec(
        title=title,
        source_type="swagger2" if is_v2 else "openapi3",
        endpoints=endpoints,
        base_url=base_url,
        version=version,
        warnings=warnings,
    )


def _merge_params(shared: List[Any], own: List[Any]) -> List[Dict[str, Any]]:
    """Operation parameters override path-level ones with the same name and location."""
    merged: Dict[tuple, Dict[str, Any]] = {}
    for p in list(shared) + list(own):
        if isinstance(p, dict) and "name" in p:
            merged[(p["name"], p.get("in"))] = p
    return list(merged.values())


def _server_url(server: Any) -> str:
    if not isinstance(server, dict):
        return ""
    url = str(server.get("url") or "")
    for name, var in (server.get("variables") or {}).items():
        default = var.get("default", "") if isinstance(var, dict) else ""
        url = url.replace("{" + name + "}", str(default))
    return url.rstrip("/")


def _openapi3_base(data: Dict[str, Any]) -> str:
    servers = data.get("servers") or []
    return _server_url(servers[0]) if servers else ""


def _swagger_base(data: Dict[str, Any]) -> str:
    host = data.get("host")
    base_path = str(data.get("basePath") or "").rstrip("/")
    if not host:
        return base_path
    schemes = data.get("schemes") or ["https"]
    scheme = "https" if "https" in schemes else schemes[0]
    return f"{scheme}://{host}{base_path}"


def _v2_param_schema(p: Dict[str, Any]) -> Dict[str, Any]:
    keys = ("type", "format", "enum", "items", "minimum", "maximum", "minLength", "maxLength", "pattern", "default")
    return {k: copy.deepcopy(p[k]) for k in keys if k in p}


def _first_json(types: List[str]) -> Optional[str]:
    for t in types:
        if "json" in t:
            return t
    return types[0] if types else None


def _apply_request_body(ep: Endpoint, body: Dict[str, Any]) -> None:
    content = body.get("content") or {}
    if not isinstance(content, dict) or not content:
        return
    chosen = None
    for pref in _BODY_PREFERENCE:
        for media in content:
            if (pref.startswith("+") and media.endswith(pref)) or media.split(";")[0].strip() == pref:
                chosen = media
                break
        if chosen:
            break
    chosen = chosen or next(iter(content))
    media_obj = content.get(chosen) or {}
    schema = media_obj.get("schema") or {}
    example = media_obj.get("example")
    if example is None and isinstance(media_obj.get("examples"), dict) and media_obj["examples"]:
        first = next(iter(media_obj["examples"].values()))
        if isinstance(first, dict):
            example = first.get("value")
    ep.content_type = chosen
    ep.body_schema = schema
    ep.body = example if example is not None else example_from_schema(schema)


def _ensure_path_params(ep: Endpoint) -> None:
    """Some descriptions forget to declare a path parameter. Add it so the URL can be built."""
    import re

    declared = {p.name for p in ep.params_in("path")}
    for name in re.findall(r"{([^}/]+)}", ep.path):
        if name not in declared:
            ep.params.append(Param(name=name, location="path", required=True, schema={"type": "string"}))
