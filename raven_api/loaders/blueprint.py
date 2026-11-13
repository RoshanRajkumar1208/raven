"""API Blueprint (.apib) loader.

Covers the parts of the format that matter for testing: HOST, resources with URI
templates, actions, + Parameters, + Request (headers and body) and + Response codes.
It is not a full API Blueprint/MSON parser: data structures (MSON attributes) are
not expanded, so request bodies must be written out under + Body.
"""

from __future__ import annotations

import json
import re
import textwrap
from typing import List, Optional, Tuple

from raven_api.models import ApiSpec, Endpoint, Param

_METHODS = "GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS"
_RESOURCE = re.compile(r"^#{1,3}\s+.*?\[(/[^\]]*)\]\s*$")
_ACTION = re.compile(rf"^#{{1,4}}\s+.*?\[({_METHODS})(?:\s+(/[^\]]*))?\]\s*$")
_SHORT_ACTION = re.compile(rf"^#{{1,4}}\s+({_METHODS})\s+(/\S*)\s*$")
_SHORT_RESOURCE = re.compile(r"^#{1,3}\s+(/\S*)\s*$")
_PARAM = re.compile(r"^\s*[+*-]\s+`?([A-Za-z0-9_.\-]+)`?(?:\s*:\s*`?([^`(]*?)`?)?\s*(?:\(([^)]*)\))?\s*(?:-\s*(.*))?$")
_TYPES = {"number": "number", "integer": "integer", "string": "string", "boolean": "boolean", "array": "array", "object": "object"}


def _split_template(template: str) -> Tuple[str, List[str]]:
    """'/notes/{id}{?limit,offset}' -> ('/notes/{id}', ['limit', 'offset'])."""
    query: List[str] = []

    def grab(m: re.Match) -> str:
        query.extend(x.strip().lstrip("*") for x in m.group(1).split(",") if x.strip())
        return ""

    path = re.sub(r"{[?&]([^}]*)}", grab, template)
    path = re.sub(r"{[+#]([^}]*)}", r"{\1}", path)  # reserved expansion -> plain
    return path or "/", query


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" \t"))


def _block(lines: List[str], start: int, parent_indent: int) -> Tuple[List[str], int]:
    """Collect lines indented deeper than parent_indent (blank lines included)."""
    out: List[str] = []
    i = start
    while i < len(lines):
        line = lines[i]
        if line.strip() and (_indent(line) <= parent_indent or line.lstrip().startswith("#")):
            break
        out.append(line)
        i += 1
    while out and not out[-1].strip():
        out.pop()
    return out, i


def load(text: str) -> ApiSpec:
    lines = text.replace("\t", "    ").splitlines()
    host = ""
    title = "API Blueprint"
    for line in lines[:30]:
        if line.upper().startswith("HOST:"):
            host = line.split(":", 1)[1].strip()
        elif line.startswith("# ") and title == "API Blueprint":
            title = line[2:].strip()

    endpoints: List[Endpoint] = []
    warnings: List[str] = []
    resource_path: Optional[str] = None
    resource_query: List[str] = []
    resource_params: List[Param] = []
    current: Optional[Endpoint] = None

    def finish() -> None:
        nonlocal current
        if current is not None:
            for p in resource_params:
                existing = next((x for x in current.params if x.name == p.name), None)
                if existing is None:
                    current.params.append(Param(p.name, p.location, p.required, dict(p.schema), p.example))
                else:  # the URI template named it; the + Parameters block describes it
                    if existing.example is None:
                        existing.example = p.example
                    if not existing.schema:
                        existing.schema = dict(p.schema)
                    existing.required = existing.required or p.required
            endpoints.append(current)
            current = None

    def new_action(method: str, template: Optional[str]) -> Endpoint:
        if template:
            path, query = _split_template(template)
        else:
            path, query = resource_path or "/", list(resource_query)
        ep = Endpoint(method=method, path=path, source="blueprint")
        for name in re.findall(r"{([^}/]+)}", path):
            ep.params.append(Param(name=name, location="path", required=True))
        for name in query:
            ep.params.append(Param(name=name, location="query"))
        return ep

    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        m_action = _ACTION.match(stripped) or _SHORT_ACTION.match(stripped)
        m_resource = None if m_action else (_RESOURCE.match(stripped) or _SHORT_RESOURCE.match(stripped))

        if m_action:
            finish()
            current = new_action(m_action.group(1).upper(), m_action.group(2))
            name_part = stripped.lstrip("#").split("[")[0].strip()
            current.summary = name_part if not name_part.upper().startswith(m_action.group(1)) else ""
            i += 1
            continue
        if m_resource:
            finish()
            resource_path, resource_query = _split_template(m_resource.group(1))
            resource_params = []
            i += 1
            continue

        low = stripped.lower()
        if low.startswith(("+ parameters", "* parameters", "- parameters")):
            block, i = _block(lines, i + 1, _indent(line))
            params = _parse_params(block)
            target = current.params if current is not None else resource_params
            for p in params:
                existing = next((x for x in target if x.name == p.name), None)
                if existing:
                    existing.example = p.example if p.example is not None else existing.example
                    existing.schema = p.schema or existing.schema
                    existing.required = p.required or existing.location == "path"
                else:
                    path_now = current.path if current is not None else (resource_path or "")
                    p.location = "path" if "{" + p.name + "}" in path_now else "query"
                    p.required = p.required or p.location == "path"
                    target.append(p)
            continue
        if low.startswith(("+ request", "* request", "- request")) and current is not None:
            m = re.search(r"\(([^)]+)\)", stripped)
            if m:
                current.content_type = m.group(1).strip()
            block, i = _block(lines, i + 1, _indent(line))
            _parse_request_block(current, block)
            continue
        if low.startswith(("+ response", "* response", "- response")) and current is not None:
            m = re.search(r"response\s+(\d{3})", low)
            if m:
                current.expected_status.append(m.group(1))
        i += 1
    finish()

    for ep in endpoints:
        if any(k.lower() == "authorization" for k in ep.headers):
            ep.auth_required = True
    return ApiSpec(title=title, source_type="blueprint", endpoints=endpoints, base_url=host, warnings=warnings)


def _parse_params(block: List[str]) -> List[Param]:
    params: List[Param] = []
    base = min((_indent(ln) for ln in block if ln.strip()), default=0)
    for ln in block:
        if not ln.strip() or _indent(ln) != base:
            continue  # descriptions, defaults and members sit deeper
        m = _PARAM.match(ln)
        if not m:
            continue
        name, example, attrs = m.group(1), (m.group(2) or "").strip(), (m.group(3) or "")
        attr_list = [a.strip().lower() for a in attrs.split(",") if a.strip()]
        ptype = next((_TYPES[a] for a in attr_list if a in _TYPES), "string")
        value: object = example or None
        if value is not None and ptype in ("number", "integer"):
            try:
                value = int(example) if example.lstrip("-").isdigit() else float(example)
            except ValueError:
                pass
        params.append(
            Param(name=name, location="query", required="required" in attr_list, schema={"type": ptype}, example=value)
        )
    return params


def _parse_request_block(ep: Endpoint, block: List[str]) -> None:
    i = 0
    body_lines: Optional[List[str]] = None
    loose: List[str] = []
    while i < len(block):
        ln = block[i]
        low = ln.strip().lower()
        if low.startswith(("+ headers", "* headers", "- headers")):
            sub, j = _block(block, i + 1, _indent(ln))
            for h in textwrap.dedent("\n".join(sub)).splitlines():
                if ":" in h:
                    k, v = h.split(":", 1)
                    ep.headers[k.strip()] = v.strip()
            i = j
            continue
        if low.startswith(("+ body", "* body", "- body")):
            sub, j = _block(block, i + 1, _indent(ln))
            body_lines = sub
            i = j
            continue
        if low.startswith(("+ attributes", "+ schema", "* attributes", "* schema")):
            _, j = _block(block, i + 1, _indent(ln))
            i = j
            continue
        loose.append(ln)
        i += 1
    if body_lines is None and any(x.strip() for x in loose):
        body_lines = loose
    if body_lines:
        raw = textwrap.dedent("\n".join(body_lines)).strip()
        try:
            ep.body = json.loads(raw)
            ep.content_type = ep.content_type or "application/json"
        except ValueError:
            ep.body = raw
    if ep.content_type and not any(k.lower() == "content-type" for k in ep.headers):
        ep.headers["Content-Type"] = ep.content_type
