"""Load an API description from a file or URL and turn it into endpoints.

Supported inputs (auto-detected from the content, not the file extension):

* OpenAPI 3.0 / 3.1   (YAML or JSON)
* Swagger 2.0          (YAML or JSON)
* Postman collection   v2.0 / v2.1 (JSON), with optional environment file
* API Blueprint        (.apib, Markdown)
* HAR file             (exported from a browser's DevTools, Burp or ZAP)
* URL list             (text file, one "METHOD URL" per line)
* A single URL         (an endpoint, or a link to any of the formats above)
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse

import yaml

from raven_api.models import ApiSpec

INPUT_TYPES = ("auto", "openapi", "swagger", "postman", "blueprint", "har", "urls")


class SpecError(Exception):
    """The input could not be read or understood."""


def _is_url(source: str) -> bool:
    return source.lower().startswith(("http://", "https://"))


def read_source(source: str, verify_tls: bool = True, proxy: Optional[str] = None) -> Tuple[str, Optional[str]]:
    """Return (text, origin_url). origin_url is set when the source was fetched over HTTP."""
    if _is_url(source):
        import requests

        try:
            resp = requests.get(
                source,
                timeout=20,
                verify=verify_tls,
                proxies={"http": proxy, "https": proxy} if proxy else None,
                headers={"User-Agent": "RAVEN-API-Scanner", "Accept": "application/json, application/yaml, */*"},
            )
        except requests.RequestException as exc:
            raise SpecError(f"Could not download {source}: {exc}") from exc
        return resp.text, source
    if not os.path.exists(source):
        raise SpecError(f"File not found: {source}")
    with open(source, "r", encoding="utf-8-sig", errors="replace") as fh:
        return fh.read(), None


def parse_structured(text: str) -> Any:
    """Parse JSON, falling back to YAML. Returns None if neither works."""
    stripped = text.lstrip()
    if stripped.startswith(("{", "[")):
        try:
            return json.loads(text)
        except ValueError:
            pass
    try:
        return yaml.safe_load(text)
    except yaml.YAMLError:
        return None


def detect_type(text: str, data: Any) -> str:
    if isinstance(data, dict):
        if "openapi" in data:
            return "openapi"
        if "swagger" in data:
            return "swagger"
        info = data.get("info")
        if isinstance(info, dict) and ("_postman_id" in info or "postman" in str(info.get("schema", ""))):
            return "postman"
        if "item" in data and isinstance(data.get("item"), list):
            return "postman"
        log = data.get("log")
        if isinstance(log, dict) and "entries" in log:
            return "har"
    head = text.lstrip()[:2000]
    if head.upper().startswith("FORMAT: 1A") or ("\n## " in text and "[/" in text) or "\nHOST:" in head:
        return "blueprint"
    lines = [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")]
    if lines and all(_looks_like_url_line(ln) for ln in lines[:20]):
        return "urls"
    raise SpecError(
        "Could not recognise the input. RAVEN reads OpenAPI 3, Swagger 2, Postman collections, "
        "API Blueprint, HAR files and URL lists. Use --input-type to force a format."
    )


def _looks_like_url_line(line: str) -> bool:
    parts = line.split()
    if not parts:
        return False
    if len(parts) >= 2 and parts[0].upper() in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"):
        return _is_url(parts[1]) or parts[1].startswith("/")
    return _is_url(parts[0])


def load_spec(
    source: str,
    input_type: str = "auto",
    base_url: Optional[str] = None,
    variables: Optional[Dict[str, str]] = None,
    postman_env: Optional[str] = None,
    verify_tls: bool = True,
    proxy: Optional[str] = None,
) -> ApiSpec:
    """Read `source` and return an ApiSpec with absolute base URLs on every endpoint."""
    from raven_api.loaders import blueprint, har, openapi, postman, urllist

    text, origin = read_source(source, verify_tls=verify_tls, proxy=proxy)
    if not text.strip():
        raise SpecError(f"{source} is empty.")
    data = parse_structured(text)

    kind = input_type if input_type and input_type != "auto" else None
    if kind is None:
        try:
            kind = detect_type(text, data)
        except SpecError:
            if origin:  # a URL that is not a spec: scan that single endpoint
                kind = "urls"
                text = source
            else:
                raise

    env_vars: Dict[str, str] = {}
    if postman_env:
        env_vars = postman.read_environment(postman_env)
    env_vars.update(variables or {})

    if kind in ("openapi", "swagger"):
        if not isinstance(data, dict):
            raise SpecError("The OpenAPI/Swagger file is not valid YAML or JSON.")
        spec = openapi.load(data, origin)
    elif kind == "postman":
        if not isinstance(data, dict):
            raise SpecError("The Postman collection is not valid JSON.")
        spec = postman.load(data, env_vars)
    elif kind == "har":
        if not isinstance(data, dict):
            raise SpecError("The HAR file is not valid JSON.")
        spec = har.load(data)
    elif kind == "blueprint":
        spec = blueprint.load(text)
    elif kind == "urls":
        spec = urllist.load(text)
    else:
        raise SpecError(f"Unknown input type: {kind}")

    _apply_base_url(spec, base_url, origin)
    if not spec.endpoints:
        raise SpecError("No endpoints were found in the input.")
    return spec


def _apply_base_url(spec: ApiSpec, override: Optional[str], origin: Optional[str]) -> None:
    """Give every endpoint an absolute base URL, or fail with a clear message."""
    if override:
        # --target replaces scheme + host. If it has no path of its own, the base path
        # from the description is kept: --target https://staging.example.com on a spec
        # whose server is https://api.example.com/v1 scans https://staging.example.com/v1.
        override = override.rstrip("/")
        if not _is_url(override):
            raise SpecError(f"--target must start with http:// or https:// (got: {override})")
        keep_path = urlparse(override).path in ("", "/")

        def with_override(original: str) -> str:
            if not keep_path:
                return override
            path = urlparse(original).path if _is_url(original) else (original or "")
            return override + ("/" + path.strip("/") if path.strip("/") else "")

        spec.base_url = with_override(spec.base_url)
        for ep in spec.endpoints:
            ep.base_url = with_override(ep.base_url or spec.base_url)
        return

    origin_root = ""
    if origin:
        p = urlparse(origin)
        origin_root = f"{p.scheme}://{p.netloc}"

    def absolute(url: str) -> str:
        if not url:
            return origin_root
        if _is_url(url):
            return url.rstrip("/")
        if origin_root:
            return (origin_root + "/" + url.lstrip("/")).rstrip("/")
        return url.rstrip("/")

    spec.base_url = absolute(spec.base_url)
    missing = []
    for ep in spec.endpoints:
        ep.base_url = absolute(ep.base_url or spec.base_url)
        if not _is_url(ep.base_url):
            missing.append(ep.key)
    if missing:
        raise SpecError(
            "The API description does not say where the API is hosted "
            f"(no absolute server URL for {len(missing)} endpoint(s)). "
            "Add it with --target, for example: --target https://api.example.com"
        )
