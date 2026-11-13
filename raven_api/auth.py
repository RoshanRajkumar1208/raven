"""Authentication: static credentials and auto-refreshing tokens.

A token file lets RAVEN log in by itself and refresh the token while a long scan
runs (useful for OAuth2 client-credentials or any "POST /login -> token" flow):

    url: https://auth.example.com/oauth/token
    method: POST                       # optional, default POST
    data:                              # form body (use `json:` for a JSON body)
      grant_type: client_credentials
      client_id: ${CLIENT_ID}          # ${VAR} is read from environment variables
      client_secret: ${CLIENT_SECRET}
    headers: {}                        # optional
    token_field: access_token          # where the token is in the JSON reply (dots allowed)
    header: Authorization              # optional, default Authorization
    prefix: "Bearer "                  # optional, default "Bearer "
    refresh_seconds: 3000              # optional, default 3000 (50 minutes)
"""

from __future__ import annotations

import base64
import os
import re
import time
from typing import Any, Dict, Optional

import yaml

AUTH_HEADER_NAMES = {"authorization", "cookie", "x-api-key", "api-key", "apikey", "x-auth-token", "x-access-token", "proxy-authorization"}
_ENV = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


class AuthError(Exception):
    pass


def _expand_env(value: Any) -> Any:
    if isinstance(value, str):
        def repl(m: re.Match) -> str:
            name = m.group(1)
            if name not in os.environ:
                raise AuthError(f"Environment variable {name} is used in the token file but is not set.")
            return os.environ[name]

        return _ENV.sub(repl, value)
    if isinstance(value, dict):
        return {k: _expand_env(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand_env(v) for v in value]
    return value


class Auth:
    """Holds whatever credentials the user gave and applies them to requests."""

    def __init__(
        self,
        bearer: Optional[str] = None,
        basic: Optional[str] = None,
        api_key_header: Optional[str] = None,
        api_key_query: Optional[str] = None,
        cookie: Optional[str] = None,
        token_file: Optional[str] = None,
    ):
        self.headers: Dict[str, str] = {}
        self.query: Dict[str, str] = {}
        self.extra_auth_names = set()
        self._token_cfg: Optional[Dict[str, Any]] = None
        self._token_expiry = 0.0

        if bearer:
            self.headers["Authorization"] = bearer if bearer.lower().startswith(("bearer ", "token ")) else f"Bearer {bearer}"
        if basic:
            if ":" not in basic:
                raise AuthError("--auth-basic needs the form username:password")
            self.headers["Authorization"] = "Basic " + base64.b64encode(basic.encode()).decode()
        if api_key_header:
            name, value = _split_pair(api_key_header, "--api-key")
            self.headers[name] = value
            self.extra_auth_names.add(name.lower())
        if api_key_query:
            name, value = _split_pair(api_key_query, "--api-key-query")
            self.query[name] = value
            self.extra_auth_names.add(name.lower())
        if cookie:
            self.headers["Cookie"] = cookie
        if token_file:
            self._load_token_file(token_file)

    @property
    def configured(self) -> bool:
        return bool(self.headers or self.query or self._token_cfg)

    @property
    def secret_names(self) -> set:
        return AUTH_HEADER_NAMES | self.extra_auth_names

    def describe(self) -> str:
        parts = []
        for k in self.headers:
            parts.append(f"header {k}")
        for k in self.query:
            parts.append(f"query {k}")
        if self._token_cfg:
            parts.append("token file (auto-refresh)")
        return ", ".join(parts) or "none"

    def _load_token_file(self, path: str) -> None:
        if not os.path.exists(path):
            raise AuthError(f"Token file not found: {path}")
        with open(path, "r", encoding="utf-8") as fh:
            cfg = yaml.safe_load(fh) or {}
        if not isinstance(cfg, dict) or not cfg.get("url"):
            raise AuthError("The token file needs at least a `url:` entry. See `raven --help` for the format.")
        self._token_cfg = _expand_env(cfg)
        self.extra_auth_names.add(str(self._token_cfg.get("header", "Authorization")).lower())

    def refresh_if_needed(self, session: Any, timeout: float, verify: bool, proxies: Optional[Dict[str, str]]) -> None:
        if not self._token_cfg or time.time() < self._token_expiry:
            return
        cfg = self._token_cfg
        try:
            resp = session.request(
                str(cfg.get("method", "POST")).upper(),
                cfg["url"],
                data=cfg.get("data"),
                json=cfg.get("json"),
                headers=cfg.get("headers") or {},
                timeout=timeout,
                verify=verify,
                proxies=proxies,
            )
        except Exception as exc:  # noqa: BLE001 - surface any network error to the user
            raise AuthError(f"Could not reach the token URL {cfg['url']}: {exc}") from exc
        if resp.status_code >= 400:
            raise AuthError(f"Login failed: the token URL answered {resp.status_code}. Check the token file.")
        try:
            node: Any = resp.json()
        except ValueError as exc:
            raise AuthError("The token URL did not return JSON.") from exc
        for part in str(cfg.get("token_field", "access_token")).split("."):
            node = node.get(part) if isinstance(node, dict) else None
        if not node:
            raise AuthError(f"No `{cfg.get('token_field', 'access_token')}` field in the token response.")
        self.headers[str(cfg.get("header", "Authorization"))] = str(cfg.get("prefix", "Bearer ")) + str(node)
        self._token_expiry = time.time() + float(cfg.get("refresh_seconds", 3000))


def _split_pair(value: str, flag: str) -> tuple:
    for sep in ("=", ":"):
        if sep in value:
            k, v = value.split(sep, 1)
            if k.strip():
                return k.strip(), v.strip()
    raise AuthError(f"{flag} needs the form NAME=VALUE, for example {flag} X-API-Key=abc123")
