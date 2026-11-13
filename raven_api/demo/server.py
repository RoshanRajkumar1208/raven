"""RAVEN demo API: a tiny shop API with deliberate configuration mistakes.

Run it with `raven demo` (or `python -m raven_api.demo.server`) and scan it with
`raven scan http://127.0.0.1:8088/openapi.yaml --auth-bearer demo-token`.

It listens on 127.0.0.1 only. Every weakness below is fake and harmless, and each
one maps to a RAVEN check so you can see what a finding looks like:

  whole server      Server header shows a version, TRACE enabled, no rate-limit headers
  /health           otherwise configured correctly
  /products         validates its input correctly
  /users            X-Powered-By leak, CORS trusts any origin, token not checked
  /users/{id}       crashes on bad input (stack trace), returns a password hash
  /orders           authentication enforced correctly; advertises an undocumented PUT
  /login            cookie without flags, accepts text/plain, crashes on a missing field
  /reports/daily    slow, token not checked, JSON labelled as HTML, undocumented status
"""

from __future__ import annotations

import argparse
import json
import os
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional, Tuple

DEMO_TOKEN = "demo-token"
SPEC_PATH = os.path.join(os.path.dirname(__file__), "openapi.yaml")

USERS = {
    1: {"id": 1, "name": "Ada", "email": "ada@example.com", "password_hash": "$2b$12$demoHashNotARealPasswordHash000000000"},
    2: {"id": 2, "name": "Linus", "email": "linus@example.com", "password_hash": "$2b$12$anotherFakeHashForTheDemoOnly0000000"},
}
PRODUCTS = [
    {"id": 7, "name": "Threat Modeling", "category": "books"},
    {"id": 8, "name": "Capture the Flag", "category": "games"},
]
GOOD_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "Cache-Control": "no-store",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
}
FAKE_TRACEBACK = (
    'Traceback (most recent call last):\n'
    '  File "/usr/src/app/shop/views.py", line 42, in get_user\n'
    "    user_id = int(request.path_params['id'])\n"
    "ValueError: invalid literal for int() with base 10\n"
)


class DemoHandler(BaseHTTPRequestHandler):
    server_version = "RavenDemo/1.0.3"
    sys_version = ""
    slow_seconds = 2.1
    seen: list = []  # (method, path) of every request, used by the test suite

    def parse_request(self) -> bool:
        ok = super().parse_request()
        if ok:
            self.seen.append((self.command, self.path))
        return ok

    def log_message(self, fmt: str, *args) -> None:  # keep the console quiet
        if os.environ.get("RAVEN_DEMO_LOG"):
            super().log_message(fmt, *args)

    # ------------------------------------------------------------ helpers
    def _send(self, status: int, body, headers: Optional[dict] = None, ctype: str = "application/json") -> None:
        data = body if isinstance(body, (bytes, str)) else json.dumps(body)
        data = data.encode() if isinstance(data, str) else data
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def _route(self) -> Tuple[str, dict]:
        path, _, query = self.path.partition("?")
        params = {}
        for pair in query.split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                from urllib.parse import unquote_plus

                params[unquote_plus(k)] = unquote_plus(v)
        return path.rstrip("/") or "/", params

    def _body(self) -> bytes:
        length = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(length) if length else b""

    def _authed(self) -> bool:
        return self.headers.get("Authorization", "") == f"Bearer {DEMO_TOKEN}"

    # ------------------------------------------------------------ methods
    def do_GET(self) -> None:  # noqa: N802
        path, q = self._route()
        if path == "/openapi.yaml":
            with open(SPEC_PATH, "rb") as fh:
                return self._send(200, fh.read(), GOOD_HEADERS, "application/yaml")
        if path == "/api/v1/health":
            return self._send(200, {"status": "ok"}, GOOD_HEADERS)
        if path == "/api/v1/products":
            cat, limit = q.get("category"), q.get("limit", "10")
            if cat is not None and cat not in ("books", "games", "music"):
                return self._send(400, {"error": "invalid category"}, GOOD_HEADERS)
            if not limit.isdigit() or not 1 <= int(limit) <= 100:
                return self._send(400, {"error": "limit must be 1-100"}, GOOD_HEADERS)
            items = [p for p in PRODUCTS if cat in (None, p["category"])][: int(limit)]
            return self._send(200, items, GOOD_HEADERS)
        if path == "/api/v1/users":
            origin = self.headers.get("Origin")
            leaky = {"X-Powered-By": "Express/4.17.1"}
            if origin:
                leaky.update({"Access-Control-Allow-Origin": origin, "Access-Control-Allow-Credentials": "true"})
            return self._send(200, [{"id": u["id"], "name": u["name"]} for u in USERS.values()], leaky)
        m = re.fullmatch(r"/api/v1/users/([^/]+)", path)
        if m:
            raw = m.group(1)
            if not raw.lstrip("-").isdigit():
                return self._send(500, FAKE_TRACEBACK, {}, "text/plain")
            user = USERS.get(int(raw))
            if not user:
                return self._send(404, {"error": "not found"}, GOOD_HEADERS)
            return self._send(200, user, {"Cache-Control": "no-store"})
        if path == "/api/v1/orders":
            if not self._authed():
                return self._send(401, {"error": "login required"}, {**GOOD_HEADERS, "WWW-Authenticate": "Bearer"})
            return self._send(200, [{"id": 501, "product_id": 7, "quantity": 1}], GOOD_HEADERS)
        if path == "/api/v1/reports/daily":
            time.sleep(self.slow_seconds)
            return self._send(202, {"report": "queued", "rows": 0}, {"Cache-Control": "no-store"}, "text/html")
        return self._send(404, {"error": "not found"}, GOOD_HEADERS)

    def do_HEAD(self) -> None:  # noqa: N802
        self.do_GET()

    def do_POST(self) -> None:  # noqa: N802
        path, _ = self._route()
        raw = self._body()
        if path == "/api/v1/login":
            try:
                data = json.loads(raw or b"{}")  # ignores Content-Type on purpose
                name = data["username"]
                data["password"]  # required: a missing field raises KeyError (the demo bug)
            except KeyError as exc:
                return self._send(500, FAKE_TRACEBACK.replace("int(request.path_params['id'])", f"data[{exc}]")
                                  .replace("ValueError: invalid literal for int() with base 10", f"KeyError: {exc}"), {}, "text/plain")
            except ValueError:
                return self._send(400, {"error": "invalid JSON"}, GOOD_HEADERS)
            if isinstance(name, str) and len(name) > 50:
                pass  # maxLength is documented but not enforced
            return self._send(200, {"token": DEMO_TOKEN}, {"Set-Cookie": "session=demo-session-123; Path=/"})
        if path == "/api/v1/orders":
            if not self._authed():
                return self._send(401, {"error": "login required"}, GOOD_HEADERS)
            try:
                data = json.loads(raw or b"{}")
                pid, qty = int(data["product_id"]), int(data["quantity"])
                if pid < 1 or not 1 <= qty <= 20:
                    raise ValueError
            except (KeyError, ValueError, TypeError):
                return self._send(400, {"error": "invalid order"}, GOOD_HEADERS)
            return self._send(201, {"id": 502, "product_id": pid, "quantity": qty}, GOOD_HEADERS)
        return self._send(404, {"error": "not found"}, GOOD_HEADERS)

    def do_OPTIONS(self) -> None:  # noqa: N802
        path, _ = self._route()
        allow = "GET, OPTIONS"
        if path == "/api/v1/orders":
            allow = "GET, POST, PUT, OPTIONS"
        elif path == "/api/v1/login":
            allow = "POST, OPTIONS"
        headers = {"Allow": allow, **GOOD_HEADERS}
        if path == "/api/v1/users" and self.headers.get("Origin"):
            headers.update({"Access-Control-Allow-Origin": self.headers["Origin"], "Access-Control-Allow-Credentials": "true"})
        self._send(204, b"", headers)

    def do_TRACE(self) -> None:  # noqa: N802
        echo = f"{self.requestline}\r\n" + "".join(f"{k}: {v}\r\n" for k, v in self.headers.items())
        self._send(200, echo, {}, "message/http")

    def do_PUT(self) -> None:  # noqa: N802
        self._send(405, {"error": "method not allowed"}, {"Allow": "GET, POST, OPTIONS", **GOOD_HEADERS})

    do_DELETE = do_PUT
    do_PATCH = do_PUT


def start(host: str = "127.0.0.1", port: int = 8088, slow_seconds: float = 2.1) -> ThreadingHTTPServer:
    """Start the demo API in a background thread and return the server (call .shutdown() to stop)."""
    handler = type("ConfiguredDemoHandler", (DemoHandler,), {"slow_seconds": slow_seconds, "seen": []})
    httpd = ThreadingHTTPServer((host, port), handler)
    httpd.daemon_threads = True
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Run the RAVEN demo API (deliberately misconfigured, local only).")
    parser.add_argument("--port", type=int, default=8088)
    args = parser.parse_args(argv)
    httpd = ThreadingHTTPServer(("127.0.0.1", args.port), DemoHandler)
    print(f"RAVEN demo API running on http://127.0.0.1:{args.port}  (Ctrl+C to stop)")
    print(f"Scan it:  raven scan http://127.0.0.1:{args.port}/openapi.yaml --auth-bearer {DEMO_TOKEN}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nDemo API stopped.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
