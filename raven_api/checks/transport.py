"""Transport security: TLS certificate, protocol version, plain-HTTP exposure."""

from __future__ import annotations

import datetime as dt
import socket
import ssl
from typing import List
from urllib.parse import urlparse

from raven_api.checks.base import Check, ScanContext
from raven_api.client import PlannedRequest
from raven_api.models import Finding

_LOCAL = ("localhost", "127.0.0.1", "::1", "0.0.0.0")


class TransportSecurity(Check):
    id = "RAV-T01"
    name = "TLS and HTTPS"
    kind = "active"
    scope = "host"
    summary = "Checks the TLS certificate (valid, matches the host, not expiring), the TLS version, and whether the API also answers over plain HTTP."
    limits = "Checks the negotiated TLS version and certificate only; for a full cipher review use testssl.sh or SSL Labs."

    def run_host(self, ctx: ScanContext, base_url: str) -> List[Finding]:
        parsed = urlparse(base_url)
        host = parsed.hostname or ""
        if host in _LOCAL:
            return []
        out: List[Finding] = []
        if parsed.scheme == "http":
            out.append(self.finding(
                title="API served without TLS",
                severity="high",
                endpoint="host",
                url=base_url,
                description="The API is reached over plain HTTP. Tokens, passwords and data travel unencrypted and can be read or changed on the network.",
                fix="Serve the API only over HTTPS and redirect or refuse plain HTTP.",
                evidence=f"Base URL: {base_url}",
                cwe=319,
                owasp="API8:2023 Security Misconfiguration",
            ))
            return out

        port = parsed.port or 443
        out.extend(self._certificate(ctx, base_url, host, port))
        out.extend(self._plain_http(ctx, base_url, host))
        return out

    def _certificate(self, ctx: ScanContext, base_url: str, host: str, port: int) -> List[Finding]:
        out: List[Finding] = []
        verified = ssl.create_default_context()
        try:
            with socket.create_connection((host, port), timeout=ctx.client.timeout) as sock:
                with verified.wrap_socket(sock, server_hostname=host) as tls:
                    cert = tls.getpeercert()
                    version = tls.version() or ""
        except ssl.SSLCertVerificationError as exc:
            return [self.finding(
                title="TLS certificate is not trusted",
                severity="high",
                endpoint="host",
                url=base_url,
                description="Clients cannot verify the server's certificate (self-signed, expired, wrong host name or missing intermediate). "
                "Clients that skip verification can be intercepted.",
                fix="Install a certificate from a trusted CA (e.g. Let's Encrypt) that covers this host name, including the full chain.",
                evidence=str(exc.verify_message or exc),
                cwe=295,
                owasp="API8:2023 Security Misconfiguration",
            )]
        except (OSError, ssl.SSLError):
            return []

        if version in ("TLSv1", "TLSv1.1", "SSLv3"):
            out.append(self.finding(
                title="Outdated TLS version negotiated",
                severity="medium",
                endpoint="host",
                url=base_url,
                description=f"The server chose {version}, which is deprecated (RFC 8996).",
                fix="Allow TLS 1.2 and TLS 1.3 only.",
                evidence=f"Negotiated protocol: {version}",
                cwe=326,
            ))
        not_after = cert.get("notAfter") if cert else None
        if not_after:
            try:
                expires = dt.datetime.utcfromtimestamp(ssl.cert_time_to_seconds(not_after))
                days = (expires - dt.datetime.utcnow()).days
                if days < 30:
                    out.append(self.finding(
                        title="TLS certificate expires soon",
                        severity="medium" if days < 7 else "low",
                        endpoint="host",
                        url=base_url,
                        description=f"The certificate expires in {days} day(s). When it expires, clients will refuse to connect.",
                        fix="Renew the certificate and automate renewal.",
                        evidence=f"notAfter: {not_after}",
                        cwe=298,
                    ))
            except (ValueError, OverflowError):
                pass
        return out

    def _plain_http(self, ctx: ScanContext, base_url: str, host: str) -> List[Finding]:
        http_url = "http://" + base_url.split("://", 1)[1]
        res = ctx.send(PlannedRequest("GET", http_url), timeout=min(ctx.client.timeout, 8))
        if not res.ok:
            return []
        location = res.header("Location")
        if 300 <= res.status < 400 and location.lower().startswith("https://"):
            return []
        return [self.finding(
            title="API also answers over plain HTTP",
            severity="medium",
            endpoint="host",
            url=http_url,
            description="The same API responds on http:// instead of redirecting to https://. A client that is misconfigured or downgraded sends its credentials unencrypted.",
            fix="Redirect all http:// requests to https:// (or close port 80), and send Strict-Transport-Security.",
            evidence=f"GET {http_url} -> {res.status}" + (f" (Location: {location})" if location else ""),
            result=res,
            cwe=319,
            owasp="API8:2023 Security Misconfiguration",
        )]
