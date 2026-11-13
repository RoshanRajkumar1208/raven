"""Command-line interface: `raven scan`, `raven list`, `raven checks`, `raven demo`."""

from __future__ import annotations

import argparse
import datetime as dt
import fnmatch
import json
import os
import sys
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from raven_api import __version__

EXAMPLES = """
examples:
  raven demo                                              start the practice API (in a second terminal)
  raven scan http://127.0.0.1:8088/openapi.yaml --auth-bearer demo-token
  raven scan openapi.yaml --target https://staging.example.com --auth-bearer $TOKEN
  raven scan collection.postman.json --postman-env staging.postman_environment.json
  raven scan swagger.json --only RAV-H01,RAV-C01 --format all --fail-on high
  raven scan traffic.har --proxy http://127.0.0.1:8080 --insecure
  raven scan https://api.example.com/v1/users           a single URL works too
  raven list openapi.yaml                                 show the endpoints without sending anything

Only scan systems you own or have written permission to test.
"""


# --------------------------------------------------------------------------- colours
class C:
    on = True
    codes = {"b": "1", "dim": "2", "red": "31", "green": "32", "yellow": "33", "blue": "34", "magenta": "35",
             "cyan": "36", "grey": "90", "pink": "38;5;204", "indigo": "38;5;105", "orange": "38;5;214"}

    @classmethod
    def s(cls, text: Any, *styles: str) -> str:
        if not cls.on or not styles:
            return str(text)
        return "\033[" + ";".join(cls.codes[x] for x in styles) + "m" + str(text) + "\033[0m"


SEV_STYLE = {"critical": ("magenta", "b"), "high": ("red", "b"), "medium": ("orange",), "low": ("yellow",), "info": ("blue",)}


def setup_colour(disable: bool) -> None:
    forced = bool(os.environ.get("FORCE_COLOR"))  # colours in CI logs
    C.on = not disable and not os.environ.get("NO_COLOR") and (forced or sys.stdout.isatty())
    if C.on and os.name == "nt":
        os.system("")  # enables ANSI colours in the Windows console


def say(*parts: Any, quiet: bool = False) -> None:
    if not quiet:
        print(*parts, flush=True)


BANNER = r"""
   ___  ___ _   _____ _  __
  / _ \/ _ | | / / __/ |/ /   REST API Validation Engine
 / , _/ __ | |/ / _//    /    v{v}
/_/|_/_/ |_|___/___/_/|_/     configuration & contract checks for REST APIs
"""


# --------------------------------------------------------------------------- parser
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="raven",
        description="RAVEN checks REST APIs for security misconfigurations and for gaps between the API and its own description.",
        epilog=EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--version", action="version", version=f"RAVEN {__version__}")
    sub = p.add_subparsers(dest="command", metavar="COMMAND")

    scan = sub.add_parser("scan", help="scan an API", epilog=EXAMPLES, formatter_class=argparse.RawDescriptionHelpFormatter,
                          description="Scan an API described by OpenAPI 3, Swagger 2, Postman, API Blueprint, HAR, a URL list or a single URL.")
    _input_args(scan)
    a = scan.add_argument_group("authentication (credentials are masked in reports)")
    a.add_argument("--auth-bearer", metavar="TOKEN", help="send Authorization: Bearer TOKEN")
    a.add_argument("--auth-basic", metavar="USER:PASS", help="HTTP Basic authentication")
    a.add_argument("--api-key", metavar="NAME=VALUE", help="API key sent as a header, e.g. X-API-Key=abc123")
    a.add_argument("--api-key-query", metavar="NAME=VALUE", help="API key sent as a query parameter, e.g. api_key=abc123")
    a.add_argument("--cookie", metavar="COOKIES", help='cookies to send, e.g. "session=abc; csrftoken=xyz"')
    a.add_argument("--token-file", metavar="FILE", help="YAML file describing how to log in and refresh a token automatically")
    a.add_argument("-H", "--header", action="append", default=[], metavar='"NAME: VALUE"', help="extra header for every request (repeatable)")

    b = scan.add_argument_group("what to run")
    b.add_argument("--profile", choices=["quick", "standard"], default="standard",
                   help="quick = passive checks only (reads normal responses); standard = all checks (default)")
    b.add_argument("--only", metavar="IDS", help="run only these checks, e.g. RAV-H01,RAV-C01 (see `raven checks`)")
    b.add_argument("--skip", metavar="IDS", help="skip these checks")
    b.add_argument("--unsafe", action="store_true",
                   help="also send POST/PUT/PATCH/DELETE requests. They can create or change data: use on test systems only")
    b.add_argument("--yes", action="store_true", help="do not ask for confirmation when --unsafe targets a non-local host")
    b.add_argument("--slow-ms", type=int, default=2000, metavar="MS", help="report responses slower than this (default 2000)")
    b.add_argument("--max-cases", type=int, default=4, metavar="N", help="invalid-input requests per parameter (default 4)")

    n = scan.add_argument_group("network")
    n.add_argument("--timeout", type=float, default=15, metavar="SEC", help="seconds to wait for each response (default 15)")
    n.add_argument("--delay", type=int, default=0, metavar="MS", help="pause between requests in milliseconds (be gentle with shared systems)")
    n.add_argument("--max-requests", type=int, default=5000, metavar="N", help="stop after N requests (default 5000)")
    n.add_argument("--proxy", metavar="URL", help="send traffic through a proxy, e.g. Burp Suite at http://127.0.0.1:8080")
    n.add_argument("--insecure", action="store_true", help="do not verify TLS certificates (self-signed test servers, proxies)")
    n.add_argument("--user-agent", metavar="UA", help="custom User-Agent")

    o = scan.add_argument_group("output")
    o.add_argument("-o", "--output", metavar="DIR", help="folder for the reports (default: raven-report-<date-time>)")
    o.add_argument("--format", default="html,json", metavar="LIST", help="html, json, sarif, md, or all (default html,json)")
    o.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "info", "never"], default="never",
                   help="exit with code 1 if a finding of this severity or worse is found (for CI pipelines)")
    o.add_argument("--no-redact", action="store_true", help="show credentials in reports instead of masking them")
    o.add_argument("--open", action="store_true", help="open the HTML report in your browser when done")
    o.add_argument("-q", "--quiet", action="store_true", help="print only the summary")
    o.add_argument("--no-color", action="store_true", help="plain text output")
    o.add_argument("--config", metavar="FILE", help="YAML file with any of these options (command-line flags win)")

    lst = sub.add_parser("list", help="show the endpoints RAVEN found, without sending any request")
    _input_args(lst)
    lst.add_argument("--no-color", action="store_true")

    chk = sub.add_parser("checks", help="list every check, what it finds and its limits")
    chk.add_argument("--no-color", action="store_true")
    demo = sub.add_parser("demo", help="run the deliberately misconfigured practice API on 127.0.0.1")
    demo.add_argument("--port", type=int, default=8088)
    return p


def _input_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("source", help="API description file or URL (OpenAPI, Swagger, Postman, API Blueprint, HAR, URL list) or a single endpoint URL")
    g = p.add_argument_group("input")
    g.add_argument("-t", "--target", metavar="URL", help="base URL to scan, replacing the server in the description (e.g. a staging host)")
    g.add_argument("--input-type", default="auto", choices=["auto", "openapi", "swagger", "postman", "blueprint", "har", "urls"],
                   help="force the input format (default: detect automatically)")
    g.add_argument("--var", action="append", default=[], metavar="NAME=VALUE", help="Postman variable, e.g. --var baseUrl=https://api.example.com (repeatable)")
    g.add_argument("--postman-env", metavar="FILE", help="Postman environment export to read variables from")
    g.add_argument("--values", metavar="FILE", help="YAML/JSON file with values to use for parameters, e.g. {id: 42, query.limit: 5}")
    g.add_argument("--include", action="append", default=[], metavar="PATTERN", help="only endpoints whose path matches, e.g. '/users*' (repeatable)")
    g.add_argument("--exclude", action="append", default=[], metavar="PATTERN", help="skip endpoints whose path matches (repeatable)")
    g.add_argument("--methods", metavar="LIST", help="only these HTTP methods, e.g. GET,POST")


# --------------------------------------------------------------------------- helpers
def _split_ids(value: Optional[str]) -> List[str]:
    return [x for x in (value or "").replace(" ", "").split(",") if x]


def _load_values(path: Optional[str]) -> Dict[str, Any]:
    if not path:
        return {}
    import yaml

    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    if not isinstance(data, dict):
        raise ValueError("The --values file must contain name: value pairs.")
    return {str(k): v for k, v in data.items()}


def _parse_vars(items: List[str]) -> Dict[str, str]:
    out = {}
    for item in items:
        if "=" not in item:
            raise ValueError(f"--var needs NAME=VALUE (got: {item})")
        k, v = item.split("=", 1)
        out[k.strip()] = v
    return out


def _parse_headers(items: List[str]) -> Dict[str, str]:
    out = {}
    for item in items:
        if ":" not in item:
            raise ValueError(f'--header needs "Name: value" (got: {item})')
        k, v = item.split(":", 1)
        out[k.strip()] = v.strip()
    return out


def _filter_endpoints(spec, args) -> None:
    methods = {m.upper() for m in _split_ids(getattr(args, "methods", None))}
    eps = spec.endpoints
    if methods:
        eps = [e for e in eps if e.method in methods]
    if args.include:
        eps = [e for e in eps if any(fnmatch.fnmatch(e.path, pat) for pat in args.include)]
    if args.exclude:
        eps = [e for e in eps if not any(fnmatch.fnmatch(e.path, pat) for pat in args.exclude)]
    if not eps:
        raise ValueError("No endpoints left after --include/--exclude/--methods. Check your patterns with `raven list`.")
    spec.endpoints = eps


def _load(args):
    from raven_api.loaders import load_spec

    spec = load_spec(
        args.source,
        input_type=args.input_type,
        base_url=args.target,
        variables=_parse_vars(args.var),
        postman_env=args.postman_env,
        verify_tls=not getattr(args, "insecure", False),
        proxy=getattr(args, "proxy", None),
    )
    _filter_endpoints(spec, args)
    return spec


def _is_local(url: str) -> bool:
    host = (urlparse(url).hostname or "").lower()
    return host in ("localhost", "127.0.0.1", "::1") or host.endswith(".localhost")


def _apply_config(parser: argparse.ArgumentParser, argv: List[str]) -> List[str]:
    """--config FILE: values from the file become defaults; flags on the command line still win."""
    if "--config" not in argv:
        return argv
    i = argv.index("--config")
    if i + 1 >= len(argv):
        raise ValueError("--config needs a file name")
    import yaml

    with open(argv[i + 1], "r", encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh) or {}
    if not isinstance(cfg, dict):
        raise ValueError("The --config file must contain option: value pairs.")
    scan_parser = parser._subparsers._group_actions[0].choices["scan"]  # type: ignore[attr-defined]
    known = {a.dest for a in scan_parser._actions}
    defaults = {}
    extra: List[str] = []
    for key, value in cfg.items():
        dest = str(key).replace("-", "_")
        if dest == "source":
            if not any(not x.startswith("-") for x in argv[1:i]):
                extra = [str(value)]
            continue
        if dest not in known:
            raise ValueError(f"Unknown option in config file: {key}")
        if dest in ("header", "var", "include", "exclude") and isinstance(value, (list, dict)):
            value = [f"{k}: {v}" for k, v in value.items()] if (dest == "header" and isinstance(value, dict)) else list(value)
        if dest in ("only", "skip", "format", "methods") and isinstance(value, list):
            value = ",".join(str(v) for v in value)
        defaults[dest] = value
    scan_parser.set_defaults(**defaults)
    return argv[:1] + extra + argv[1:] if extra else argv


# --------------------------------------------------------------------------- commands
def cmd_checks() -> int:
    from raven_api.checks import CHECK_CLASSES, PROFILES

    say(C.s("RAVEN checks", "b", "indigo"), C.s("(passive = only reads normal responses · active = sends a few extra harmless requests)", "grey"))
    for cls in CHECK_CLASSES:
        quick = "quick+standard" if cls.id in PROFILES["quick"] else "standard"
        say(f"\n{C.s(cls.id, 'b', 'pink')}  {C.s(cls.name, 'b')}  {C.s('[' + cls.kind + ', ' + quick + ']', 'grey')}")
        say(f"  {cls.summary}")
        say(C.s(f"  Limits: {cls.limits}", "grey"))
    return 0


def cmd_list(args) -> int:
    spec = _load(args)
    say(f"{C.s(spec.title, 'b')}  {C.s(spec.source_type + (' ' + spec.version if spec.version else ''), 'grey')}")
    for base in sorted({e.base_url for e in spec.endpoints}):
        say(C.s(f"Base URL: {base}", "cyan"))
    say("")
    for e in spec.endpoints:
        params = ", ".join(f"{p.name}({p.location[0]})" for p in e.params) or "-"
        lock = C.s(" [auth]", "yellow") if e.auth_required else ""
        write = "" if e.is_safe else C.s("  (sent only with --unsafe)", "grey")
        say(f"  {C.s(e.method.ljust(7), 'b', 'indigo')} {e.path}{lock}{write}")
        say(C.s(f"          params: {params}" + (f" · body: {e.content_type}" if e.body is not None else ""), "grey"))
    for w in spec.warnings:
        say(C.s(f"! {w}", "yellow"))
    say(f"\n{len(spec.endpoints)} endpoints. Nothing was sent.")
    return 0


def cmd_demo(args) -> int:
    from raven_api.demo.server import main as demo_main

    return demo_main(["--port", str(args.port)])


def cmd_scan(args) -> int:
    from raven_api.auth import Auth
    from raven_api.checks import select_checks
    from raven_api.checks.base import ScanOptions
    from raven_api.client import HttpClient
    from raven_api.engine import Scanner
    from raven_api.models import SEVERITY_RANK
    from raven_api.report import FORMATS, grade, write_reports

    quiet = args.quiet
    say(C.s(BANNER.format(v=__version__), "indigo"), quiet=quiet)

    formats = list(FORMATS) if args.format.strip().lower() == "all" else _split_ids(args.format.lower())
    bad = [f for f in formats if f not in FORMATS]
    if bad:
        raise ValueError(f"Unknown report format(s): {', '.join(bad)}. Use html, json, sarif, md or all.")

    checks = select_checks(args.profile, _split_ids(args.only), _split_ids(args.skip))
    auth = Auth(args.auth_bearer, args.auth_basic, args.api_key, args.api_key_query, args.cookie, args.token_file)
    spec = _load(args)

    bases = sorted({e.base_url for e in spec.endpoints})
    say(f"{C.s('API', 'grey')}       {C.s(spec.title, 'b')} {C.s('(' + spec.source_type + ')', 'grey')}", quiet=quiet)
    say(f"{C.s('Target', 'grey')}    {', '.join(bases)}", quiet=quiet)
    say(f"{C.s('Endpoints', 'grey')} {len(spec.endpoints)}   {C.s('Checks', 'grey')} {len(checks)}   "
        f"{C.s('Auth', 'grey')} {auth.describe()}   {C.s('Mode', 'grey')} "
        + (C.s("UNSAFE (write requests on)", "red", "b") if args.unsafe else C.s("safe (read-only requests)", "green")), quiet=quiet)
    for w in spec.warnings:
        say(C.s(f"  ! {w}", "yellow"), quiet=quiet)

    if args.unsafe and not args.yes and not all(_is_local(b) for b in bases) and sys.stdin.isatty():
        say(C.s("\n--unsafe sends POST/PUT/PATCH/DELETE requests that can create, change or delete data on:", "red", "b"))
        for b in bases:
            say(C.s(f"  {b}", "red"))
        if input("Type 'yes' to continue: ").strip().lower() != "yes":
            say("Cancelled. Nothing was sent.")
            return 2

    client = HttpClient(
        auth=auth,
        timeout=args.timeout,
        verify_tls=not args.insecure,
        proxy=args.proxy,
        delay_ms=args.delay,
        extra_headers=_parse_headers(args.header),
        max_requests=args.max_requests,
        redact=not args.no_redact,
        user_agent=args.user_agent,
    )
    options = ScanOptions(values=_load_values(args.values), unsafe=args.unsafe, slow_ms=args.slow_ms,
                          max_validation_cases=max(1, args.max_cases))

    say("", quiet=quiet)

    def on_event(kind: str, **d) -> None:
        if quiet:
            return
        if kind == "host_check":
            say(C.s(f"  host   {d['check']} on {d['host']}", "grey"))
        elif kind == "endpoint_done":
            o = d["outcome"]
            idx = C.s(f"[{d['index']:>{len(str(d['total']))}}/{d['total']}]", "grey")
            method = C.s(o.method.ljust(7), "b", "indigo")
            if o.state == "skipped":
                tail = C.s("skipped (write request; add --unsafe on a test system)", "grey")
            elif o.state == "error":
                tail = C.s(o.note, "red")
            else:
                st = o.status or 0
                colour = "green" if st < 300 else "cyan" if st < 400 else "yellow" if st < 500 else "red"
                tail = f"{C.s(st, colour)} {C.s(f'{o.elapsed_ms:.0f}ms', 'grey')}"
            found = C.s(f"  {o.findings} finding{'s' if o.findings != 1 else ''}", "pink") if o.findings else ""
            say(f"  {idx} {method} {o.path}  {tail}{found}")
        elif kind == "check_error":
            say(C.s(f"  ! {d['error']}", "yellow"))

    result = Scanner(client, spec, checks, options, on_event).run()
    result.source = args.source

    out_dir = args.output or f"raven-report-{dt.datetime.now().strftime('%Y%m%d-%H%M%S')}"
    written = write_reports(result, out_dir, formats)

    counts = result.counts()
    g = grade(counts)
    say("")
    say(C.s("─" * 64, "grey"))
    gcol = {"A": "green", "B": "cyan", "C": "orange", "D": "red", "F": "magenta"}[g]
    say(f"  {C.s('Grade ' + g, 'b', gcol)}   {len(result.findings)} findings · {result.requests_sent} requests · {result.duration_s}s")
    say("  " + "   ".join(C.s(f"{n} {s}", *SEV_STYLE[s]) for s, n in counts.items()))
    if result.findings and not quiet:
        say("")
        seen = set()
        for f in result.findings:
            key = (f.severity, f.title)
            if key in seen:
                continue
            seen.add(key)
            where = sum(1 for x in result.findings if (x.severity, x.title) == key)
            say(f"  {C.s(f.severity.upper().ljust(8), *SEV_STYLE[f.severity])} {f.title} {C.s(f'({where}×)', 'grey')}")
            if len(seen) >= 12:
                rest = len({(x.severity, x.title) for x in result.findings}) - 12
                if rest > 0:
                    say(C.s(f"  … and {rest} more in the report", "grey"))
                break
    skipped = sum(1 for e in result.endpoints if e.state == "skipped")
    if skipped:
        say(C.s(f"\n  {skipped} write endpoint(s) skipped. Use --unsafe on a test system to include them.", "grey"))
    if result.stopped_reason:
        say(C.s(f"\n  ! {result.stopped_reason}", "yellow"))
    say("")
    for fmt, path in written.items():
        say(f"  {C.s(fmt.upper().ljust(5), 'b')} {os.path.abspath(path)}")
    say(C.s("─" * 64, "grey"))

    if args.open and "html" in written:
        import pathlib
        import webbrowser

        webbrowser.open(pathlib.Path(os.path.abspath(written["html"])).as_uri())

    if args.fail_on != "never":
        limit = SEVERITY_RANK[args.fail_on]
        if any(SEVERITY_RANK[f.severity] <= limit for f in result.findings):
            say(C.s(f"  Exit code 1: findings at '{args.fail_on}' or worse (--fail-on).", "red"))
            return 1
    return 0


# --------------------------------------------------------------------------- main
def main(argv: Optional[List[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    for stream in (sys.stdout, sys.stderr):  # never crash on a console that cannot show "─" or "…"
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass
    parser = build_parser()
    commands = {"scan", "list", "checks", "demo"}
    # friendly shortcut: `raven openapi.yaml` == `raven scan openapi.yaml`
    if argv and argv[0] not in commands and not argv[0].startswith("-"):
        argv = ["scan"] + argv
    setup_colour("--no-color" in argv)
    try:
        if argv and argv[0] == "scan":
            argv = _apply_config(parser, argv)
        args = parser.parse_args(argv)
        if args.command is None:
            parser.print_help()
            return 0
        if args.command == "checks":
            return cmd_checks()
        if args.command == "demo":
            return cmd_demo(args)
        if args.command == "list":
            return cmd_list(args)
        return cmd_scan(args)
    except KeyboardInterrupt:
        print("\nStopped.")
        return 130
    except BrokenPipeError:  # output piped into `head` etc.
        try:
            sys.stdout = open(os.devnull, "w")
        except OSError:
            pass
        return 0
    except Exception as exc:  # noqa: BLE001 - show a clean message instead of a stack trace
        from raven_api.auth import AuthError
        from raven_api.loaders import SpecError

        import yaml

        if isinstance(exc, yaml.YAMLError):
            print(C.s("Error: ", "red", "b") + "a YAML file could not be read (check indentation and quotes):\n" + str(exc), file=sys.stderr)
            return 2
        if isinstance(exc, (SpecError, AuthError, ValueError, OSError, json.JSONDecodeError)):
            print(C.s("Error: ", "red", "b") + str(exc), file=sys.stderr)
            return 2
        if os.environ.get("RAVEN_DEBUG"):
            raise
        print(C.s("Unexpected error: ", "red", "b") + f"{type(exc).__name__}: {exc}", file=sys.stderr)
        print("Run again with RAVEN_DEBUG=1 for details, and please open an issue on GitHub.", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
