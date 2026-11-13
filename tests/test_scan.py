"""End-to-end scans against the bundled demo API."""

import json
import os

import pytest

from raven_api.cli import main

WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def run(args, tmp_path, name="out"):
    out = tmp_path / name
    code = main(["scan"] + args + ["-o", str(out), "--format", "all", "--no-color", "-q"])
    data = json.loads((out / "findings.json").read_text(encoding="utf-8")) if (out / "findings.json").exists() else None
    return code, data, out


def titles(data, endpoint=None):
    return {(f["check_id"], f["title"]) for f in data["findings"] if endpoint is None or f["endpoint"] == endpoint}


def test_openapi_scan_finds_the_planted_issues(demo, example, tmp_path):
    code, data, _ = run([example("demo-openapi.yaml"), "--target", demo.base, "--auth-bearer", "demo-token", "--slow-ms", "200"], tmp_path)
    assert code == 0
    found = titles(data)
    for expected in [
        ("RAV-A01", "Protected endpoint answers without credentials"),
        ("RAV-C01", "CORS trusts any origin, with credentials"),
        ("RAV-D01", "Secret in response: Password field with a value"),
        ("RAV-E01", "Verbose error: Python stack trace"),
        ("RAV-V01", "Server error on invalid input"),
        ("RAV-H01", "Missing or weak security headers"),
        ("RAV-H02", "Server software and version disclosed"),
        ("RAV-M01", "TRACE method enabled"),
        ("RAV-M01", "Undocumented HTTP methods advertised"),
        ("RAV-V02", "JSON served as text/html"),
        ("RAV-V02", "Undocumented response status"),
        ("RAV-P01", "Slow response"),
        ("RAV-R01", "No rate-limit headers seen"),
    ]:
        assert expected in found, expected
    assert data["summary"]["grade"] == "D"


def test_correctly_built_endpoints_stay_clean(demo, example, tmp_path):
    _, data, _ = run([example("demo-openapi.yaml"), "--target", demo.base, "--auth-bearer", "demo-token"], tmp_path)
    # /orders enforces auth, /products validates input, /health sends good headers
    assert not any(f["check_id"] == "RAV-A01" for f in data["findings"] if f["endpoint"] == "GET /orders")
    assert not any(f["check_id"] == "RAV-V01" for f in data["findings"] if f["endpoint"] == "GET /products")
    assert not any(f["check_id"] == "RAV-H01" for f in data["findings"] if f["endpoint"] == "GET /health")


def test_safe_mode_never_sends_write_requests(demo, example, tmp_path):
    demo.seen.clear()
    _, data, _ = run([example("demo-openapi.yaml"), "--target", demo.base, "--auth-bearer", "demo-token"], tmp_path)
    methods = {m for m, _ in demo.seen}
    assert not methods & WRITE_METHODS, methods
    skipped = [e for e in data["endpoints"] if e["state"] == "skipped"]
    assert {(e["method"], e["path"]) for e in skipped} == {("POST", "/orders"), ("POST", "/login")}


def test_unsafe_mode_covers_write_endpoints(demo, example, tmp_path):
    _, data, _ = run([example("demo-openapi.yaml"), "--target", demo.base, "--auth-bearer", "demo-token", "--unsafe", "--yes"], tmp_path)
    login = titles(data, "POST /login")
    assert ("RAV-H03", "Cookie set without security flags") in login
    assert ("RAV-V01", "Request Content-Type not enforced") in login
    assert ("RAV-V01", "Server error on invalid input") in login  # missing required field crashes it
    assert all(e["state"] == "scanned" for e in data["endpoints"])


def test_quick_profile_is_passive(demo, example, tmp_path):
    demo.seen.clear()
    _, data, _ = run([example("demo-openapi.yaml"), "--target", demo.base, "--profile", "quick"], tmp_path)
    assert {m for m, _ in demo.seen} == {"GET"}
    assert len(demo.seen) == 6  # exactly one request per GET endpoint
    assert {f["check_id"] for f in data["findings"]} <= {"RAV-H01", "RAV-H02", "RAV-H03", "RAV-V02", "RAV-D01", "RAV-P01", "RAV-E01", "RAV-R01", "RAV-T01"}


@pytest.mark.parametrize("name,extra", [
    ("demo-swagger.json", []),
    ("demo.apib", []),
    ("demo.postman_collection.json", ["--postman-env"]),
    ("demo.har", []),
    ("demo-urls.txt", []),
])
def test_every_input_format_scans(demo, example, tmp_path, name, extra):
    args = [example(name), "--target", demo.base, "--auth-bearer", "demo-token"]
    if extra:
        args += [extra[0], example("demo.postman_environment.json")]
    code, data, _ = run(args, tmp_path)
    assert code == 0
    found = {t for _, t in titles(data)}
    assert "CORS trusts any origin, with credentials" in found
    assert "Secret in response: Password field with a value" in found
    assert data["summary"]["endpoints_scanned"] >= 5


def test_credentials_are_masked_and_secrets_never_copied(demo, example, tmp_path):
    _, _, out = run([example("demo-openapi.yaml"), "--target", demo.base, "--auth-bearer", "demo-token"], tmp_path)
    for f in os.listdir(out):
        text = (out / f).read_text(encoding="utf-8")
        assert "Bearer demo-token" not in text, f
        assert "demoHashNotARealPasswordHash" not in text, f
    _, _, out2 = run([example("demo-openapi.yaml"), "--target", demo.base, "--auth-bearer", "demo-token", "--no-redact"], tmp_path, "raw")
    assert "Bearer demo-token" in (out2 / "report.html").read_text(encoding="utf-8")


def test_secrets_scrubbed_even_when_detection_check_is_off(demo, example, tmp_path):
    _, _, out = run([example("demo-openapi.yaml"), "--target", demo.base, "--only", "RAV-H01",
                     "--api-key-query", "api_key=querysecret999"], tmp_path)
    for f in os.listdir(out):
        text = (out / f).read_text(encoding="utf-8")
        assert "demoHashNotARealPasswordHash" not in text, f
        assert "querysecret999" not in text, f


def test_html_report_escapes_untrusted_content(demo, tmp_path):
    spec = tmp_path / "evil.yaml"
    spec.write_text(
        "openapi: 3.0.0\ninfo: {title: '<script>alert(1)</script>', version: '1'}\n"
        f"servers: [{{url: '{demo.base}/api/v1'}}]\n"
        "paths:\n  /users/{id}:\n    get:\n      parameters: [{name: id, in: path, required: true, schema: {type: integer}, example: '<img src=x onerror=alert(1)>'}]\n"
        "      responses: {'200': {description: ok}}\n",
        encoding="utf-8",
    )
    _, _, out = run([str(spec)], tmp_path)
    html = (out / "report.html").read_text(encoding="utf-8")
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "<img src=x" not in html


def test_fail_on_sets_exit_code(demo, example, tmp_path):
    code, _, _ = run([example("demo-openapi.yaml"), "--target", demo.base, "--auth-bearer", "demo-token", "--fail-on", "high"], tmp_path)
    assert code == 1
    code, _, _ = run([example("demo-openapi.yaml"), "--target", demo.base, "--only", "RAV-H02", "--fail-on", "high"], tmp_path, "b")
    assert code == 0


def test_only_and_skip(demo, example, tmp_path):
    _, data, _ = run([example("demo-openapi.yaml"), "--target", demo.base, "--only", "RAV-C01,RAV-H02"], tmp_path)
    assert {f["check_id"] for f in data["findings"]} == {"RAV-C01", "RAV-H02"}
    _, data, _ = run([example("demo-openapi.yaml"), "--target", demo.base, "--skip", "RAV-H02,RAV-M01"], tmp_path, "b")
    assert not {"RAV-H02", "RAV-M01"} & {f["check_id"] for f in data["findings"]}


def test_include_exclude_methods(demo, example, tmp_path):
    _, data, _ = run([example("demo-openapi.yaml"), "--target", demo.base, "--include", "/users*", "--exclude", "/users/{id}"], tmp_path)
    assert [(e["method"], e["path"]) for e in data["endpoints"]] == [("GET", "/users")]
    _, data, _ = run([example("demo-openapi.yaml"), "--target", demo.base, "--methods", "POST"], tmp_path, "b")
    assert {e["method"] for e in data["endpoints"]} == {"POST"}


def test_values_file_is_used(demo, example, tmp_path):
    demo.seen.clear()
    run([example("demo-openapi.yaml"), "--target", demo.base, "--values", example("values.yaml"), "--only", "RAV-H01"], tmp_path)
    paths = [p for _, p in demo.seen]
    assert "/api/v1/users/2" in paths
    assert "/api/v1/products?category=games&limit=5" in paths


def test_token_file_logs_in(demo, tmp_path, monkeypatch, example):
    monkeypatch.setenv("DEMO_PASSWORD", "demo-password")
    token = tmp_path / "token.yaml"
    token.write_text(
        f"url: {demo.base}/api/v1/login\njson:\n  username: demo\n  password: ${{DEMO_PASSWORD}}\ntoken_field: token\n",
        encoding="utf-8",
    )
    _, data, _ = run([example("demo-openapi.yaml"), "--target", demo.base, "--token-file", str(token), "--include", "/orders"], tmp_path)
    orders = next(e for e in data["endpoints"] if e["method"] == "GET")
    assert orders["status"] == 200  # logged in with the token from /login


def test_max_requests_stops_cleanly(demo, example, tmp_path):
    code, data, out = run([example("demo-openapi.yaml"), "--target", demo.base, "--max-requests", "5"], tmp_path)
    assert code == 0
    assert data["summary"]["requests_sent"] == 5
    assert "--max-requests" in data["summary"]["stopped_reason"]
    assert (out / "report.html").exists()


def test_config_file(demo, example, tmp_path):
    cfg = tmp_path / "raven.yaml"
    cfg.write_text(f"source: {example('demo-openapi.yaml')}\ntarget: {demo.base}\nonly: [RAV-C01]\nfail-on: high\n", encoding="utf-8")
    out = tmp_path / "cfgout"
    code = main(["scan", "--config", str(cfg), "-o", str(out), "-q", "--no-color"])
    data = json.loads((out / "findings.json").read_text(encoding="utf-8"))
    assert code == 1  # fail-on from the file
    assert {f["check_id"] for f in data["findings"]} == {"RAV-C01"}


def test_sarif_is_well_formed(demo, example, tmp_path):
    _, _, out = run([example("demo-openapi.yaml"), "--target", demo.base], tmp_path)
    sarif = json.loads((out / "findings.sarif").read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"
    run0 = sarif["runs"][0]
    rule_ids = {r["id"] for r in run0["tool"]["driver"]["rules"]}
    assert run0["results"] and all(r["ruleId"] in rule_ids for r in run0["results"])
    assert all(r["level"] in ("error", "warning", "note") for r in run0["results"])
    for rule in run0["tool"]["driver"]["rules"]:
        if "security-severity" in rule.get("properties", {}):
            assert 0 < float(rule["properties"]["security-severity"]) <= 10


def test_broken_yaml_gives_clear_error(tmp_path, example, capsys):
    bad = tmp_path / "token.yaml"
    bad.write_text("url: [unclosed\n", encoding="utf-8")
    assert main(["scan", example("demo-openapi.yaml"), "--token-file", str(bad), "--no-color", "-q"]) == 2
    assert "YAML" in capsys.readouterr().err


def test_unreachable_target_does_not_crash(example, tmp_path):
    code, data, _ = run([example("demo-openapi.yaml"), "--target", "http://127.0.0.1:9", "--timeout", "2"], tmp_path)
    assert code == 0
    assert {e["state"] for e in data["endpoints"]} <= {"error", "skipped"}
