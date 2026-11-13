# Changelog

## 4.0.0 — November 2026

A complete, from-scratch open-source rewrite. No code from earlier versions is included.

**New**
- Input formats detected automatically from the content: OpenAPI 3.0/3.1, Swagger 2.0,
  Postman v2.0/v2.1 (with environments and `--var`), API Blueprint, HAR, URL lists and single URLs.
- 13 checks with severity, evidence, CWE, OWASP API Top 10 (2023) mapping and a plain-English fix.
- Safe by default: write requests (POST/PUT/PATCH/DELETE) only with `--unsafe`.
- Authentication: bearer, basic, API key (header or query), cookies, and an auto-refreshing token file.
- New HTML report: grade, severity filters, search, grouped findings, request/response evidence,
  coverage table, light/dark theme, works offline.
- JSON, SARIF (GitHub code scanning) and Markdown outputs; `--fail-on` exit codes for CI.
- Credentials are masked in every report, including when a server echoes them back.
- Runs on Windows, macOS and Linux; Python 3.9+; only two dependencies.
- Bundled practice API (`raven demo`) and examples in every input format.
- Test suite and GitHub Actions workflow.

**Removed compared with the 2021 tool**
- Excel spreadsheets as an intermediate format and the dependency on the NIST ACTS Java tool.
- Windows-only file paths.
- Functional checks that are not security checks (idempotency, HATEOAS links, Accept-Encoding).

## 2021–2022 — original tool

RAVEN started as a Python CLI I built during my application security internship to
automate repetitive REST API security checks. That version was internal and is not published here.
