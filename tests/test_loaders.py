"""Every input format must turn into the same, correct list of endpoints."""

import json
import shutil

import pytest

from raven_api.loaders import SpecError, load_spec
from raven_api.client import build_request

DEMO_KEYS = {
    "GET /health", "GET /products", "GET /users", "GET /users/{id}",
    "GET /orders", "POST /orders", "POST /login", "GET /reports/daily",
}


def keys(spec, strip=""):
    return {f"{e.method} {e.path.replace(strip, '', 1)}" for e in spec.endpoints}


@pytest.mark.parametrize("name,kind", [
    ("demo-openapi.yaml", "openapi3"),
    ("demo-swagger.json", "swagger2"),
    ("demo.apib", "blueprint"),
])
def test_spec_formats_give_same_endpoints(example, name, kind):
    spec = load_spec(example(name))
    assert spec.source_type == kind
    assert keys(spec) == DEMO_KEYS
    assert {e.base_url for e in spec.endpoints} == {"http://127.0.0.1:8088/api/v1"}


def test_postman_with_environment(example):
    spec = load_spec(example("demo.postman_collection.json"), postman_env=example("demo.postman_environment.json"))
    assert spec.source_type == "postman"
    assert keys(spec, "/api/v1") == DEMO_KEYS
    users = next(e for e in spec.endpoints if e.path == "/api/v1/users/{id}")
    assert users.headers["Authorization"] == "Bearer demo-token"  # inherited collection auth
    assert users.auth_required is True
    login = next(e for e in spec.endpoints if e.path == "/api/v1/login")
    assert login.auth_required is None and "Authorization" not in login.headers  # folder says noauth
    assert login.body == {"username": "demo", "password": "demo-password"}
    assert build_request(users).url.endswith("/api/v1/users/1")  # :id variable value


def test_postman_unresolved_variable_warns(example):
    spec = load_spec(example("demo.postman_collection.json"))  # no environment: {{token}} unknown
    assert any("token" in w for w in spec.warnings)


def test_postman_var_flag_overrides(example):
    spec = load_spec(example("demo.postman_collection.json"), variables={"baseUrl": "https://staging.example.com/v9"})
    assert {e.base_url for e in spec.endpoints} == {"https://staging.example.com"}
    assert all(e.path.startswith("/v9/") for e in spec.endpoints)


def test_har_skips_static_and_keeps_auth(example):
    spec = load_spec(example("demo.har"))
    assert spec.source_type == "har"
    assert len(spec.endpoints) == 6
    assert not any(e.path.endswith(".js") for e in spec.endpoints)
    users = next(e for e in spec.endpoints if e.path == "/api/v1/users")
    assert users.auth_required and users.headers["Authorization"] == "Bearer demo-token"
    assert "Host" not in users.headers and "User-Agent" not in users.headers


def test_url_list(example):
    spec = load_spec(example("demo-urls.txt"))
    assert spec.source_type == "urls"
    assert len(spec.endpoints) == 5
    products = next(e for e in spec.endpoints if e.path.endswith("/products"))
    assert {(p.name, p.example) for p in products.params} == {("category", "books"), ("limit", "10")}


def test_blueprint_details(example):
    spec = load_spec(example("demo.apib"))
    products = next(e for e in spec.endpoints if e.path == "/products")
    limit = next(p for p in products.params if p.name == "limit")
    assert limit.location == "query" and limit.example == 10 and limit.schema["type"] == "number"
    user = next(e for e in spec.endpoints if e.path == "/users/{id}")
    assert user.params[0].location == "path" and user.params[0].example == 1
    order = next(e for e in spec.endpoints if e.key == "POST /orders")
    assert order.body == {"product_id": 7, "quantity": 1}
    assert order.auth_required is True
    login = next(e for e in spec.endpoints if e.key == "POST /login")
    assert login.body == {"username": "demo", "password": "demo-password"}
    assert "200" in login.expected_status


def test_openapi_details(example):
    spec = load_spec(example("demo-openapi.yaml"))
    products = next(e for e in spec.endpoints if e.path == "/products")
    assert products.auth_required is False
    assert build_request(products).params == [("category", "books"), ("limit", "10")]
    login = next(e for e in spec.endpoints if e.key == "POST /login")
    assert login.body == {"username": "demo", "password": "demo-password"}
    assert login.body_schema["required"] == ["username", "password"]


def test_detection_ignores_file_extension(example, tmp_path):
    copy = tmp_path / "spec.txt"
    shutil.copy(example("demo-swagger.json"), copy)
    assert load_spec(str(copy)).source_type == "swagger2"


def test_target_keeps_base_path_unless_given(example):
    spec = load_spec(example("demo-openapi.yaml"), base_url="https://staging.example.com")
    assert spec.endpoints[0].base_url == "https://staging.example.com/api/v1"
    spec = load_spec(example("demo-openapi.yaml"), base_url="https://staging.example.com/v2")
    assert spec.endpoints[0].base_url == "https://staging.example.com/v2"


def test_missing_server_asks_for_target(tmp_path):
    f = tmp_path / "api.yaml"
    f.write_text("openapi: 3.0.0\ninfo: {title: t, version: '1'}\npaths:\n  /a:\n    get: {responses: {'200': {description: ok}}}\n", encoding="utf-8")
    with pytest.raises(SpecError, match="--target"):
        load_spec(str(f))
    assert load_spec(str(f), base_url="http://localhost:9").endpoints[0].base_url == "http://localhost:9"


def test_recursive_refs_and_openapi31_types(tmp_path):
    spec = {
        "openapi": "3.1.0",
        "info": {"title": "t", "version": "1"},
        "servers": [{"url": "https://{env}.example.com", "variables": {"env": {"default": "api"}}}],
        "paths": {"/nodes/{id}": {"get": {
            "parameters": [{"name": "id", "in": "path", "required": True, "schema": {"type": ["integer", "null"]}}],
            "responses": {"200": {"description": "ok", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Node"}}}}},
        }}},
        "components": {"schemas": {"Node": {"type": "object", "properties": {"child": {"$ref": "#/components/schemas/Node"}}}}},
    }
    f = tmp_path / "api.json"
    f.write_text(json.dumps(spec), encoding="utf-8")
    loaded = load_spec(str(f))
    ep = loaded.endpoints[0]
    assert ep.base_url == "https://api.example.com"
    assert ep.params[0].type == "integer"
    assert build_request(ep).url == "https://api.example.com/nodes/1"


def test_garbage_input_is_rejected(tmp_path):
    f = tmp_path / "notes.txt"
    f.write_text("hello, this is not an API description\nsecond line\n", encoding="utf-8")
    with pytest.raises(SpecError, match="Could not recognise"):
        load_spec(str(f))
    with pytest.raises(SpecError, match="not found"):
        load_spec(str(tmp_path / "missing.yaml"))
