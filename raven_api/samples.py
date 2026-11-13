"""Turn a JSON schema (or a parameter) into a realistic example value."""

from __future__ import annotations

from typing import Any, Dict, Optional

from raven_api.models import Param

_FORMAT_EXAMPLES = {
    "email": "raven.test@example.com",
    "uuid": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    "date": "2024-01-15",
    "date-time": "2024-01-15T10:30:00Z",
    "uri": "https://example.com",
    "url": "https://example.com",
    "hostname": "example.com",
    "ipv4": "192.0.2.10",
    "ipv6": "2001:db8::10",
    "password": "RavenTest#2026",
    "byte": "cmF2ZW4=",
    "binary": "raven",
}

_NAME_HINTS = (
    ("email", "raven.test@example.com"),
    ("mail", "raven.test@example.com"),
    ("phone", "+490000000000"),
    ("url", "https://example.com"),
    ("uuid", "3fa85f64-5717-4562-b3fc-2c963f66afa6"),
    ("date", "2024-01-15"),
    ("name", "raven"),
    ("country", "DE"),
    ("lang", "en"),
    ("currency", "EUR"),
)


def example_from_schema(schema: Optional[Dict[str, Any]], name: str = "", depth: int = 0) -> Any:
    """Return an example value for a schema, preferring examples written in the spec."""
    if not isinstance(schema, dict):
        return "raven"
    if depth > 6:
        return None
    for key in ("example", "default"):
        if key in schema:
            return schema[key]
    if isinstance(schema.get("examples"), list) and schema["examples"]:
        return schema["examples"][0]
    if schema.get("enum"):
        return schema["enum"][0]
    if "const" in schema:
        return schema["const"]

    for combo in ("allOf", "oneOf", "anyOf"):
        parts = schema.get(combo)
        if isinstance(parts, list) and parts:
            if combo == "allOf":
                merged: Dict[str, Any] = {}
                for part in parts:
                    value = example_from_schema(part, name, depth + 1)
                    if isinstance(value, dict):
                        merged.update(value)
                if merged:
                    return merged
            return example_from_schema(parts[0], name, depth + 1)

    t = schema.get("type")
    if isinstance(t, list):
        t = next((x for x in t if x != "null"), None)
    if t is None:
        if "properties" in schema:
            t = "object"
        elif "items" in schema:
            t = "array"
        else:
            t = "string"

    if t == "object":
        props = schema.get("properties") or {}
        return {k: example_from_schema(v, k, depth + 1) for k, v in props.items()}
    if t == "array":
        return [example_from_schema(schema.get("items") or {}, name, depth + 1)]
    if t == "integer":
        low = schema.get("minimum")
        return int(low) if isinstance(low, (int, float)) and low > 1 else 1
    if t == "number":
        low = schema.get("minimum")
        return float(low) if isinstance(low, (int, float)) and low > 1 else 1.5
    if t == "boolean":
        return True
    fmt = schema.get("format")
    if fmt in _FORMAT_EXAMPLES:
        return _FORMAT_EXAMPLES[fmt]
    lowered = name.lower()
    for hint, value in _NAME_HINTS:
        if hint in lowered:
            return value
    min_len = schema.get("minLength")
    if isinstance(min_len, int) and min_len > 5:
        return "r" * min_len
    return "raven"


def value_for_param(param: Param, overrides: Optional[Dict[str, Any]] = None) -> Any:
    """Pick the value RAVEN sends for a parameter.

    Order: user values file > example in the description > generated from the type.
    """
    overrides = overrides or {}
    for key in (f"{param.location}.{param.name}", param.name):
        if key in overrides:
            value = overrides[key]
            return value[0] if isinstance(value, list) and value else value
    if param.example is not None:
        return param.example
    return example_from_schema(param.schema, param.name)
