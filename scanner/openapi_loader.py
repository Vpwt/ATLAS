"""Parses an OpenAPI 3.x / Swagger 2.0 spec into scanner Endpoint objects.

This gives you automatic endpoint discovery instead of hand-listing every
path in config.yaml. Path/query parameters get best-effort placeholder
values (and request bodies get example payloads) so requests are
well-formed out of the box.

BOLA testing still needs a bit of manual input: the spec has no concept of
"an ID my test account owns" vs. "an ID belonging to someone else", so you'll
typically still declare `sample_ids` / `foreign_ids` (and optionally
`id_param`) for specific endpoints under `endpoints:` in config.yaml. Those
entries are merged onto the discovered endpoints - see
`scanner.config_loader.load_config`.
"""
import json
import os
from typing import Any, Optional

import requests
import yaml

from scanner.models import Endpoint

_HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}


def load_spec(source: str) -> dict:
    """Load an OpenAPI/Swagger spec from a local file path or an http(s) URL."""
    if source.startswith("http://") or source.startswith("https://"):
        resp = requests.get(source, timeout=15)
        resp.raise_for_status()
        text = resp.text
    else:
        if not os.path.exists(source):
            raise FileNotFoundError(f"OpenAPI spec not found: {source}")
        with open(source, "r", encoding="utf-8") as f:
            text = f.read()

    stripped = text.lstrip()
    if stripped.startswith("{"):
        return json.loads(text)
    return yaml.safe_load(text)


def _resolve_ref(spec: dict, ref: str) -> Any:
    """Resolve a local '#/components/schemas/Foo' style $ref."""
    if not isinstance(ref, str) or not ref.startswith("#/"):
        return {}
    node: Any = spec
    for part in ref[2:].split("/"):
        node = node.get(part, {}) if isinstance(node, dict) else {}
    return node


def _example_value_for_schema(spec: dict, schema: dict, _depth: int = 0) -> Any:
    """Best-effort placeholder value generation from a JSON schema fragment."""
    if _depth > 5 or not isinstance(schema, dict):
        return "test"
    if "$ref" in schema:
        return _example_value_for_schema(spec, _resolve_ref(spec, schema["$ref"]), _depth + 1)
    if "example" in schema:
        return schema["example"]
    if "default" in schema:
        return schema["default"]
    if schema.get("enum"):
        return schema["enum"][0]

    # allOf: schema composition - merge every subschema's example together
    # (this is how OpenAPI expresses "inherits from" / mixins).
    if schema.get("allOf"):
        merged: Any = {}
        for sub in schema["allOf"]:
            sub_resolved = _resolve_ref(spec, sub["$ref"]) if isinstance(sub, dict) and "$ref" in sub else sub
            value = _example_value_for_schema(spec, sub_resolved, _depth + 1)
            if isinstance(value, dict) and isinstance(merged, dict):
                merged.update(value)
            elif not merged:
                merged = value
        return merged

    # oneOf/anyOf: schema is exactly one of / any of several alternatives -
    # best-effort, just use the first alternative as a representative example.
    for key in ("oneOf", "anyOf"):
        if schema.get(key):
            first = schema[key][0]
            first_resolved = _resolve_ref(spec, first["$ref"]) if isinstance(first, dict) and "$ref" in first else first
            return _example_value_for_schema(spec, first_resolved, _depth + 1)

    schema_type = schema.get("type")
    if schema_type == "object" or "properties" in schema:
        return {
            name: _example_value_for_schema(spec, prop, _depth + 1)
            for name, prop in schema.get("properties", {}).items()
        }
    if schema_type == "array":
        return [_example_value_for_schema(spec, schema.get("items", {}), _depth + 1)]
    if schema_type == "integer":
        return 1
    if schema_type == "number":
        return 1.0
    if schema_type == "boolean":
        return True
    if schema_type == "string":
        fmt = schema.get("format")
        if fmt == "email":
            return "test@example.com"
        if fmt in ("date", "date-time"):
            return "2026-01-01"
        return "test"
    return "test"


def _pick_content_entry(content: dict) -> Optional[dict]:
    """Picks which media-type entry in a `content:` map to derive an example
    body from. Prefers JSON media types (including '+json' suffixes like
    'application/vnd.api+json'), then form-encoded media types (whose fields
    are still expressible as a flat key/value dict), then falls back to
    whatever's listed first so unusual/custom media types still get a
    best-effort example instead of being skipped entirely."""
    if not content:
        return None
    for name, entry in content.items():
        if name == "application/json" or name.endswith("+json"):
            return entry
    for name, entry in content.items():
        if name in ("application/x-www-form-urlencoded", "multipart/form-data"):
            return entry
    return next(iter(content.values()), None)


def _request_body_example(spec: dict, operation: dict) -> tuple[Optional[dict], str]:
    """Best-effort body example + content type for an operation.

    Returns (body_dict_or_none, content_type). Content type defaults to
    application/json when no request body exists.
    """
    request_body = operation.get("requestBody")
    if isinstance(request_body, dict) and "$ref" in request_body:
        request_body = _resolve_ref(spec, request_body["$ref"])
    if not isinstance(request_body, dict):
        return None, "application/json"

    content = request_body.get("content", {})
    picked_name = None
    picked_entry = None
    if content:
        for name, entry in content.items():
            if name == "application/json" or name.endswith("+json"):
                picked_name, picked_entry = name, entry
                break
        if picked_entry is None:
            for name, entry in content.items():
                if name in ("application/x-www-form-urlencoded", "multipart/form-data"):
                    picked_name, picked_entry = name, entry
                    break
        if picked_entry is None:
            picked_name, picked_entry = next(iter(content.items()))

    json_content = picked_entry
    if not isinstance(json_content, dict):
        return None, (picked_name or "application/json")

    if "example" in json_content:
        value = json_content["example"]
        return (value if isinstance(value, dict) else None), (picked_name or "application/json")
    examples = json_content.get("examples")
    if isinstance(examples, dict) and examples:
        first = next(iter(examples.values()))
        if isinstance(first, dict) and "value" in first:
            value = first["value"]
            return (value if isinstance(value, dict) else None), (picked_name or "application/json")

    schema = json_content.get("schema")
    if schema:
        value = _example_value_for_schema(spec, schema)
        return (value if isinstance(value, dict) else None), (picked_name or "application/json")
    return None, (picked_name or "application/json")


def _operation_requires_auth(spec: dict, operation: dict) -> bool:
    """Mirror OpenAPI's `security` semantics: missing => inherit/assume public,
    empty list => explicitly no auth, non-empty list => auth required."""
    security = operation.get("security", spec.get("security"))
    if not security:
        return False
    return True


def _collect_parameters(spec: dict, operation: dict, path_item: dict) -> list:
    params = []
    for p in list(path_item.get("parameters", [])) + list(operation.get("parameters", [])):
        if isinstance(p, dict) and "$ref" in p:
            p = _resolve_ref(spec, p["$ref"])
        if isinstance(p, dict):
            params.append(p)
    return params


def load_endpoints_from_spec(source: str) -> list:
    """Parse an OpenAPI 3.x / Swagger 2.0 spec into a list of Endpoint objects."""
    spec = load_spec(source)
    paths = spec.get("paths", {}) or {}
    endpoints = []

    for raw_path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        for method, operation in path_item.items():
            method_lower = method.lower()
            if method_lower not in _HTTP_METHODS or not isinstance(operation, dict):
                continue

            params = {}
            id_param = None
            for p in _collect_parameters(spec, operation, path_item):
                name = p.get("name")
                location = p.get("in")
                if not name or location not in ("path", "query"):
                    continue
                schema = p.get("schema", {})
                params[name] = _example_value_for_schema(spec, schema) if schema else "test"
                if location == "path" and id_param is None and "id" in name.lower():
                    id_param = name

            tags = [str(t).lower() for t in operation.get("tags", [])]
            admin_only = "admin" in raw_path.lower() or "admin" in tags

            body_example, body_content_type = _request_body_example(spec, operation)
            endpoints.append(Endpoint(
                path=raw_path,
                method=method_lower.upper(),
                auth_required=_operation_requires_auth(spec, operation),
                params=params,
                body=body_example,
                body_content_type=body_content_type,
                id_param=id_param,
                sample_ids=[],
                foreign_ids=[],
                admin_only=admin_only,
                description=operation.get("summary") or operation.get("operationId") or "",
            ))

    return endpoints
