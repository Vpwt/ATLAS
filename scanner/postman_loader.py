"""Loads endpoints from a Postman Collection (v2.0/v2.1 export), local file or URL.

Complements openapi_loader.py for teams that document their API as a Postman
collection instead of (or in addition to) an OpenAPI spec.
"""
import json
import os
import re
import requests

from scanner.models import Endpoint

_VAR_RE = re.compile(r"{{\s*([\w.-]+)\s*}}")
_SCHEME_HOST_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://[^/]+(/.*)?$")


def _load_collection(source: str) -> dict:
    if source.startswith("http://") or source.startswith("https://"):
        resp = requests.get(source, timeout=15)
        resp.raise_for_status()
        return resp.json()
    if not os.path.exists(source):
        raise FileNotFoundError(f"Postman collection not found: {source}")
    with open(source, "r", encoding="utf-8") as f:
        return json.load(f)


def _substitute_vars(text: str, variables: dict) -> str:
    return _VAR_RE.sub(lambda m: str(variables.get(m.group(1), m.group(0))), text)


def _url_to_path(url_obj, variables: dict) -> str:
    raw = url_obj if isinstance(url_obj, str) else (url_obj or {}).get("raw", "")
    raw = _substitute_vars(raw, variables)
    m = _SCHEME_HOST_RE.match(raw)
    path = m.group(1) if (m and m.group(1)) else raw
    path = path.split("?")[0]
    if not path.startswith("/"):
        path = "/" + path
    return path


def _query_params(url_obj) -> dict:
    if not isinstance(url_obj, dict):
        return {}
    return {q.get("key"): q.get("value") for q in url_obj.get("query", []) or [] if q.get("key")}


def _body_to_dict(body_obj):
    if not isinstance(body_obj, dict):
        return None
    mode = body_obj.get("mode")
    if mode == "raw":
        try:
            return json.loads(body_obj.get("raw", ""))
        except (ValueError, TypeError):
            return None
    if mode == "urlencoded":
        return {kv.get("key"): kv.get("value") for kv in body_obj.get("urlencoded", []) or [] if kv.get("key")}
    return None


def _is_no_auth(request: dict, item: dict) -> bool:
    auth_obj = request.get("auth") or item.get("auth")
    return isinstance(auth_obj, dict) and auth_obj.get("type") == "noauth"


def _walk_items(items, variables: dict, endpoints: list):
    for item in items or []:
        if "item" in item:  # folder - recurse
            _walk_items(item["item"], variables, endpoints)
            continue

        request = item.get("request")
        if not isinstance(request, dict):
            continue

        url_obj = request.get("url", "")
        body = _body_to_dict(request.get("body"))
        endpoints.append(Endpoint(
            path=_url_to_path(url_obj, variables),
            method=(request.get("method") or "GET").upper(),
            auth_required=not _is_no_auth(request, item),
            params=_query_params(url_obj),
            body=body,
            description=item.get("name", ""),
        ))


def load_endpoints_from_postman(source: str) -> list:
    """Parse a Postman Collection export into a list of Endpoint objects."""
    collection = _load_collection(source)
    variables = {
        v.get("key"): v.get("value")
        for v in collection.get("variable", []) or []
        if v.get("key")
    }
    endpoints = []
    _walk_items(collection.get("item", []) or [], variables, endpoints)
    return endpoints
