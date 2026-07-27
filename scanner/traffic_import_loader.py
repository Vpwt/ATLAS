"""Traffic export importers for HAR/Burp/ZAP/mitmproxy/Chrome traces."""
from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlsplit, parse_qs

from scanner.models import Endpoint


def _read_json(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _params_from_url(url: str) -> dict:
    parsed = urlsplit(url)
    q = parse_qs(parsed.query)
    return {k: (v[0] if len(v) == 1 else v) for k, v in q.items()}


def _endpoint_key(ep: Endpoint) -> tuple[str, str]:
    return (ep.method.upper(), ep.path)


def _merge(endpoints: list[Endpoint]) -> list[Endpoint]:
    out: dict[tuple[str, str], Endpoint] = {}
    for ep in endpoints:
        key = _endpoint_key(ep)
        if key not in out:
            out[key] = ep
            continue
        cur = out[key]
        if not cur.body and ep.body:
            cur.body = ep.body
        if ep.params:
            cur.params.update(ep.params)
        cur.auth_required = cur.auth_required or ep.auth_required
    return sorted(out.values(), key=lambda e: (e.path, e.method))


def load_endpoints_from_har(path: str) -> list[Endpoint]:
    data = _read_json(path)
    entries = (data.get("log") or {}).get("entries") or []
    eps: list[Endpoint] = []
    for e in entries:
        req = e.get("request") or {}
        url = req.get("url", "")
        if not url:
            continue
        parsed = urlsplit(url)
        method = (req.get("method") or "GET").upper()
        body = None
        post = req.get("postData") or {}
        txt = post.get("text")
        if txt:
            try:
                body = json.loads(txt)
            except Exception:
                body = None

        hdrs = {h.get("name", "").lower(): h.get("value", "") for h in req.get("headers", [])}
        auth_required = bool(hdrs.get("authorization") or hdrs.get("cookie"))

        eps.append(Endpoint(
            path=parsed.path or "/",
            method=method,
            auth_required=auth_required,
            params=_params_from_url(url),
            body=body,
            description="Imported from HAR traffic",
        ))
    return _merge(eps)


def load_endpoints_from_burp_or_zap_json(path: str) -> list[Endpoint]:
    data = _read_json(path)
    # Accept common list-based exports where each item has method + url/path.
    rows = data if isinstance(data, list) else data.get("requests") or data.get("items") or []
    eps: list[Endpoint] = []
    for r in rows:
        method = (r.get("method") or "GET").upper()
        url = r.get("url") or r.get("fullUrl") or ""
        path_val = r.get("path") or ""
        if url:
            parsed = urlsplit(url)
            path = parsed.path or "/"
            params = _params_from_url(url)
        elif path_val:
            path = path_val
            params = r.get("params") or {}
        else:
            continue
        body = r.get("body") if isinstance(r.get("body"), dict) else None
        auth_required = bool(r.get("auth") or r.get("authorization") or r.get("cookie"))
        eps.append(Endpoint(
            path=path,
            method=method,
            auth_required=auth_required,
            params=params,
            body=body,
            description="Imported from traffic export",
        ))
    return _merge(eps)


def load_endpoints_from_traffic_export(path: str) -> list[Endpoint]:
    suffix = Path(path).suffix.lower()
    if suffix == ".har":
        return load_endpoints_from_har(path)
    return load_endpoints_from_burp_or_zap_json(path)
