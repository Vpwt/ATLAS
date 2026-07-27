"""Reverse-proxy capture mode for auto-generating scan config from traffic."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit


@dataclass
class CapturedRequest:
    method: str
    path: str
    params: dict = field(default_factory=dict)
    body: dict | None = None
    auth_header: str = ""
    cookies: str = ""


def _safe_json(data: bytes):
    if not data:
        return None
    try:
        return json.loads(data.decode("utf-8", errors="ignore"))
    except Exception:
        return None


def _as_params(path: str) -> dict:
    q = urlsplit(path).query
    parsed = parse_qs(q)
    return {k: (v[0] if len(v) == 1 else v) for k, v in parsed.items()}


def run_proxy_capture(
    listen_host: str,
    listen_port: int,
    upstream_base_url: str,
    output_config_path: str,
) -> None:
    import httpx  # pyright: ignore[reportMissingImports]
    import yaml  # pyright: ignore[reportMissingImports,reportMissingModuleSource]

    captured: dict[tuple[str, str], CapturedRequest] = {}
    upstream_base = upstream_base_url.rstrip("/")

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            self._handle()

        def do_POST(self):
            self._handle()

        def do_PUT(self):
            self._handle()

        def do_PATCH(self):
            self._handle()

        def do_DELETE(self):
            self._handle()

        def do_OPTIONS(self):
            self._handle()

        def _handle(self):
            content_len = int(self.headers.get("Content-Length", "0") or "0")
            raw_body = self.rfile.read(content_len) if content_len > 0 else b""
            body_json = _safe_json(raw_body)

            parsed = urlsplit(self.path)
            endpoint_path = parsed.path or "/"
            key = (self.command.upper(), endpoint_path)
            captured[key] = CapturedRequest(
                method=self.command.upper(),
                path=endpoint_path,
                params=_as_params(self.path),
                body=body_json,
                auth_header=self.headers.get("Authorization", ""),
                cookies=self.headers.get("Cookie", ""),
            )

            out_headers = {}
            for k, v in self.headers.items():
                lk = k.lower()
                if lk in {"host", "content-length", "connection"}:
                    continue
                out_headers[k] = v

            target_url = f"{upstream_base}{self.path}"
            try:
                resp = httpx.request(
                    self.command.upper(),
                    target_url,
                    headers=out_headers,
                    content=raw_body if raw_body else None,
                    timeout=30.0,
                    follow_redirects=False,
                )
                payload = resp.content or b""
                self.send_response(resp.status_code)
                for k, v in resp.headers.items():
                    if k.lower() in {"content-length", "transfer-encoding", "connection"}:
                        continue
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                if payload:
                    self.wfile.write(payload)
            except Exception as e:
                data = json.dumps({"error": str(e)}).encode("utf-8")
                self.send_response(502)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        def log_message(self, format, *args):
            return

    server = ThreadingHTTPServer((listen_host, listen_port), Handler)
    print(f"Proxy capture mode listening on http://{listen_host}:{listen_port} -> {upstream_base_url}")
    print("Press Ctrl+C to stop and write captured config.")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()

    endpoints = []
    auth_header = ""
    for req in captured.values():
        if req.auth_header and not auth_header:
            auth_header = req.auth_header
        endpoints.append({
            "path": req.path,
            "method": req.method,
            "auth_required": bool(req.auth_header),
            "params": req.params or {},
            "body": req.body,
            "description": "Captured via proxy mode",
        })

    config = {
        "base_url": upstream_base_url,
        "auth_header": auth_header,
        "request_delay": 0.1,
        "rate_limit_burst": 25,
        "verify_tls": True,
        "endpoints": sorted(endpoints, key=lambda e: (e["path"], e["method"])),
    }

    with open(output_config_path, "w", encoding="utf-8") as f:
        yaml.safe_dump(config, f, sort_keys=False)

    print(f"Captured {len(endpoints)} endpoint(s). Wrote generated config to {output_config_path}")
