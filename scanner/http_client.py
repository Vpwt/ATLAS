"""Thin wrapper around requests that adds timeouts, logging, and safety rails."""
import json
import shlex
import time
from urllib.parse import urlencode
import requests
from typing import Any, Callable, Optional


def build_curl(method: str, url: str, headers: Optional[dict] = None,
                params: Optional[dict] = None, json_body: Optional[dict] = None,
                body_content_type: str = "application/json") -> str:
    """Builds a copy-pasteable curl command reproducing a request, for PoC/repro
    steps in findings. Purely for display - never executed by this tool."""
    parts = ["curl", "-i", "-X", method.upper()]
    for key, value in (headers or {}).items():
        parts += ["-H", shlex.quote(f"{key}: {value}")]
    if json_body is not None:
        ctype = (body_content_type or "application/json").lower()
        if ctype and "content-type" not in {k.lower() for k in (headers or {}).keys()} and ctype != "multipart/form-data":
            parts += ["-H", shlex.quote(f"Content-Type: {body_content_type}")]
        if ctype == "application/x-www-form-urlencoded" and isinstance(json_body, dict):
            parts += ["--data", shlex.quote(urlencode(json_body))]
        else:
            payload = json_body if isinstance(json_body, str) else json.dumps(json_body)
            parts += ["-d", shlex.quote(payload)]

    full_url = url
    if params:
        sep = "&" if "?" in url else "?"
        full_url = f"{url}{sep}{urlencode(params)}"
    parts.append(shlex.quote(full_url))
    return " ".join(parts)


class ApiClient:
    def __init__(self, base_url: str, default_headers: Optional[dict] = None,
                 timeout: float = 10.0, verify_tls: bool = True, request_delay: float = 0.0,
                 auth_provider: Optional[Callable[[], str]] = None):
        self.base_url = base_url.rstrip("/")
        self.default_headers = default_headers or {}
        self.timeout = timeout
        self.verify_tls = verify_tls
        self.request_delay = request_delay  # politeness delay between requests, seconds
        # Optional callable returning a fresh "Bearer ..." string, used instead of
        # (or as a refreshed version of) default_headers["Authorization"] - lets a
        # long scan re-login/refresh a short-lived access token mid-run.
        self.auth_provider = auth_provider
        self.request_count = 0

    def request(self, method: str, path: str, headers: Optional[dict] = None,
                params: Optional[dict] = None, json_body: Optional[dict] = None,
                auth_override: Optional[str] = "keep",
                body_content_type: str = "application/json") -> requests.Response:
        """
        auth_override:
          "keep"  -> use default_headers as-is (includes auth if configured)
          "strip" -> remove Authorization header (test unauthenticated access)
          None    -> no headers at all
        """
        url = f"{self.base_url}{path}"
        merged_headers = dict(self.default_headers)
        if self.auth_provider and auth_override == "keep":
            try:
                merged_headers["Authorization"] = self.auth_provider()
            except Exception:
                pass
        if headers:
            merged_headers.update(headers)

        if auth_override == "strip":
            merged_headers.pop("Authorization", None)
            merged_headers.pop("authorization", None)
        elif auth_override is None:
            merged_headers = {}

        if self.request_delay:
            time.sleep(self.request_delay)

        self.request_count += 1
        request_kwargs: dict[str, Any] = {
            "method": method.upper(),
            "url": url,
            "headers": merged_headers,
            "params": params,
            "timeout": self.timeout,
            "verify": self.verify_tls,
        }

        ctype = (body_content_type or "application/json").lower()
        if json_body is not None:
            if ctype == "application/x-www-form-urlencoded":
                request_kwargs["data"] = json_body
                request_kwargs["headers"].setdefault("Content-Type", "application/x-www-form-urlencoded")
            elif ctype == "multipart/form-data":
                # Let requests set the multipart boundary/header automatically.
                request_kwargs["files"] = {k: (None, str(v)) for k, v in (json_body or {}).items()}
            elif ctype == "application/json" or ctype.endswith("+json"):
                request_kwargs["json"] = json_body
            else:
                if isinstance(json_body, str):
                    request_kwargs["data"] = json_body
                else:
                    request_kwargs["data"] = json.dumps(json_body)
                request_kwargs["headers"].setdefault("Content-Type", body_content_type)

        resp = requests.request(
            **request_kwargs,
        )
        # Attach a ready-to-run curl reproduction to every response so check
        # modules can optionally surface it as PoC evidence on a Finding.
        resp.curl_repro = build_curl(method, url, merged_headers, params, json_body, body_content_type)
        return resp
