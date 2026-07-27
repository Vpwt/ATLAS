"""Thin wrapper around requests that adds timeouts, logging, and safety rails."""
import json
import shlex
import time
from urllib.parse import urlencode
import requests
from typing import Callable, Optional


def build_curl(method: str, url: str, headers: Optional[dict] = None,
                params: Optional[dict] = None, json_body: Optional[dict] = None) -> str:
    """Builds a copy-pasteable curl command reproducing a request, for PoC/repro
    steps in findings. Purely for display - never executed by this tool."""
    parts = ["curl", "-i", "-X", method.upper()]
    for key, value in (headers or {}).items():
        parts += ["-H", shlex.quote(f"{key}: {value}")]
    if json_body is not None:
        parts += ["-H", shlex.quote("Content-Type: application/json")]
        parts += ["-d", shlex.quote(json.dumps(json_body))]

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
                auth_override: Optional[str] = "keep") -> requests.Response:
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
        resp = requests.request(
            method=method.upper(),
            url=url,
            headers=merged_headers,
            params=params,
            json=json_body,
            timeout=self.timeout,
            verify=self.verify_tls,
        )
        # Attach a ready-to-run curl reproduction to every response so check
        # modules can optionally surface it as PoC evidence on a Finding.
        resp.curl_repro = build_curl(method, url, merged_headers, params, json_body)
        return resp
