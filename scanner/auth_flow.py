"""Automated login / OAuth2-style token acquisition.

Lets you configure a login request once instead of pasting a fresh bearer
token into config.yaml by hand every run, and optionally re-fetch it
periodically for long scans against APIs with short-lived access tokens.
"""
import time
import requests


def acquire_token(base_url: str, login_config: dict, verify_tls: bool = True, timeout: float = 10.0) -> str:
    """Performs a single login request per `login_config` and extracts a
    bearer token from the JSON response.

    login_config fields:
      url: "/api/auth/login"       # relative to base_url, or absolute
      method: "POST"                # default POST
      body: {...}                   # e.g. {username, password} or an OAuth2
                                     # client_credentials/password grant body
      headers: {...}                # optional extra headers for the login request
      token_field: "access_token"   # dot-path into the JSON response, e.g. "data.token"
      header_prefix: "Bearer"       # default "Bearer"

    Returns a ready-to-use header value, e.g. "Bearer eyJhbGciOi...".
    """
    url = login_config["url"]
    if not url.startswith("http"):
        url = f"{base_url.rstrip('/')}{url}"
    method = login_config.get("method", "POST").upper()

    resp = requests.request(
        method, url,
        json=login_config.get("body", {}),
        headers=login_config.get("headers"),
        timeout=timeout,
        verify=verify_tls,
    )
    resp.raise_for_status()
    data = resp.json()

    token_field = login_config.get("token_field", "access_token")
    value = data
    for part in token_field.split("."):
        if not isinstance(value, dict):
            value = None
            break
        value = value.get(part)

    if not value:
        raise ValueError(f"Login succeeded but could not find '{token_field}' in the response body")

    prefix = login_config.get("header_prefix", "Bearer")
    return f"{prefix} {value}".strip()


class TokenRefresher:
    """Wraps acquire_token() to transparently re-fetch a token every
    `refresh_interval` seconds, so a long-running scan doesn't fail partway
    through because a short-lived access token expired."""

    def __init__(self, base_url: str, login_config: dict, verify_tls: bool = True,
                 refresh_interval: float = 0):
        self.base_url = base_url
        self.login_config = login_config
        self.verify_tls = verify_tls
        self.refresh_interval = refresh_interval
        self._token = None
        self._last_fetch = 0.0

    def get_token(self) -> str:
        now = time.monotonic()
        stale = self.refresh_interval and (now - self._last_fetch) > self.refresh_interval
        if self._token is None or stale:
            self._token = acquire_token(self.base_url, self.login_config, self.verify_tls)
            self._last_fetch = now
        return self._token
