"""Advanced authentication providers for enterprise APIs."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import urllib.parse
from dataclasses import dataclass
from typing import Callable, Optional

import requests


@dataclass
class AuthRuntime:
    default_headers: dict
    auth_provider: Optional[Callable[[], str]] = None
    session_cookie: str = ""
    signer: Optional[Callable[..., dict]] = None
    client_cert: Optional[object] = None


def _resolve_url(base_url: str, url: str) -> str:
    if url.startswith("http://") or url.startswith("https://"):
        return url
    return f"{base_url.rstrip('/')}{url}"


def _oauth_client_credentials_provider(base_url: str, cfg: dict, verify_tls: bool) -> Callable[[], str]:
    token_url = _resolve_url(base_url, cfg["token_url"])
    client_id = cfg["client_id"]
    client_secret = cfg["client_secret"]
    scope = cfg.get("scope") or cfg.get("scopes")
    audience = cfg.get("audience")
    header_prefix = cfg.get("header_prefix", "Bearer")

    state = {"token": None, "exp": 0}

    def _fetch() -> str:
        if state["token"] and time.time() < state["exp"] - 20:
            return state["token"]

        body = {"grant_type": "client_credentials", "client_id": client_id, "client_secret": client_secret}
        if scope:
            body["scope"] = scope if isinstance(scope, str) else " ".join(scope)
        if audience:
            body["audience"] = audience

        resp = requests.post(token_url, data=body, timeout=20, verify=verify_tls)
        resp.raise_for_status()
        data = resp.json()
        access_token = data.get("access_token")
        if not access_token:
            raise ValueError("OAuth2 token response missing access_token")
        expires_in = int(data.get("expires_in", 3600))
        state["token"] = f"{header_prefix} {access_token}".strip()
        state["exp"] = time.time() + max(expires_in, 60)
        return state["token"]

    return _fetch


def _oauth_device_flow_provider(base_url: str, cfg: dict, verify_tls: bool) -> Callable[[], str]:
    device_url = _resolve_url(base_url, cfg["device_authorization_url"])
    token_url = _resolve_url(base_url, cfg["token_url"])
    client_id = cfg["client_id"]
    scope = cfg.get("scope")
    header_prefix = cfg.get("header_prefix", "Bearer")

    state = {"token": None, "exp": 0}

    def _fetch() -> str:
        if state["token"] and time.time() < state["exp"] - 20:
            return state["token"]

        body = {"client_id": client_id}
        if scope:
            body["scope"] = scope
        auth_resp = requests.post(device_url, data=body, timeout=20, verify=verify_tls)
        auth_resp.raise_for_status()
        auth_data = auth_resp.json()

        verification_uri = auth_data.get("verification_uri") or auth_data.get("verification_uri_complete")
        user_code = auth_data.get("user_code", "")
        device_code = auth_data.get("device_code")
        interval = int(auth_data.get("interval", 5))
        expires_in = int(auth_data.get("expires_in", 600))

        if not device_code:
            raise ValueError("Device flow response missing device_code")

        print("\nDevice Flow login required:")
        print(f"  Visit: {verification_uri}")
        if user_code:
            print(f"  Enter code: {user_code}")

        end = time.time() + expires_in
        while time.time() < end:
            poll_body = {
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": device_code,
                "client_id": client_id,
            }
            poll = requests.post(token_url, data=poll_body, timeout=20, verify=verify_tls)
            if poll.status_code == 200:
                data = poll.json()
                access_token = data.get("access_token")
                if not access_token:
                    raise ValueError("Token response missing access_token")
                tok_exp = int(data.get("expires_in", 3600))
                state["token"] = f"{header_prefix} {access_token}".strip()
                state["exp"] = time.time() + max(tok_exp, 60)
                return state["token"]
            try:
                err = poll.json().get("error")
            except Exception:
                err = "authorization_pending"
            if err in {"authorization_pending", "slow_down"}:
                time.sleep(interval + (2 if err == "slow_down" else 0))
                continue
            raise RuntimeError(f"Device flow token error: {err}")

        raise TimeoutError("Device flow login timed out before token was granted")

    return _fetch


def _oauth_pkce_provider(base_url: str, cfg: dict, verify_tls: bool) -> Callable[[], str]:
    authorize_url = _resolve_url(base_url, cfg["authorize_url"])
    token_url = _resolve_url(base_url, cfg["token_url"])
    client_id = cfg["client_id"]
    redirect_uri = cfg["redirect_uri"]
    scope = cfg.get("scope", "openid profile email")
    header_prefix = cfg.get("header_prefix", "Bearer")

    state = {"token": None, "exp": 0}

    def _fetch() -> str:
        if state["token"] and time.time() < state["exp"] - 20:
            return state["token"]

        verifier_raw = hashlib.sha256(str(time.time()).encode("utf-8")).digest()
        code_verifier = base64.urlsafe_b64encode(verifier_raw).decode("utf-8").rstrip("=")
        challenge = base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode("utf-8")).digest()).decode("utf-8").rstrip("=")

        params = {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": scope,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        auth_link = authorize_url + "?" + urllib.parse.urlencode(params)
        print("\nPKCE login required: open this URL and complete login")
        print(auth_link)
        redirected = input("Paste the full redirected URL: ").strip()

        parsed = urllib.parse.urlparse(redirected)
        code = urllib.parse.parse_qs(parsed.query).get("code", [""])[0]
        if not code:
            raise ValueError("No authorization code found in redirected URL")

        body = {
            "grant_type": "authorization_code",
            "client_id": client_id,
            "code": code,
            "redirect_uri": redirect_uri,
            "code_verifier": code_verifier,
        }
        resp = requests.post(token_url, data=body, timeout=20, verify=verify_tls)
        resp.raise_for_status()
        data = resp.json()
        access_token = data.get("access_token")
        if not access_token:
            raise ValueError("PKCE token response missing access_token")
        expires_in = int(data.get("expires_in", 3600))
        state["token"] = f"{header_prefix} {access_token}".strip()
        state["exp"] = time.time() + max(expires_in, 60)
        return state["token"]

    return _fetch


def _sign(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def build_sigv4_signer(cfg: dict) -> Callable[..., dict]:
    access_key = cfg["access_key"]
    secret_key = cfg["secret_key"]
    region = cfg["region"]
    service = cfg["service"]
    session_token = cfg.get("session_token")

    def signer(method: str, url: str, headers: dict, body: object, params: dict | None) -> dict:
        parsed = urllib.parse.urlparse(url)
        host = parsed.netloc
        amz_date = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        date_stamp = amz_date[:8]

        canonical_uri = parsed.path or "/"
        query_pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        if params:
            for k, v in params.items():
                query_pairs.append((str(k), str(v)))
        query_pairs = sorted(query_pairs)
        canonical_qs = "&".join(
            f"{urllib.parse.quote(k, safe='-_.~')}={urllib.parse.quote(v, safe='-_.~')}" for k, v in query_pairs
        )

        payload_text = ""
        if body is not None:
            payload_text = body if isinstance(body, str) else json.dumps(body, separators=(",", ":"))
        payload_hash = hashlib.sha256(payload_text.encode("utf-8")).hexdigest()

        sign_headers = {
            "host": host,
            "x-amz-date": amz_date,
            "x-amz-content-sha256": payload_hash,
        }
        if session_token:
            sign_headers["x-amz-security-token"] = session_token

        canonical_headers = "".join(f"{k}:{sign_headers[k]}\n" for k in sorted(sign_headers))
        signed_headers = ";".join(sorted(sign_headers.keys()))

        canonical_request = "\n".join([
            method.upper(),
            canonical_uri,
            canonical_qs,
            canonical_headers,
            signed_headers,
            payload_hash,
        ])

        credential_scope = f"{date_stamp}/{region}/{service}/aws4_request"
        string_to_sign = "\n".join([
            "AWS4-HMAC-SHA256",
            amz_date,
            credential_scope,
            hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
        ])

        k_date = _sign(("AWS4" + secret_key).encode("utf-8"), date_stamp)
        k_region = hmac.new(k_date, region.encode("utf-8"), hashlib.sha256).digest()
        k_service = hmac.new(k_region, service.encode("utf-8"), hashlib.sha256).digest()
        k_signing = hmac.new(k_service, b"aws4_request", hashlib.sha256).digest()
        signature = hmac.new(k_signing, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()

        auth_header = (
            "AWS4-HMAC-SHA256 "
            f"Credential={access_key}/{credential_scope}, "
            f"SignedHeaders={signed_headers}, "
            f"Signature={signature}"
        )

        out = {
            "Authorization": auth_header,
            "x-amz-date": amz_date,
            "x-amz-content-sha256": payload_hash,
        }
        if session_token:
            out["x-amz-security-token"] = session_token
        return out

    return signer


def _provider_preset(base_url: str, config: dict) -> Optional[dict]:
    azure = config.get("azure_ad")
    if azure:
        tenant = azure["tenant_id"]
        grant = azure.get("grant_type", "client_credentials")
        if grant == "device_code":
            return {
                "mode": "device_flow",
                "client_id": azure["client_id"],
                "scope": azure.get("scope", "https://graph.microsoft.com/.default"),
                "device_authorization_url": f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/devicecode",
                "token_url": f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
            }
        return {
            "mode": "client_credentials",
            "client_id": azure["client_id"],
            "client_secret": azure["client_secret"],
            "scope": azure.get("scope", "https://graph.microsoft.com/.default"),
            "token_url": f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
        }

    okta = config.get("okta")
    if okta:
        return {
            "mode": "client_credentials",
            "client_id": okta["client_id"],
            "client_secret": okta["client_secret"],
            "scope": okta.get("scope", "default"),
            "token_url": f"{okta['issuer'].rstrip('/')}/v1/token",
        }

    keycloak = config.get("keycloak")
    if keycloak:
        return {
            "mode": "client_credentials",
            "client_id": keycloak["client_id"],
            "client_secret": keycloak["client_secret"],
            "scope": keycloak.get("scope", ""),
            "token_url": f"{keycloak['issuer'].rstrip('/')}/protocol/openid-connect/token",
        }

    return None


def build_auth_runtime(base_url: str, config: dict, verify_tls: bool = True) -> AuthRuntime:
    headers = {}
    if config.get("auth_header"):
        headers["Authorization"] = config["auth_header"]

    runtime = AuthRuntime(default_headers=headers)
    runtime.session_cookie = config.get("session_cookie", "") or ""

    mtls = config.get("mtls") or {}
    cert_file = mtls.get("cert_file")
    key_file = mtls.get("key_file")
    if cert_file and key_file:
        runtime.client_cert = (cert_file, key_file)
    elif cert_file:
        runtime.client_cert = cert_file

    provider = _provider_preset(base_url, config)
    oauth_cfg = config.get("oauth2") or provider
    if oauth_cfg:
        mode = oauth_cfg.get("mode", "client_credentials")
        if mode == "client_credentials":
            runtime.auth_provider = _oauth_client_credentials_provider(base_url, oauth_cfg, verify_tls)
        elif mode == "device_flow":
            runtime.auth_provider = _oauth_device_flow_provider(base_url, oauth_cfg, verify_tls)
        elif mode == "pkce":
            runtime.auth_provider = _oauth_pkce_provider(base_url, oauth_cfg, verify_tls)

    sigv4 = config.get("aws_sigv4")
    if sigv4:
        runtime.signer = build_sigv4_signer(sigv4)

    return runtime
