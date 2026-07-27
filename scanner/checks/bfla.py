"""API5:2023 - Broken Function Level Authorization.

Two probes:
  1. Endpoints marked `admin_only` in config are tested with no auth, and
     (if configured) with a second, lower-privileged test account token, to
     confirm privileged functions actually reject non-admin callers.
  2. Verb tampering: HTTP methods that were never declared for a given path
     are tried against it, to catch cases where authorization is enforced
     for some verbs but not others on the same route. "safe" mode only tries
     non-destructive methods; "full" includes potentially destructive verbs.
"""
from scanner.models import Endpoint, Finding, Severity

_CANDIDATE_METHODS_SAFE = ["GET", "HEAD", "OPTIONS"]
_CANDIDATE_METHODS_FULL = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]
_ADMIN_HINTS = ("admin", "role", "permission", "grant", "promote", "internal")


def run(client, endpoints: list[Endpoint], low_priv_auth_header: str = None,
        enable_verb_tampering: bool = False,
        verb_tampering_mode: str = "safe") -> list[Finding]:
    findings = []
    findings.extend(_check_admin_only_endpoints(client, endpoints, low_priv_auth_header))
    mode = verb_tampering_mode.lower().strip() if isinstance(verb_tampering_mode, str) else "safe"
    if enable_verb_tampering and mode == "off":
        mode = "full"
    if mode in ("safe", "full"):
        findings.extend(_check_verb_tampering(client, endpoints, mode))
    return findings


def _likely_admin(ep: Endpoint) -> bool:
    if ep.admin_only:
        return True
    path = (ep.path or "").lower()
    desc = (ep.description or "").lower()
    return any(h in path or h in desc for h in _ADMIN_HINTS)


def _check_admin_only_endpoints(client, endpoints, low_priv_auth_header) -> list:
    findings = []

    for ep in endpoints:
        if not _likely_admin(ep):
            continue
        path = ep.resolved_path()
        label = f"{ep.method} {path}"

        try:
            resp = client.request(ep.method, path, params=ep.params if ep.method == "GET" else None,
                                       json_body=ep.body, auth_override="strip",
                                       body_content_type=ep.body_content_type)
            if resp.status_code < 300:
                findings.append(Finding(
                    check="bfla", severity=Severity.CRITICAL,
                    title="Admin-only endpoint accessible without authentication",
                    endpoint=label,
                    detail=("This endpoint is marked admin_only in config, but returned a "
                            "success response with no Authorization header at all."),
                    evidence=f"HTTP {resp.status_code}",
                    owasp_ref="API5:2023 Broken Function Level Authorization",
                    curl_repro=getattr(resp, "curl_repro", ""),
                ))
        except Exception:
            pass

        if not low_priv_auth_header:
            continue
        try:
            resp = client.request(ep.method, path, headers={"Authorization": low_priv_auth_header},
                                   params=ep.params if ep.method == "GET" else None,
                                       json_body=ep.body, auth_override="keep",
                                       body_content_type=ep.body_content_type)
            if resp.status_code < 300:
                findings.append(Finding(
                    check="bfla", severity=Severity.CRITICAL,
                    title="Admin-only endpoint accessible by a regular/low-privilege user",
                    endpoint=label,
                    detail=("A request using the configured low-privilege test account "
                            "(low_priv_auth_header) succeeded against an endpoint marked "
                            "admin_only. Function-level authorization checks appear to be "
                            "missing or misconfigured server-side."),
                    evidence=f"HTTP {resp.status_code}",
                    owasp_ref="API5:2023 Broken Function Level Authorization",
                    curl_repro=getattr(resp, "curl_repro", ""),
                ))
        except Exception:
            pass

    return findings


def _check_verb_tampering(client, endpoints, mode: str) -> list:
    findings = []

    declared_methods_by_path = {}
    for ep in endpoints:
        declared_methods_by_path.setdefault(ep.path, set()).add(ep.method)

    tested = set()
    for ep in endpoints:
        if not ep.auth_required:
            continue
        declared = declared_methods_by_path.get(ep.path, set())

        candidates = _CANDIDATE_METHODS_FULL if mode == "full" else _CANDIDATE_METHODS_SAFE
        for candidate in candidates:
            key = (ep.path, candidate)
            if candidate in declared or key in tested:
                continue
            tested.add(key)

            path = ep.resolved_path()
            label = f"{candidate} {path}"
            try:
                resp = client.request(candidate, path, params=ep.params if candidate == "GET" else None,
                                       json_body=ep.body if candidate in ("POST", "PUT", "PATCH") else None,
                                           auth_override="keep",
                                           body_content_type=ep.body_content_type)
            except Exception:
                continue

            if resp.status_code < 300:
                severity = Severity.HIGH if candidate in ("PUT", "PATCH", "DELETE") else Severity.MEDIUM
                findings.append(Finding(
                    check="bfla", severity=severity,
                    title=f"Undeclared HTTP method ({candidate}) accepted on endpoint",
                    endpoint=label,
                    detail=(f"This path was only ever declared with method(s) {sorted(declared)} "
                            f"in config, but sending {candidate} instead also returned a success "
                            "response. Confirm function-level authorization and routing are "
                            "correctly scoped per-method, not just per-path."),
                    evidence=f"HTTP {resp.status_code}",
                    owasp_ref="API5:2023 Broken Function Level Authorization",
                    curl_repro=getattr(resp, "curl_repro", ""),
                ))

    return findings
