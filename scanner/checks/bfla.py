"""API5:2023 - Broken Function Level Authorization.

Two probes:
  1. Endpoints marked `admin_only` in config are tested with no auth, and
     (if configured) with a second, lower-privileged test account token, to
     confirm privileged functions actually reject non-admin callers.
  2. Verb tampering: HTTP methods that were never declared for a given path
     are tried against it, to catch cases where authorization is enforced
     for some verbs but not others on the same route. This is opt-in
     (enable_verb_tampering) since it can exercise destructive verbs like
     DELETE/PUT against real endpoints.
"""
from scanner.models import Endpoint, Finding, Severity

_CANDIDATE_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"]


def run(client, endpoints: list[Endpoint], low_priv_auth_header: str = None,
        enable_verb_tampering: bool = False) -> list[Finding]:
    findings = []
    findings.extend(_check_admin_only_endpoints(client, endpoints, low_priv_auth_header))
    if enable_verb_tampering:
        findings.extend(_check_verb_tampering(client, endpoints))
    return findings


def _check_admin_only_endpoints(client, endpoints, low_priv_auth_header) -> list:
    findings = []

    for ep in endpoints:
        if not ep.admin_only:
            continue
        path = ep.resolved_path()
        label = f"{ep.method} {path}"

        try:
            resp = client.request(ep.method, path, params=ep.params if ep.method == "GET" else None,
                                   json_body=ep.body, auth_override="strip")
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
                                   json_body=ep.body, auth_override="keep")
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


def _check_verb_tampering(client, endpoints) -> list:
    findings = []

    declared_methods_by_path = {}
    for ep in endpoints:
        declared_methods_by_path.setdefault(ep.path, set()).add(ep.method)

    tested = set()
    for ep in endpoints:
        if not ep.auth_required:
            continue
        declared = declared_methods_by_path.get(ep.path, set())

        for candidate in _CANDIDATE_METHODS:
            key = (ep.path, candidate)
            if candidate in declared or key in tested:
                continue
            tested.add(key)

            path = ep.resolved_path()
            label = f"{candidate} {path}"
            try:
                resp = client.request(candidate, path, params=ep.params if candidate == "GET" else None,
                                       json_body=ep.body if candidate in ("POST", "PUT", "PATCH") else None,
                                       auth_override="keep")
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
