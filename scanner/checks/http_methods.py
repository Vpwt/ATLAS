"""API8:2023-adjacent - HTTP method / verb misconfiguration.

Checks for the TRACE method being enabled (can enable cross-site tracing /
credential-stealing attacks when combined with XSS) and flags dangerous
methods (PUT/DELETE/PATCH) advertised via OPTIONS on paths that are
configured as not requiring authentication.
"""
from scanner.models import Endpoint, Finding, Severity

_DANGEROUS_METHODS = {"PUT", "DELETE", "PATCH"}


def run(client, endpoints: list[Endpoint]) -> list[Finding]:
    findings = []
    checked_paths = set()

    for ep in endpoints:
        path = ep.resolved_path()
        if path in checked_paths:
            continue
        checked_paths.add(path)

        try:
            trace_resp = client.request("TRACE", path, auth_override="keep")
            if trace_resp.status_code < 300:
                findings.append(Finding(
                    check="http_methods", severity=Severity.MEDIUM,
                    title="HTTP TRACE method is enabled",
                    endpoint=f"TRACE {path}",
                    detail=("The server responded successfully to an HTTP TRACE request. TRACE "
                            "should be disabled - it can be combined with XSS to read "
                            "cookies/headers otherwise protected by HttpOnly (cross-site "
                            "tracing)."),
                    evidence=f"HTTP {trace_resp.status_code}",
                    owasp_ref="API8:2023 Security Misconfiguration",
                ))
        except Exception:
            pass

        try:
            options_resp = client.request("OPTIONS", path, auth_override="keep")
            allow = options_resp.headers.get("Allow") or options_resp.headers.get("allow")
            if allow:
                advertised = {m.strip().upper() for m in allow.split(",")}
                dangerous = _DANGEROUS_METHODS & advertised
                if dangerous and not ep.auth_required:
                    findings.append(Finding(
                        check="http_methods", severity=Severity.LOW,
                        title="Potentially dangerous methods advertised on an unauthenticated path",
                        endpoint=f"OPTIONS {path}",
                        detail=(f"OPTIONS response advertises {sorted(dangerous)} as allowed on a "
                                "path that's configured as not requiring authentication. Confirm "
                                "those methods are actually protected server-side."),
                        evidence=f"Allow: {allow}",
                        owasp_ref="API8:2023 Security Misconfiguration",
                    ))
        except Exception:
            pass

    return findings
