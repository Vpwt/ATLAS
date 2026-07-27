"""API2:2023 - Broken Authentication.

Checks whether endpoints marked auth_required=True actually enforce that
requirement, and probes for weak/absent authentication behavior.
"""
from scanner.models import Endpoint, Finding, Severity


def run(client, endpoints: list[Endpoint]) -> list[Finding]:
    findings = []

    for ep in endpoints:
        if not ep.auth_required:
            continue

        path = ep.resolved_path()
        label = f"{ep.method} {path}"

        # 1. Request with no Authorization header at all
        try:
            resp = client.request(ep.method, path, params=ep.params if ep.method == "GET" else None,
                                   json_body=ep.body, auth_override="strip")
        except Exception as e:
            findings.append(Finding(
                check="auth", severity=Severity.INFO, title="Request failed",
                endpoint=label, detail=f"Could not complete request: {e}"
            ))
            continue

        if resp.status_code < 400:
            findings.append(Finding(
                check="auth", severity=Severity.CRITICAL,
                title="Protected endpoint accessible without authentication",
                endpoint=label,
                detail=("This endpoint is marked as requiring authentication, but returned a "
                        "success status with no Authorization header present."),
                evidence=f"HTTP {resp.status_code}",
                owasp_ref="API2:2023 Broken Authentication",
                curl_repro=getattr(resp, "curl_repro", ""),
            ))

        # 2. Request with an obviously malformed/garbage token
        try:
            resp2 = client.request(ep.method, path, headers={"Authorization": "Bearer not-a-real-token"},
                                    params=ep.params if ep.method == "GET" else None,
                                    json_body=ep.body, auth_override="keep")
            if resp2.status_code < 400:
                findings.append(Finding(
                    check="auth", severity=Severity.CRITICAL,
                    title="Endpoint accepts an invalid/garbage bearer token",
                    endpoint=label,
                    detail="A clearly invalid Authorization token was accepted as valid.",
                    evidence=f"HTTP {resp2.status_code}",
                    owasp_ref="API2:2023 Broken Authentication",
                    curl_repro=getattr(resp2, "curl_repro", ""),
                ))
        except Exception:
            pass

    return findings
