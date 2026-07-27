"""API8:2023 - Security Misconfiguration: HTTP security headers and CORS."""
from scanner.models import Endpoint, Finding, Severity

RECOMMENDED_HEADERS = {
    "strict-transport-security": Severity.MEDIUM,
    "x-content-type-options": Severity.LOW,
    "content-security-policy": Severity.LOW,
    "x-frame-options": Severity.LOW,
}


def run(client, endpoints: list[Endpoint]) -> list[Finding]:
    findings = []
    checked_once = False

    for ep in endpoints:
        path = ep.resolved_path()
        label = f"{ep.method} {path}"

        try:
            resp = client.request(ep.method, path, params=ep.params if ep.method == "GET" else None,
                                   json_body=ep.body, auth_override="keep")
        except Exception:
            continue

        lower_headers = {k.lower(): v for k, v in resp.headers.items()}

        for header, sev in RECOMMENDED_HEADERS.items():
            if header not in lower_headers:
                findings.append(Finding(
                    check="headers", severity=sev,
                    title=f"Missing recommended security header: {header}",
                    endpoint=label,
                    detail=f"Response did not include the '{header}' header.",
                    owasp_ref="API8:2023 Security Misconfiguration",
                ))

        cors = lower_headers.get("access-control-allow-origin")
        if cors == "*":
            allow_creds = lower_headers.get("access-control-allow-credentials", "").lower()
            sev = Severity.HIGH if allow_creds == "true" else Severity.MEDIUM
            findings.append(Finding(
                check="headers", severity=sev,
                title="Overly permissive CORS policy",
                endpoint=label,
                detail=("Access-Control-Allow-Origin is set to '*' " +
                        ("together with Allow-Credentials: true, which is a serious combination "
                         "since it lets any origin make authenticated requests." if allow_creds == "true"
                         else "which allows any website to read responses from this API.")),
                evidence="Access-Control-Allow-Origin: *",
                owasp_ref="API8:2023 Security Misconfiguration",
            ))

        checked_once = True

    if not checked_once:
        findings.append(Finding(
            check="headers", severity=Severity.INFO,
            title="No endpoints could be checked for headers",
            endpoint="-", detail="All requests failed before headers could be inspected."
        ))

    return findings
